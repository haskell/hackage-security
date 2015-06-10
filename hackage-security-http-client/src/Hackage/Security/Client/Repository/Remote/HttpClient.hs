module Hackage.Security.Client.Repository.Remote.HttpClient (
    withClient
  ) where

import Control.Exception
import Control.Monad
import Data.Default.Class (def)
import Network.URI
import Network.HTTP.Client hiding (BodyReader)
import Network.HTTP.Client.Internal (setUri)
import Network.HTTP.Types
import qualified Data.CaseInsensitive  as CI
import qualified Data.ByteString.Char8 as BS.C8

import Hackage.Security.Client
import Hackage.Security.Client.Repository.Remote

{-------------------------------------------------------------------------------
  Top-level API
-------------------------------------------------------------------------------}

withClient :: (String -> IO ()) -> (HttpClient -> IO a) -> IO a
withClient _logger callback = do
    caps <- newServerCapabilities
    withManager defaultManagerSettings $ \manager ->
      callback HttpClient {
          httpClientGet          = get      manager caps
        , httpClientGetRange     = getRange manager caps
        , httpClientCapabilities = caps
        , httpWrapCustomEx       = wrapCustomEx
        }

{-------------------------------------------------------------------------------
  Individual methods
-------------------------------------------------------------------------------}

-- See TODOs in the HTTP client
get :: Manager -> ServerCapabilities
    -> URI -> (BodyReader -> IO a) -> IO a
get manager caps uri callback = do
    -- TODO: setUri fails under certain circumstances; in particular, when
    -- the URI contains URL auth. Not sure if this is a concern.
    request <- setUri def uri
    withResponse request manager $ \response -> do
      updateCapabilities caps response
      callback (responseBody response)

getRange :: Manager -> ServerCapabilities
         -> URI -> (Int, Int) -> (DownloadedRange -> BodyReader -> IO a) -> IO a
getRange manager caps uri (from, to) callback = do
    request' <- setUri def uri
    let request = request' {
            requestHeaders = (hRange, rangeHeader)
                           : requestHeaders request'
          }
    withResponse request manager $ \response -> do
      updateCapabilities caps response
      let br = responseBody response
      case responseStatus response of
        s | s == partialContent206 -> callback DownloadedRange      br
        s | s == ok200             -> callback DownloadedEntireFile br
        s -> throwIO $ StatusCodeException s (responseHeaders response)
                                             (responseCookieJar response)
  where
    -- Content-Range header uses inclusive rather than exclusive bounds
    -- See <http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html>
    rangeHeader = BS.C8.pack $ "bytes=" ++ show from ++ "-" ++ show (to - 1)

-- | Update recorded server capabilities given a response
updateCapabilities :: ServerCapabilities -> Response a -> IO ()
updateCapabilities caps response = do
    when ((hAcceptRanges, BS.C8.pack "bytes") `elem` headers) $
      setServerSupportsAcceptBytes caps True
  where
    headers = responseHeaders response

-- | Wrap custom exceptions
--
-- TODO: Are there any others we should catch?
wrapCustomEx :: IO a -> IO a
wrapCustomEx act = catches act [
      Handler $ \(ex :: HttpException) -> throwIO (CustomException ex)
    ]

{-------------------------------------------------------------------------------
  http-client auxiliary
-------------------------------------------------------------------------------}

hAcceptRanges :: HeaderName
hAcceptRanges = CI.mk (BS.C8.pack "Accept-Ranges")
