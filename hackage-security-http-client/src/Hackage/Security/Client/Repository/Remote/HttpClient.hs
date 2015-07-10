{-# LANGUAGE OverloadedStrings #-}
module Hackage.Security.Client.Repository.Remote.HttpClient (
    withClient
  ) where

import Control.Exception
import Control.Monad
import Data.ByteString (ByteString)
import Data.Default.Class (def)
import Data.Monoid
import Network.URI
import Network.HTTP.Client hiding (BodyReader)
import Network.HTTP.Client.Internal (setUri)
import Network.HTTP.Types
import qualified Data.CaseInsensitive  as CI
import qualified Data.ByteString       as BS
import qualified Data.ByteString.Char8 as BS.C8

import Hackage.Security.Client hiding (Header)
import Hackage.Security.Client.Repository.Remote
import qualified Hackage.Security.Util.Lens as Lens

{-------------------------------------------------------------------------------
  Top-level API
-------------------------------------------------------------------------------}

withClient :: ProxyConfig Proxy -> (String -> IO ()) -> (HttpClient -> IO a) -> IO a
withClient proxyConfig _logger callback = do
    caps <- newServerCapabilities
    withManager (setProxy defaultManagerSettings) $ \manager ->
      callback HttpClient {
          httpClientGet          = get      manager caps
        , httpClientGetRange     = getRange manager caps
        , httpClientCapabilities = caps
        , httpWrapCustomEx       = wrapCustomEx
        }
  where
    setProxy = managerSetProxy $
      case proxyConfig of
        ProxyConfigNone  -> noProxy
        ProxyConfigUse p -> useProxy p
        ProxyConfigAuto  -> proxyEnvironment Nothing

{-------------------------------------------------------------------------------
  Individual methods
-------------------------------------------------------------------------------}

-- See TODOs in the HTTP client
get :: Manager -> ServerCapabilities
    -> [HttpOption] -> URI -> (BodyReader -> IO a) -> IO a
get manager caps httpOpts uri callback = do
    -- TODO: setUri fails under certain circumstances; in particular, when
    -- the URI contains URL auth. Not sure if this is a concern.
    request' <- setUri def uri
    let request = setHttpOptions httpOpts
                $ request'
    withResponse request manager $ \response -> do
      updateCapabilities caps response
      callback (responseBody response)

getRange :: Manager -> ServerCapabilities
         -> [HttpOption] -> URI -> (Int, Int)
         -> (DownloadedRange -> BodyReader -> IO a) -> IO a
getRange manager caps httpOpts uri (from, to) callback = do
    request' <- setUri def uri
    let request = setRange from to
                $ setHttpOptions httpOpts
                $ request'
    withResponse request manager $ \response -> do
      updateCapabilities caps response
      let br = responseBody response
      case responseStatus response of
        s | s == partialContent206 -> callback DownloadedRange      br
        s | s == ok200             -> callback DownloadedEntireFile br
        s -> throwIO $ StatusCodeException s (responseHeaders response)
                                             (responseCookieJar response)

-- | Update recorded server capabilities given a response
updateCapabilities :: ServerCapabilities -> Response a -> IO ()
updateCapabilities caps response = do
    when ((hAcceptRanges, "bytes") `elem` headers) $
      setServerSupportsAcceptBytes caps True
  where
    headers = responseHeaders response

-- | Wrap custom exceptions
--
-- NOTE: The only other exception defined in @http-client@ is @TimeoutTriggered@
-- but it is currently disabled <https://github.com/snoyberg/http-client/issues/116>
wrapCustomEx :: IO a -> IO a
wrapCustomEx act = catches act [
      Handler $ \(ex :: HttpException) -> go ex
    ]
  where
    go :: Exception e => e -> IO a
    go = throwIO . CustomRecoverableException

{-------------------------------------------------------------------------------
  http-client auxiliary
-------------------------------------------------------------------------------}

hAcceptRanges :: HeaderName
hAcceptRanges = CI.mk "Accept-Ranges"

setRange :: Int -> Int -> Request -> Request
setRange from to req = req {
      requestHeaders = (hRange, rangeHeader) : requestHeaders req
    }
  where
    -- Content-Range header uses inclusive rather than exclusive bounds
    -- See <http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html>
    rangeHeader = BS.C8.pack $ "bytes=" ++ show from ++ "-" ++ show (to - 1)

setHttpOptions :: [HttpOption] -> Request -> Request
setHttpOptions opts req = req {
      requestHeaders = trOpt [] opts ++ requestHeaders req
    }
  where
    trOpt :: [(HeaderName, [ByteString])] -> [HttpOption] -> [Header]
    trOpt acc [] =
      concatMap finalizeHeader acc
    trOpt acc (HttpOptionMaxAge0:os) =
      trOpt (insert hCacheControl ["max-age=0"] acc) os
    trOpt acc (HttpOptionNoTransform:os) =
      trOpt (insert hCacheControl ["no-transform"] acc) os

    -- Some headers are comma-separated, others need multiple headers for
    -- multiple options. Since right now we deal with HdrCacheControl only,
    -- we just comma-separate all of them.
    finalizeHeader :: (HeaderName, [ByteString]) -> [Header]
    finalizeHeader (name, strs) = [(name, BS.intercalate ", " (reverse strs))]

    insert :: (Eq a, Monoid b) => a -> b -> [(a, b)] -> [(a, b)]
    insert x y = Lens.modify (Lens.lookupM x) (mappend y)
