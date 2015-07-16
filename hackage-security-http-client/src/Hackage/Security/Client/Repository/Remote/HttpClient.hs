{-# LANGUAGE OverloadedStrings #-}
module Hackage.Security.Client.Repository.Remote.HttpClient (
    withClient
  ) where

import Control.Exception
import Data.ByteString (ByteString)
import Data.Default.Class (def)
import Data.Monoid
import Network.URI
import Network.HTTP.Client hiding (BodyReader)
import Network.HTTP.Client.Internal (setUri)
import Network.HTTP.Types
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
    withManager (setProxy defaultManagerSettings) $ \manager ->
      callback HttpClient {
          httpClientGet      = get      manager
        , httpClientGetRange = getRange manager
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

get :: Manager
    -> [HttpRequestHeader] -> URI
    -> ([HttpResponseHeader] -> BodyReader -> IO a)
    -> IO a
get manager reqHeaders uri callback = wrapCustomEx $ do
    -- TODO: setUri fails under certain circumstances; in particular, when
    -- the URI contains URL auth. Not sure if this is a concern.
    request' <- setUri def uri
    let request = setRequestHeaders reqHeaders
                $ request'
    withResponse request manager $ \response -> do
      let br = wrapCustomEx $ responseBody response
      callback (getResponseHeaders response) br

getRange :: Manager
         -> [HttpRequestHeader] -> URI -> (Int, Int)
         -> ([HttpResponseHeader] -> BodyReader -> IO a)
         -> IO a
getRange manager reqHeaders uri (from, to) callback = wrapCustomEx $ do
    request' <- setUri def uri
    let request = setRange from to
                $ setRequestHeaders reqHeaders
                $ request'
    withResponse request manager $ \response -> do
      let br = wrapCustomEx $ responseBody response
      case responseStatus response of
        s | s == partialContent206 -> callback (getResponseHeaders response) br
        s -> throwIO $ StatusCodeException s (responseHeaders response)
                                             (responseCookieJar response)

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
hAcceptRanges = "Accept-Ranges"

hAcceptEncoding :: HeaderName
hAcceptEncoding = "Accept-Encoding"

setRange :: Int -> Int -> Request -> Request
setRange from to req = req {
      requestHeaders = (hRange, rangeHeader) : requestHeaders req
    }
  where
    -- Content-Range header uses inclusive rather than exclusive bounds
    -- See <http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html>
    rangeHeader = BS.C8.pack $ "bytes=" ++ show from ++ "-" ++ show (to - 1)

-- | Set request headers
setRequestHeaders :: [HttpRequestHeader] -> Request -> Request
setRequestHeaders opts req = req {
      requestHeaders = trOpt disallowCompressionByDefault opts
    }
  where
    trOpt :: [(HeaderName, [ByteString])]
          -> [HttpRequestHeader]
          -> [Header]
    trOpt acc [] =
      concatMap finalizeHeader acc
    trOpt acc (HttpRequestMaxAge0:os) =
      trOpt (insert hCacheControl ["max-age=0"] acc) os
    trOpt acc (HttpRequestNoTransform:os) =
      trOpt (insert hCacheControl ["no-transform"] acc) os
    trOpt acc (HttpRequestContentCompression:os) =
      trOpt (insert hAcceptEncoding ["gzip"] acc) os

    -- http-client deals with decompression completely transparently, so we
    -- don't actually need to manually decompress the response stream (we do
    -- still need to report to the `hackage-security` library however that the
    -- response stream had been compressed). However, we do have to make sure
    -- that we allow for compression _only_ when explicitly requested because
    -- the default is that it's always enabled.
    disallowCompressionByDefault :: [(HeaderName, [ByteString])]
    disallowCompressionByDefault = [(hAcceptEncoding, [])]

    -- Some headers are comma-separated, others need multiple headers for
    -- multiple options.
    --
    -- TODO: Right we we just comma-separate all of them.
    finalizeHeader :: (HeaderName, [ByteString]) -> [Header]
    finalizeHeader (name, strs) = [(name, BS.intercalate ", " (reverse strs))]

    insert :: (Eq a, Monoid b) => a -> b -> [(a, b)] -> [(a, b)]
    insert x y = Lens.modify (Lens.lookupM x) (mappend y)

-- | Extract the response headers
getResponseHeaders :: Response a -> [HttpResponseHeader]
getResponseHeaders response = concat [
      [ HttpResponseAcceptRangesBytes
      | (hAcceptRanges, "bytes") `elem` headers
      ]
    , [ HttpResponseContentCompression
      | (hContentEncoding, "gzip") `elem` headers
      ]
    ]
  where
    headers = responseHeaders response
