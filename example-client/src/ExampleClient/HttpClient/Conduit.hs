module ExampleClient.HttpClient.Conduit (
    initClient
  ) where

import Control.Concurrent
import Control.Monad
import Data.Default.Class (def)
import Network.URI
import Network.HTTP.Client hiding (BodyReader)
import Network.HTTP.Client.Internal (setUri)
import Network.HTTP.Types
import qualified Data.CaseInsensitive  as CI
import qualified Data.ByteString.Char8 as BS.C8

import Hackage.Security.Client.Repository.HTTP

{-------------------------------------------------------------------------------
  Top-level API
-------------------------------------------------------------------------------}

initClient :: (String -> IO ()) -> IO HttpClient
initClient _logger = do
    m'   <- newMVar ManagerNotInit
    caps <- newServerCapabilities
    return $ HttpClient {
        httpClientGet          = get      m' caps
      , httpClientGetRange     = getRange m' caps
      , httpClientCapabilities = caps
      }

{-------------------------------------------------------------------------------
  Dealing with the Manager

  We start the manager on first use, and then keep it open; however,
  this setup also allows to terminate the manager at any point should we want
  to; it will then automatically be recreated when needed again.

  TODO: Should the manager ever be terminated?
-------------------------------------------------------------------------------}

data Manager' = ManagerNotInit | ManagerInit Manager

withManager' :: MVar Manager' -> (Manager -> IO a) -> IO a
withManager' mv callback = modifyMVar mv $ \st -> do
    m <- case st of
           ManagerInit m  -> return m
           ManagerNotInit -> newManager defaultManagerSettings
    result <- callback m
    return (ManagerInit m, result)

{-------------------------------------------------------------------------------
  Individual methods
-------------------------------------------------------------------------------}

-- See TODOs in the HTTP client
get :: MVar Manager' -> ServerCapabilities
    -> URI -> (BodyReader -> IO a) -> IO a
get m' caps uri callback = do
    -- TODO: setUri fails under certain circumstances; in particular, when
    -- the URI contains URL auth. Not sure if this is a concern.
    request <- setUri def uri
    withManager' m' $ \m -> do
      withResponse request m $ \response -> do
        updateCapabilities caps response
        callback (responseBody response)

getRange :: MVar Manager' -> ServerCapabilities
         -> URI -> (Int, Int) -> (BodyReader -> IO a) -> IO a
getRange m' caps uri (from, to) callback = do
    request' <- setUri def uri
    let request = request' {
            requestHeaders = (hRange, rangeHeader)
                           : requestHeaders request'
          }
    withManager' m' $ \m -> do
      withResponse request m $ \response -> do
        updateCapabilities caps response
        callback (responseBody response)
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

{-------------------------------------------------------------------------------
  http-client auxiliary
-------------------------------------------------------------------------------}

hAcceptRanges :: HeaderName
hAcceptRanges = CI.mk (BS.C8.pack "Accept-Ranges")
