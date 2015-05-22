module ExampleClient.HttpClient.Conduit (
    initClient
  ) where

import Network.URI
import Network.HTTP.Conduit
import System.FilePath
import System.IO
import System.IO.Temp
import qualified Data.ByteString.Lazy as BS.L

import Hackage.Security.Client.Repository
import Hackage.Security.Client.Repository.HTTP

{-------------------------------------------------------------------------------
  Top-level API
-------------------------------------------------------------------------------}

initClient :: (String -> IO ()) -> IO HttpClient
initClient logger = do
    caps <- newServerCapabilities
    return $ HttpClient {
        httpClientGet = get
      }

{-------------------------------------------------------------------------------
  Individual methods
-------------------------------------------------------------------------------}

-- TODO: This is just a quick implementation for now, needs to be improved in
-- all sorts of ways (not least of which is to make use of the FileSize)
get :: URI -> FileSize -> (TempPath -> IO a) -> IO a
get uri mlen callback = do
    responseBody <- simpleHttp (show uri)
    withSystemTempFile (takeFileName (uriPath uri)) $ \tempPath h -> do
      BS.L.hPutStr h responseBody
      hClose h
      callback tempPath
