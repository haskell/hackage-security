-- | Implementation of 'HttpClient' using the HTTP package
module ExampleClient.HttpClient.HTTP (
    initClient
  ) where

import Control.Exception
import Network.Browser
import Network.HTTP
import Network.URI
import System.FilePath
import System.IO
import System.IO.Temp

import Hackage.Security.Client.Repository
import Hackage.Security.Client.Repository.HTTP

{-------------------------------------------------------------------------------
  Top-level API
-------------------------------------------------------------------------------}

initClient :: HttpClient
initClient = HttpClient {
      httpClientGet = get
    }

{-------------------------------------------------------------------------------
  Individual methods
-------------------------------------------------------------------------------}

-- TODO: This is just a quick implementation for now, needs to be improved in
-- all sorts of ways (not least of which is to make use of the FileSize)
get :: URI -> FileSize -> (TempPath -> IO a) -> IO a
get uri mlen callback = do
    (_uri, response) <- browse $ do
      setOutHandler $ \_ -> return ()
      request (mkRequest GET uri)
    if rspCode response == (2, 0, 0)
      then withSystemTempFile (takeFileName (uriPath uri)) $ \tempPath h -> do
             hPutStr h (rspBody response)
             hClose h
             callback tempPath
      else throwIO $ userError $ "Expected 200 OK, got " ++ show (rspCode response)
