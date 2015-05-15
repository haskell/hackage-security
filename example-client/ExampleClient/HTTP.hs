-- | Implementation of 'HttpClient' using the HTTP package
module ExampleClient.HTTP (
    initClient
  ) where

import Network.Browser
import Network.HTTP
import Network.URI
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

get :: URI -> Maybe Int -> (TempPath -> IO a) -> IO a
get uri mlen callback = do
    (_uri, response) <- browse $ do
      request (mkRequest GET uri)
    withSystemTempFile "00-index.tar.gz" $ \tempPath h -> do
      hPutStr h (rspBody response)
      hClose h
      callback tempPath
