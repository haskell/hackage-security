-- | Implementation of 'HttpClient' using the HTTP package
module ExampleClient.HttpClient.HTTP (
    initClient
  ) where

import Control.Exception
import Data.Typeable
import Network.Browser
import Network.HTTP
import Network.URI
import System.FilePath
import System.IO
import System.IO.Temp
import qualified Data.ByteString.Lazy as BS.L

import Hackage.Security.Client.Repository
import Hackage.Security.Client.Repository.HTTP

{-------------------------------------------------------------------------------
  Top-level API
-------------------------------------------------------------------------------}

initClient :: HttpClient
initClient = HttpClient {
      httpClientGet      = get
    , httpClientGetRange = getRange
    }

{-------------------------------------------------------------------------------
  Individual methods
-------------------------------------------------------------------------------}

-- TODO: This is just a quick implementation for now, needs to be improved in
-- all sorts of ways (not least of which is to make use of the FileSize)
get :: URI -> FileSize -> (TempPath -> IO a) -> IO a
get uri mlen callback = do
    (_uri, response) <- browse $ do
      -- setOutHandler $ \_ -> return ()
      request $ mkRequest GET uri
    case rspCode response of
      (2, 0, 0)  -> withResponseBody uri response callback
      _otherwise -> throwIO $ UnexpectedResponse (rspCode response)

getRange :: URI -> (Int, Int) -> (TempPath -> IO a) -> IO a
getRange uri (from, to) callback = do
    (_uri, response) <- browse $ do
      -- setOutHandler $ \_ -> return ()
      request $ insertHeader HdrRange rangeHeader
              $ mkRequest GET uri
    -- TODO: Should verify HdrContentRange in response
    -- which will look like "bytes 734-1233/1234"
    case rspCode response of
      (2, 0, 6)  -> withResponseBody uri response callback
      _otherwise -> throwIO $ UnexpectedResponse (rspCode response)
  where
    -- Content-Range header uses inclusive rather than exclusive bounds
    -- See <http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html>
    rangeHeader = "bytes=" ++ show from ++ "-" ++ show (to - 1)

withResponseBody :: URI -> Response BS.L.ByteString -> (TempPath -> IO a) -> IO a
withResponseBody uri response callback = do
    withSystemTempFile (takeFileName (uriPath uri)) $ \tempPath h -> do
      BS.L.hPutStr h (rspBody response)
      hClose h
      callback tempPath

data UnexpectedResponse = UnexpectedResponse (Int, Int, Int)
  deriving (Show, Typeable)

instance Exception UnexpectedResponse
