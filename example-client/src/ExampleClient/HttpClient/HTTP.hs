-- | Implementation of 'HttpClient' using the HTTP package
module ExampleClient.HttpClient.HTTP (
    initClient
  ) where

import Control.Concurrent
import Control.Exception
import Control.Monad
import Data.IORef
import Data.Typeable
import Network.Browser
import Network.HTTP
import Network.URI
import qualified Data.ByteString      as BS
import qualified Data.ByteString.Lazy as BS.L
import qualified Control.Monad.State  as State

import Hackage.Security.Client.Repository.HTTP

{-------------------------------------------------------------------------------
  Top-level API
-------------------------------------------------------------------------------}

initClient :: (String -> IO ()) -> IO HttpClient
initClient logger = do
    caps    <- newServerCapabilities
    browser <- newMVar BrowserNotInit
    return $ HttpClient {
        httpClientGet          = get      logger browser caps
      , httpClientGetRange     = getRange logger browser caps
      , httpClientCapabilities = caps
      }

{-------------------------------------------------------------------------------
  Individual methods
-------------------------------------------------------------------------------}

-- TODO: We should verify that the file we downloaded is the expected size
-- (that it didn't get truncated); here and in getRange
get :: (String -> IO ()) -> MVar Browser -> ServerCapabilities
    -> URI -> (BodyReader -> IO a) -> IO a
get logger browser caps uri callback = do
    (_uri, response) <- withBrowser browser $ do
      -- TODO: should probably distinguish between Out and Err
      setOutHandler $ logger
      setErrHandler $ logger
      request $ mkRequest GET uri
    case rspCode response of
      (2, 0, 0)  -> withResponse caps response callback
      _otherwise -> throwIO $ UnexpectedResponse (rspCode response)

getRange :: (String -> IO ()) -> MVar Browser -> ServerCapabilities
         -> URI -> (Int, Int) -> (BodyReader -> IO a) -> IO a
getRange logger browser caps uri (from, to) callback = do
    (_uri, response) <- withBrowser browser $ do
      setOutHandler $ logger
      setErrHandler $ logger
      request $ insertHeader HdrRange rangeHeader
              $ mkRequest GET uri
    -- TODO: Should verify HdrContentRange in response
    -- which will look like "bytes 734-1233/1234"
    case rspCode response of
      (2, 0, 6)  -> withResponse caps response callback
      _otherwise -> throwIO $ UnexpectedResponse (rspCode response)
  where
    -- Content-Range header uses inclusive rather than exclusive bounds
    -- See <http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html>
    rangeHeader = "bytes=" ++ show from ++ "-" ++ show (to - 1)

withResponse :: ServerCapabilities
             -> Response BS.L.ByteString -> (BodyReader -> IO a) -> IO a
withResponse caps response callback = do
    -- TODO: This is a very crude way of "chunking" the input, probably should
    -- make this more sophisticated.
    -- TODO: Unfortunately we have no way of closing the connection when the
    -- callback decides it doens't require any further input.
    -- See <https://github.com/haskell/HTTP/issues/86>.
    updateCapabilities caps response
    chunks <- newIORef $ BS.L.toChunks (rspBody response)
    -- NOTE: Lazy bytestrings invariant: no empty chunks
    let br = do bss <- readIORef chunks
                case bss of
                  []        -> return BS.empty
                  (bs:bss') -> writeIORef chunks bss' >> return bs
    callback br

-- | Update recorded server capabilities given a response
updateCapabilities :: ServerCapabilities -> Response a -> IO ()
updateCapabilities caps response =
    -- Check the @Accept-Ranges@ header.
    --
    -- @Accept-Ranges@ takes a _single_ argument, but there might potentially
    -- be more than one of them (although the spec does not explicitly say so).

    -- See <http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.5>
    -- and <http://www.w3.org/Protocols/rfc2616/rfc2616-sec3.html#sec3.12>
    when ("bytes" `elem` map hdrValue (retrieveHeaders hAcceptRanges response)) $
      setServerSupportsAcceptBytes caps True

data UnexpectedResponse = UnexpectedResponse (Int, Int, Int)
  deriving (Show, Typeable)

instance Exception UnexpectedResponse

{-------------------------------------------------------------------------------
  HTTP auxiliary

  We initialize the browser state on first use, and then keep it open.
  If we ever decide to close it, we will simply reopen it on the next use.
  (Note that the 'browse' action doesn't itself create any connections, they are
  created on demand; we just need to make sure to carry this state from one
  invocation of 'browse' to another.)

  TODO: Should we ever "terminate" the browser?
-------------------------------------------------------------------------------}

type LazyStream = HandleStream BS.L.ByteString

hAcceptRanges :: HeaderName
hAcceptRanges = HdrCustom "Accept-Ranges"

data Browser = BrowserNotInit | BrowserInit (BrowserState LazyStream)

withBrowser :: MVar Browser -> BrowserAction LazyStream a -> IO a
withBrowser mv act = modifyMVar mv $ \st -> do
    bst <- case st of
             BrowserNotInit  -> browse State.get
             BrowserInit bst -> return bst
    (bst', result) <- browse $ do
      State.put bst
      result <- act
      bst'   <- State.get
      return (bst', result)
    return (BrowserInit bst', result)
