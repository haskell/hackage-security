-- | Implementation of 'HttpClient' using the HTTP package
module Hackage.Security.Client.Repository.Remote.HTTP (
    withClient
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

import Hackage.Security.Client
import Hackage.Security.Client.Repository.Remote

{-------------------------------------------------------------------------------
  Top-level API
-------------------------------------------------------------------------------}

withClient :: (String -> IO ()) -- ^ stdout log handler
           -> (String -> IO ()) -- ^ stderr log handler
           -> (HttpClient -> IO a) -> IO a
withClient outLog errLog callback = do
    caps <- newServerCapabilities
    bracket browserInit browserCleanup $ \browser ->
      callback HttpClient {
          httpClientGet          = get      outLog errLog browser caps
        , httpClientGetRange     = getRange outLog errLog browser caps
        , httpClientCapabilities = caps
        , httpWrapCustomEx       = wrapCustomEx
        }

{-------------------------------------------------------------------------------
  Individual methods
-------------------------------------------------------------------------------}

-- TODO: We should verify that the file we downloaded is the expected size
-- (that it didn't get truncated); here and in getRange
get :: (String -> IO ()) -> (String -> IO ())
    -> Browser -> ServerCapabilities
    -> [HttpOption] -> URI
    -> (BodyReader -> IO a) -> IO a
get outLog errLog browser caps httpOpts uri callback = do
    (_uri, response) <- withBrowser browser $ do
      setOutHandler outLog
      setErrHandler errLog
      request $ setHttpOptions httpOpts
              $ mkRequest GET uri
    case rspCode response of
      (2, 0, 0)  -> withResponse caps response callback
      _otherwise -> throwIO $ UnexpectedResponse uri (rspCode response)

getRange :: (String -> IO ()) -> (String -> IO ())
         -> Browser -> ServerCapabilities
         -> [HttpOption] -> URI -> (Int, Int)
         -> (DownloadedRange -> BodyReader -> IO a) -> IO a
getRange outLog errLog browser caps httpOpts uri (from, to) callback = do
    (_uri, response) <- withBrowser browser $ do
      setOutHandler outLog
      setErrHandler errLog
      request $ setRange from to
              $ setHttpOptions httpOpts
              $ mkRequest GET uri
    -- TODO: Should verify HdrContentRange in response
    -- which will look like "bytes 734-1233/1234"
    case rspCode response of
      (2, 0, 6)  -> withResponse caps response (callback DownloadedRange)
      (2, 0, 0)  -> withResponse caps response (callback DownloadedEntireFile)
      _otherwise -> throwIO $ UnexpectedResponse uri (rspCode response)

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

-- | Wrap custom exceptions
--
-- TODO: Does the HTTP library define some custom exceptions?
wrapCustomEx :: IO a -> IO a
wrapCustomEx act = catches act [
      Handler $ \(ex :: UnexpectedResponse) -> throwIO (CustomException ex)
    ]

data UnexpectedResponse = UnexpectedResponse URI (Int, Int, Int)
  deriving (Show, Typeable)

instance Exception UnexpectedResponse

{-------------------------------------------------------------------------------
  Browser state
-------------------------------------------------------------------------------}

type LazyStream = HandleStream BS.L.ByteString
type Browser    = MVar (BrowserState LazyStream)

-- | Run a browser action
--
-- IMPLEMENTATION NOTE: the 'browse' action doesn't itself create any
-- connections, they are created on demand; we just need to make sure to carry
-- this state from one invocation of 'browse' to another.
withBrowser :: Browser -> BrowserAction LazyStream a -> IO a
withBrowser browser act = modifyMVar browser $ \bst -> browse $ do
    State.put bst
    result <- act
    bst'   <- State.get
    return (bst', result)

-- | Initial browser state
browserInit :: IO Browser
browserInit = newMVar =<< browse State.get

-- | Cleanup browser state
--
-- NOTE: Calling 'withBrowser' after 'browserCleanup' will result in deadlock.
--
-- IMPLEMENTATION NOTE: "HTTP" does not provide any explicit API for resource
-- cleanup, so we can only rely on the garbage collector to do for us.
browserCleanup :: Browser -> IO ()
browserCleanup = void . takeMVar

{-------------------------------------------------------------------------------
  HTTP auxiliary
-------------------------------------------------------------------------------}

hAcceptRanges :: HeaderName
hAcceptRanges = HdrCustom "Accept-Ranges"

setRange :: HasHeaders a => Int -> Int -> a -> a
setRange from to = insertHeader HdrRange rangeHeader
  where
    -- Content-Range header uses inclusive rather than exclusive bounds
    -- See <http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html>
    rangeHeader = "bytes=" ++ show from ++ "-" ++ show (to - 1)

setHttpOptions :: HasHeaders a => [HttpOption] -> a -> a
setHttpOptions = foldr (.) id . map (uncurry insertHeader . trOpt)
  where
    trOpt :: HttpOption -> (HeaderName, String)
    trOpt HttpOptionMaxAge0     = (HdrCacheControl, "max-age=0")
    trOpt HttpOptionNoTransform = (HdrCacheControl, "no-transform")
