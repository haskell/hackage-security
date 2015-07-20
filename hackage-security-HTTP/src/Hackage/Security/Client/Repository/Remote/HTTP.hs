{-# LANGUAGE CPP #-}
-- | Implementation of 'HttpClient' using the HTTP package
module Hackage.Security.Client.Repository.Remote.HTTP (
    withClient
    -- * Exception types
  , UnexpectedResponse(..)
  , InvalidProxy(..)
  ) where

import Control.Concurrent
import Control.Exception
import Control.Monad
import Data.Monoid
import Data.List (intercalate)
import Data.Typeable (Typeable)
import Network.Browser
import Network.HTTP
import Network.HTTP.Proxy
import Network.URI
import qualified Data.ByteString.Lazy   as BS.L
import qualified Control.Monad.State    as State
import qualified Codec.Compression.GZip as GZip

#if MIN_VERSION_zlib(0,6,0)
import qualified Codec.Compression.Zlib.Internal as GZip (DecompressError)
#endif

import Hackage.Security.Client
import Hackage.Security.Client.Repository.Remote
import qualified Hackage.Security.Util.Lens as Lens

{-------------------------------------------------------------------------------
  Top-level API
-------------------------------------------------------------------------------}

-- | Initialize the client
--
-- TODO: This currently uses the lazy bytestring API offered by the HTTP
-- library. Unfortunately this provides no way of closing the connection when
-- the callback decides it doens't require any further input. It seems
-- impossible however to implement a proper streaming API.
-- See <https://github.com/haskell/HTTP/issues/86>.
withClient :: ProxyConfig String -- ^ Proxy
           -> (String -> IO ())  -- ^ stdout log handler
           -> (String -> IO ())  -- ^ stderr log handler
           -> (HttpClient -> IO a) -> IO a
withClient proxyConfig outLog errLog callback =
    bracket (browserInit proxyConfig outLog errLog) browserCleanup $ \browser ->
      callback HttpClient {
          httpClientGet      = get      browser
        , httpClientGetRange = getRange browser
        }

{-------------------------------------------------------------------------------
  Individual methods
-------------------------------------------------------------------------------}

get :: Browser
    -> [HttpRequestHeader] -> URI
    -> ([HttpResponseHeader] -> BodyReader -> IO a)
    -> IO a
get browser reqHeaders uri callback = wrapCustomEx $ do
    response <- request' browser
      $ setRequestHeaders reqHeaders
      $ mkRequest GET uri
    case rspCode response of
      (2, 0, 0)  -> withResponse response callback
      _otherwise -> throwIO $ UnexpectedResponse uri (rspCode response)

getRange :: Browser
         -> [HttpRequestHeader] -> URI -> (Int, Int)
         -> ([HttpResponseHeader] -> BodyReader -> IO a)
         -> IO a
getRange browser reqHeaders uri (from, to) callback = wrapCustomEx $ do
    response <- request' browser
      $ setRange from to
      $ setRequestHeaders reqHeaders
      $ mkRequest GET uri
    case rspCode response of
      (2, 0, 6)  -> withResponse response callback
      _otherwise -> throwIO $ UnexpectedResponse uri (rspCode response)

{-------------------------------------------------------------------------------
  Auxiliary methods used to implement the HttpClient interface
-------------------------------------------------------------------------------}

withResponse :: Response BS.L.ByteString
             -> ([HttpResponseHeader] -> BodyReader -> IO a)
             -> IO a
withResponse response callback = do
    br <- bodyReaderFromBS $ decompress (rspBody response)
    callback responseHeaders $ wrapCustomEx br
  where
    responseHeaders    = getResponseHeaders response
    needsDecompression = HttpResponseContentCompression `elem` responseHeaders
    decompress         = if needsDecompression then GZip.decompress else id

{-------------------------------------------------------------------------------
  Custom exception types
-------------------------------------------------------------------------------}

-- | Wrap custom exceptions
--
-- The @HTTP@ libary itself does not define any custom exceptions.
-- The ZLib library defines a custom exception type only from 0.6 and up
-- (before that a deserialization error will result in an 'error' call.)
wrapCustomEx :: forall a. IO a -> IO a
wrapCustomEx act = catches act [
      Handler $ \(ex :: UnexpectedResponse)   -> go ex
#if MIN_VERSION_zlib(0,6,0)
    , Handler $ \(ex :: GZip.DecompressError) -> go ex
#endif
      -- Case for InvalidProxy intentionally omitted (not recoverable)
    ]
  where
    go :: Exception e => e -> IO a
    go = throwIO . CustomRecoverableException

data UnexpectedResponse = UnexpectedResponse URI (Int, Int, Int)
  deriving (Show, Typeable)

data InvalidProxy = InvalidProxy String
  deriving (Show, Typeable)

instance Exception UnexpectedResponse
instance Exception InvalidProxy

{-------------------------------------------------------------------------------
  Browser state
-------------------------------------------------------------------------------}

type LazyStream = HandleStream BS.L.ByteString

data Browser = Browser {
    browserState :: MVar (BrowserState LazyStream)
  }

-- | Run a browser action
--
-- IMPLEMENTATION NOTE: the 'browse' action doesn't itself create any
-- connections, they are created on demand; we just need to make sure to carry
-- this state from one invocation of 'browse' to another.
withBrowser :: forall a. Browser -> BrowserAction LazyStream a -> IO a
withBrowser Browser{..} act = modifyMVar browserState $ \bst -> browse $ do
    State.put bst
    result <- act
    bst'   <- State.get
    return (bst', result)

-- | Initial browser state
--
-- Throws an 'InvalidProxy' exception if the proxy definition is invalid.
--
-- TODO: If the proxy configuration is automatic, the _only_ way that we can
-- find out from the @HTTP@ library is to pass @True@ as the argument to
-- 'fetchProxy'; but this prints to standard error when the proxy is invalid,
-- rather than throwing an exception :-O
browserInit :: ProxyConfig String
            -> (String -> IO ())
            -> (String -> IO ())
            -> IO Browser
browserInit proxyConfig outLog errLog = do
    proxy <- case proxyConfig of
      ProxyConfigNone  -> return NoProxy
      ProxyConfigAuto  -> fetchProxy True
      ProxyConfigUse p -> case parseProxy p of
                             Nothing -> throwIO $ InvalidProxy p
                             Just p' -> return p'
    browserState <- newMVar =<< browse (initAction (emptyAsNone proxy))
    return Browser{..}
  where
    initAction :: Proxy -> BrowserAction LazyStream (BrowserState LazyStream)
    initAction proxy = do
        setOutHandler outLog
        setErrHandler errLog
        setProxy proxy
        State.get

    emptyAsNone :: Proxy -> Proxy
    emptyAsNone (Proxy uri _) | null uri = NoProxy
    emptyAsNone p = p

-- | Cleanup browser state
--
-- NOTE: Calling 'withBrowser' after 'browserCleanup' will result in deadlock.
--
-- IMPLEMENTATION NOTE: "HTTP" does not provide any explicit API for resource
-- cleanup, so we can only rely on the garbage collector to do for us.
browserCleanup :: Browser -> IO ()
browserCleanup Browser{..} = void $ takeMVar browserState

-- | Execute a single request
request' :: Browser -> Request BS.L.ByteString -> IO (Response BS.L.ByteString)
request' browser = liftM snd . withBrowser browser . request

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

setRequestHeaders :: HasHeaders a => [HttpRequestHeader] -> a -> a
setRequestHeaders =
    foldr (.) id . map (uncurry insertHeader) . trOpt []
  where
    trOpt :: [(HeaderName, [String])]
          -> [HttpRequestHeader]
          -> [(HeaderName, String)]
    trOpt acc [] =
      concatMap finalizeHeader acc
    trOpt acc (HttpRequestMaxAge0:os) =
      trOpt (insert HdrCacheControl ["max-age=0"] acc) os
    trOpt acc (HttpRequestNoTransform:os) =
      trOpt (insert HdrCacheControl ["no-transform"] acc) os
    trOpt acc (HttpRequestContentCompression:os) =
      trOpt (insert HdrAcceptEncoding ["gzip"] acc) os

    -- Some headers are comma-separated, others need multiple headers for
    -- multiple options.
    --
    -- TODO: Right we we just comma-separate all of them.
    finalizeHeader :: (HeaderName, [String]) -> [(HeaderName, String)]
    finalizeHeader (name, strs) = [(name, intercalate ", " (reverse strs))]

    insert :: (Eq a, Monoid b) => a -> b -> [(a, b)] -> [(a, b)]
    insert x y = Lens.modify (Lens.lookupM x) (mappend y)

getResponseHeaders :: Response a -> [HttpResponseHeader]
getResponseHeaders response = concat [
    -- Check the @Accept-Ranges@ header.
    --
    -- @Accept-Ranges@ takes a _single_ argument, but there might potentially
    -- be more than one of them (although the spec does not explicitly say so).

    -- See <http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.5>
    -- and <http://www.w3.org/Protocols/rfc2616/rfc2616-sec3.html#sec3.12>
    [ HttpResponseAcceptRangesBytes
    | "bytes" `elem` map hdrValue (retrieveHeaders hAcceptRanges response)
    ]
  , [ HttpResponseContentCompression
    | findHeader HdrContentEncoding response == Just "gzip"
    ]
  ]
