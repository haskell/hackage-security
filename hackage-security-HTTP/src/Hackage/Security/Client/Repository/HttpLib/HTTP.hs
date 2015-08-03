{-# LANGUAGE CPP #-}
-- | Implementation of 'HttpClient' using the HTTP package
module Hackage.Security.Client.Repository.HttpLib.HTTP (
    withClient
    -- ** Additional operations
  , setOutHandler
  , setErrHandler
  , setProxy
  , request
    -- ** Low-level API
  , Browser -- opaque
  , withBrowser
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
import Network.URI
import qualified Data.ByteString.Lazy   as BS.L
import qualified Control.Monad.State    as State
import qualified Codec.Compression.GZip as GZip
import qualified Network.Browser        as HTTP
import qualified Network.HTTP           as HTTP
import qualified Network.HTTP.Proxy     as HTTP

#if MIN_VERSION_zlib(0,6,0)
import qualified Codec.Compression.Zlib.Internal as GZip (DecompressError)
#endif

import Hackage.Security.Client
import Hackage.Security.Client.Repository.HttpLib
import Hackage.Security.Util.Checked
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
withClient :: (Browser -> HttpLib -> IO a) -> IO a
withClient callback =
    bracket browserInit browserCleanup $ \browser ->
      callback browser HttpLib {
          httpGet      = get      browser
        , httpGetRange = getRange browser
        }

{-------------------------------------------------------------------------------
  Individual methods
-------------------------------------------------------------------------------}

get :: Throws SomeRemoteError
    => Browser
    -> [HttpRequestHeader] -> URI
    -> ([HttpResponseHeader] -> BodyReader -> IO a)
    -> IO a
get browser reqHeaders uri callback = wrapCustomEx $ do
    response <- request browser
      $ setRequestHeaders reqHeaders
      $ HTTP.mkRequest HTTP.GET uri
    case HTTP.rspCode response of
      (2, 0, 0) -> withResponse response callback
      otherCode -> throwChecked $ UnexpectedResponse uri otherCode

getRange :: Throws SomeRemoteError
         => Browser
         -> [HttpRequestHeader] -> URI -> (Int, Int)
         -> ([HttpResponseHeader] -> BodyReader -> IO a)
         -> IO a
getRange browser reqHeaders uri (from, to) callback = wrapCustomEx $ do
    response <- request browser
      $ setRange from to
      $ setRequestHeaders reqHeaders
      $ HTTP.mkRequest HTTP.GET uri
    case HTTP.rspCode response of
      (2, 0, 6) -> withResponse response callback
      otherCode -> throwChecked $ UnexpectedResponse uri otherCode

{-------------------------------------------------------------------------------
  Auxiliary methods used to implement the HttpClient interface
-------------------------------------------------------------------------------}

withResponse :: Throws SomeRemoteError
             => HTTP.Response BS.L.ByteString
             -> ([HttpResponseHeader] -> BodyReader -> IO a)
             -> IO a
withResponse response callback = wrapCustomEx $ do
    br <- bodyReaderFromBS $ decompress (HTTP.rspBody response)
    callback responseHeaders $ wrapCustomEx (checkDecompressError br)
  where
    responseHeaders    = getResponseHeaders response
    needsDecompression = HttpResponseContentCompression `elem` responseHeaders
    decompress         = if needsDecompression then GZip.decompress else id

{-------------------------------------------------------------------------------
  Custom exception types
-------------------------------------------------------------------------------}

#if MIN_VERSION_zlib(0,6,0)
wrapCustomEx :: ( ( Throws UnexpectedResponse
                  , Throws IOException
                  , Throws GZip.DecompressError
                  ) => IO a)
             -> (Throws SomeRemoteError => IO a)
wrapCustomEx act = handleChecked (\(ex :: UnexpectedResponse)   -> go ex)
                 $ handleChecked (\(ex :: IOException)          -> go ex)
                 $ handleChecked (\(ex :: GZip.DecompressError) -> go ex)
                 $ act
  where
    go ex = throwChecked (SomeRemoteError ex)

checkDecompressError :: Throws GZip.DecompressError => IO a -> IO a
checkDecompressError = handle $ \(ex :: GZip.DecompressError) -> throwChecked ex
#else
wrapCustomEx :: ( ( Throws UnexpectedResponse
                  , Throws IOException
                  ) => IO a)
             -> (Throws SomeRemoteError => IO a)
wrapCustomEx act = handleChecked (\(ex :: UnexpectedResponse) -> go ex)
                 $ handleChecked (\(ex :: IOException)        -> go ex)
                 $ act
  where
    go ex = throwChecked (SomeRemoteError ex)

checkDecompressError :: IO a -> IO a
checkDecompressError = id
#endif

data UnexpectedResponse = UnexpectedResponse URI (Int, Int, Int)
  deriving (Show, Typeable)

data InvalidProxy = InvalidProxy String
  deriving (Show, Typeable)

instance Exception UnexpectedResponse
instance Exception InvalidProxy

{-------------------------------------------------------------------------------
  Additional operations
-------------------------------------------------------------------------------}

setProxy :: Browser -> ProxyConfig String -> IO ()
setProxy browser proxyConfig = do
    proxy <- case proxyConfig of
      ProxyConfigNone  -> return HTTP.NoProxy
      ProxyConfigAuto  -> HTTP.fetchProxy True
      ProxyConfigUse p -> case HTTP.parseProxy p of
                             Nothing -> throwUnchecked $ InvalidProxy p
                             Just p' -> return p'
    withBrowser browser $ HTTP.setProxy (emptyAsNone proxy)
  where
    emptyAsNone :: HTTP.Proxy -> HTTP.Proxy
    emptyAsNone (HTTP.Proxy uri _) | null uri = HTTP.NoProxy
    emptyAsNone p = p

setOutHandler :: Browser -> (String -> IO ()) -> IO ()
setOutHandler browser = withBrowser browser . HTTP.setOutHandler

setErrHandler :: Browser -> (String -> IO ()) -> IO ()
setErrHandler browser = withBrowser browser . HTTP.setErrHandler

-- | Execute a single request
request :: Throws IOException
        => Browser
        -> HTTP.Request BS.L.ByteString
        -> IO (HTTP.Response BS.L.ByteString)
request browser = checkIO . liftM snd . withBrowser browser . HTTP.request

{-------------------------------------------------------------------------------
  Browser state
-------------------------------------------------------------------------------}

type LazyStream = HTTP.HandleStream BS.L.ByteString

data Browser = Browser {
    browserState :: MVar (HTTP.BrowserState LazyStream)
  }

-- | Run a browser action
--
-- IMPLEMENTATION NOTE: the 'browse' action doesn't itself create any
-- connections, they are created on demand; we just need to make sure to carry
-- this state from one invocation of 'browse' to another.
withBrowser :: forall a. Browser -> HTTP.BrowserAction LazyStream a -> IO a
withBrowser Browser{..} act = modifyMVar browserState $ \bst -> HTTP.browse $ do
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
browserInit :: IO Browser
browserInit = do
    browserState <- newMVar =<< HTTP.browse State.get
    return Browser{..}

-- | Cleanup browser state
--
-- NOTE: Calling 'withBrowser' after 'browserCleanup' will result in deadlock.
--
-- IMPLEMENTATION NOTE: "HTTP" does not provide any explicit API for resource
-- cleanup, so we can only rely on the garbage collector to do for us.
browserCleanup :: Browser -> IO ()
browserCleanup Browser{..} = void $ takeMVar browserState

{-------------------------------------------------------------------------------
  HTTP auxiliary
-------------------------------------------------------------------------------}

hAcceptRanges :: HTTP.HeaderName
hAcceptRanges = HTTP.HdrCustom "Accept-Ranges"

setRange :: HTTP.HasHeaders a => Int -> Int -> a -> a
setRange from to = HTTP.insertHeader HTTP.HdrRange rangeHeader
  where
    -- Content-Range header uses inclusive rather than exclusive bounds
    -- See <http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html>
    rangeHeader = "bytes=" ++ show from ++ "-" ++ show (to - 1)

setRequestHeaders :: HTTP.HasHeaders a => [HttpRequestHeader] -> a -> a
setRequestHeaders =
    foldr (.) id . map (uncurry HTTP.insertHeader) . trOpt []
  where
    trOpt :: [(HTTP.HeaderName, [String])]
          -> [HttpRequestHeader]
          -> [(HTTP.HeaderName, String)]
    trOpt acc [] =
      concatMap finalizeHeader acc
    trOpt acc (HttpRequestMaxAge0:os) =
      trOpt (insert HTTP.HdrCacheControl ["max-age=0"] acc) os
    trOpt acc (HttpRequestNoTransform:os) =
      trOpt (insert HTTP.HdrCacheControl ["no-transform"] acc) os
    trOpt acc (HttpRequestContentCompression:os) =
      trOpt (insert HTTP.HdrAcceptEncoding ["gzip"] acc) os

    -- Some headers are comma-separated, others need multiple headers for
    -- multiple options.
    --
    -- TODO: Right we we just comma-separate all of them.
    finalizeHeader :: (HTTP.HeaderName, [String]) -> [(HTTP.HeaderName, String)]
    finalizeHeader (name, strs) = [(name, intercalate ", " (reverse strs))]

    insert :: (Eq a, Monoid b) => a -> b -> [(a, b)] -> [(a, b)]
    insert x y = Lens.modify (Lens.lookupM x) (mappend y)

getResponseHeaders :: HTTP.Response a -> [HttpResponseHeader]
getResponseHeaders response = concat [
    -- Check the @Accept-Ranges@ header.
    --
    -- @Accept-Ranges@ takes a _single_ argument, but there might potentially
    -- be more than one of them (although the spec does not explicitly say so).

    -- See <http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.5>
    -- and <http://www.w3.org/Protocols/rfc2616/rfc2616-sec3.html#sec3.12>
    [ HttpResponseAcceptRangesBytes
    | "bytes" `elem` map HTTP.hdrValue (HTTP.retrieveHeaders hAcceptRanges response)
    ]
  , [ HttpResponseContentCompression
    | HTTP.findHeader HTTP.HdrContentEncoding response == Just "gzip"
    ]
  ]
