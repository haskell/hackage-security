{-# LANGUAGE CPP #-}
-- | Abstracting over HTTP libraries
module Hackage.Security.Client.Repository.HttpLib (
    HttpLib(..)
  , HttpRequestHeader(..)
  , HttpResponseHeader(..)
  , HttpStatus(..)
  , ProxyConfig(..)
    -- ** Body reader
  , BodyReader
  , bodyReaderFromBS
  ) where

import Data.IORef
import Network.URI hiding (uriPath, path)
import qualified Data.ByteString      as BS
import qualified Data.ByteString.Lazy as BS.L

import Hackage.Security.Util.Checked
import Hackage.Security.Client.Repository (SomeRemoteError)

{-------------------------------------------------------------------------------
  Abstraction over HTTP clients (such as HTTP, http-conduit, etc.)
-------------------------------------------------------------------------------}

-- | Abstraction over HTTP clients
--
-- This avoids insisting on a particular implementation (such as the HTTP
-- package) and allows for other implementations (such as a conduit based one).
--
-- NOTE: Library-specific exceptions MUST be wrapped in 'SomeRemoteError'.
data HttpLib = HttpLib {
    -- | Download a file
    httpGet :: forall a. Throws SomeRemoteError
            => [HttpRequestHeader]
            -> URI
            -> ([HttpResponseHeader] -> BodyReader -> IO a)
            -> IO a

    -- | Download a byte range
    --
    -- Range is starting and (exclusive) end offset in bytes.
    --
    -- HTTP servers are normally expected to respond to a range request with
    -- a "206 Partial Content" response. However, servers can respond with a
    -- "200 OK" response, sending the entire file instead (for instance, this
    -- may happen for servers that don't actually support range rqeuests, but
    -- for which we optimistically assumed they did). Implementations of
    -- 'HttpLib' may accept such a response and inform the @hackage-security@
    -- library that the whole file is being returned; the security library can
    -- then decide to execute the 'BodyReader' anyway (downloading the entire
    -- file) or abort the request and try something else. For this reason
    -- the security library must be informed whether the server returned the
    -- full file or the requested range.
  , httpGetRange :: forall a. Throws SomeRemoteError
                 => [HttpRequestHeader]
                 -> URI
                 -> (Int, Int)
                 -> (HttpStatus -> [HttpResponseHeader] -> BodyReader -> IO a)
                 -> IO a
  }

-- | Additional request headers
--
-- Since different libraries represent headers differently, here we just
-- abstract over the few request headers that we might want to set
data HttpRequestHeader =
    -- | Set @Cache-Control: max-age=0@
    HttpRequestMaxAge0

    -- | Set @Cache-Control: no-transform@
  | HttpRequestNoTransform
  deriving (Eq, Ord, Show)

-- | HTTP status code
data HttpStatus =
     -- | 200 OK
     HttpStatus200OK

     -- | 206 Partial Content
   | HttpStatus206PartialContent

-- | Response headers
--
-- Since different libraries represent headers differently, here we just
-- abstract over the few response headers that we might want to know about.
data HttpResponseHeader =
    -- | Server accepts byte-range requests (@Accept-Ranges: bytes@)
    HttpResponseAcceptRangesBytes
  deriving (Eq, Ord, Show)

-- | Proxy configuration
--
-- Although actually setting the proxy is the purview of the initialization
-- function for individual 'HttpLib' implementations and therefore outside
-- the scope of this module, we offer this 'ProxyConfiguration' type here as a
-- way to uniformly configure proxies across all 'HttpLib's.
data ProxyConfig a =
    -- | Don't use a proxy
    ProxyConfigNone

    -- | Use this specific proxy
    --
    -- Individual HTTP backends use their own types for specifying proxies.
  | ProxyConfigUse a

    -- | Use automatic proxy settings
    --
    -- What precisely automatic means is 'HttpLib' specific, though
    -- typically it will involve looking at the @HTTP_PROXY@ environment
    -- variable or the (Windows) registry.
  | ProxyConfigAuto

{-------------------------------------------------------------------------------
  Body readers
-------------------------------------------------------------------------------}

-- | An @IO@ action that represents an incoming response body coming from the
-- server.
--
-- The action gets a single chunk of data from the response body, or an empty
-- bytestring if no more data is available.
--
-- This definition is copied from the @http-client@ package.
type BodyReader = IO BS.ByteString

-- | Construct a 'Body' reader from a lazy bytestring
--
-- This is appropriate if the lazy bytestring is constructed, say, by calling
-- 'hGetContents' on a network socket, and the chunks of the bytestring
-- correspond to the chunks as they are returned from the OS network layer.
--
-- If the lazy bytestring needs to be re-chunked this function is NOT suitable.
bodyReaderFromBS :: BS.L.ByteString -> IO BodyReader
bodyReaderFromBS lazyBS = do
    chunks <- newIORef $ BS.L.toChunks lazyBS
    -- NOTE: Lazy bytestrings invariant: no empty chunks
    let br = do bss <- readIORef chunks
                case bss of
                  []        -> return BS.empty
                  (bs:bss') -> writeIORef chunks bss' >> return bs
    return br
