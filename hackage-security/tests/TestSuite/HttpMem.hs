-- | HttpLib bridge to the in-memory repository
module TestSuite.HttpMem (
    httpMem
  ) where

-- stdlib
import Network.URI (URI)
import qualified Data.ByteString.Lazy as BS.L

-- hackage-security
import Hackage.Security.Client
import Hackage.Security.Client.Repository.HttpLib
import Hackage.Security.Util.Checked
import Hackage.Security.Util.Path
import Hackage.Security.Util.Some

-- TestSuite
import TestSuite.InMemRepo

httpMem :: InMemRepo -> HttpLib
httpMem inMemRepo = HttpLib {
      httpGet      = get      inMemRepo
    , httpGetRange = getRange inMemRepo
    }

{-------------------------------------------------------------------------------
  Individual methods
-------------------------------------------------------------------------------}

-- | Download a file
--
-- Since we don't (yet?) make any attempt to simulate a cache, we ignore
-- caching headers.
get :: forall a. Throws SomeRemoteError
    => InMemRepo
    -> [HttpRequestHeader]
    -> URI
    -> ([HttpResponseHeader] -> BodyReader -> IO a)
    -> IO a
get InMemRepo{..} _requestHeaders uri callback = do
    Some inMemFile <- inMemRepoGetPath $ castRoot (uriPath uri)
    br <- bodyReaderFromBS $ inMemFileRender inMemFile
    callback [HttpResponseAcceptRangesBytes] br

-- | Download a byte range
--
-- Range is starting and (exclusive) end offset in bytes.
--
-- We ignore requests for compression; different servers deal with compression
-- for byte range requests differently; in particular, Apache returns the range
-- of the _compressed_ file, which is pretty useless for our purposes. For now
-- we ignore this issue completely here.
getRange :: forall a. Throws SomeRemoteError
         => InMemRepo
         -> [HttpRequestHeader]
         -> URI
         -> (Int, Int)
         -> (HttpStatus -> [HttpResponseHeader] -> BodyReader -> IO a)
         -> IO a
getRange InMemRepo{..} _requestHeaders uri (fr, to) callback = do
    Some inMemFile <- inMemRepoGetPath $ castRoot (uriPath uri)
    br <- bodyReaderFromBS $ substr (inMemFileRender inMemFile)

    let responseHeaders = concat [
            [ HttpResponseAcceptRangesBytes ]
          ]
    callback HttpStatus206PartialContent responseHeaders br
  where
    substr :: BS.L.ByteString -> BS.L.ByteString
    substr = BS.L.take (fromIntegral (to - fr)) . BS.L.drop (fromIntegral fr)
