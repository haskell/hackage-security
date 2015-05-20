module Hackage.Security.Client.Repository.HTTP (
    HttpClient(..)
  , FileSize(..)
  , Cache
  , initRepo
  ) where

import Network.URI
import System.FilePath

import Hackage.Security.Client.Repository
import Hackage.Security.Client.Repository.Local (Cache)
import Hackage.Security.TUF
import qualified Hackage.Security.Client.Repository.Local as Local

{-------------------------------------------------------------------------------
  Top-level API
-------------------------------------------------------------------------------}

data FileSize =
    -- | For most files we download we know the exact size beforehand
    -- (because this information comes from the snapshot or delegated info)
    FileSizeExact Int

    -- | For some files we might not know the size beforehand, but we might
    -- be able to provide an upper bound (timestamp, root info)
  | FileSizeBound Int

    -- | If we don't want to guess, we can also just indicate we have no idea
    -- what size file we are expecting. This means we cannot protect against
    -- endless data attacks however.
  | FileSizeUnknown

-- | Abstraction over HTTP clients
--
-- This avoids insisting on a particular implementation (such as the HTTP
-- package) and allows for other implements (such as a conduit based one)
data HttpClient = HttpClient {
    httpClientGet :: forall a. URI -> FileSize -> (TempPath -> IO a) -> IO a
  }

initRepo :: HttpClient  -- ^ Implementation of the HTTP protocol
         -> URI         -- ^ Base URI
         -> Cache       -- ^ Location of local cache
         -> Repository
initRepo http auth cache = Repository {
    repWithRemote    = withRemote http auth cache
  , repGetCached     = Local.getCached     cache
  , repGetCachedRoot = Local.getCachedRoot cache
  , repClearCache    = Local.clearCache    cache
  , repGetFromIndex  = Local.getFromIndex  cache
  -- TODO: We should allow clients to plugin a proper logging message here
  -- (probably means accepting a callback to initRepo)
  , repLog = putStrLn . formatLogMessage
  }

{-------------------------------------------------------------------------------
  Implementations of the various methods of Repository
-------------------------------------------------------------------------------}

-- | Get a file from the server
--
-- TODO: We need to deal with the combined timestamp/snapshot thing
withRemote :: HttpClient -> URI -> Cache
           -> RemoteFile -> (Format -> TempPath -> IO a) -> IO a
withRemote HttpClient{..} baseURI cache remoteFile callback =
    httpClientGet uri sz $ \tempPath -> do
      result <- callback format tempPath
      Local.cacheRemoteFile cache tempPath format (mustCache remoteFile)
      return result
  where
    (format, (uri, sz)) = preferFormat FormatCompressedGz $
                            mergeMultipleFormats
                              (remoteFileURI baseURI remoteFile)
                              (remoteFileSize remoteFile)

remoteFileURI :: URI -> RemoteFile -> MultipleFormats URI
remoteFileURI baseURI = fmap aux . remoteFilePath
  where
    aux :: FilePath -> URI
    aux remotePath = baseURI { uriPath = uriPath baseURI </> remotePath }

-- | Extracting or estimating file sizes
--
-- TODO: Put in estimates
remoteFileSize :: RemoteFile -> MultipleFormats FileSize
remoteFileSize (RemoteTimestamp) = multipleFormats $
    [ (FormatUncompressed, FileSizeUnknown) ]
remoteFileSize (RemoteRoot mLen) = multipleFormats $
    [ (FormatUncompressed, sz) ]
  where
    sz = maybe FileSizeUnknown (FileSizeExact . trustedFileLength) mLen
remoteFileSize (RemoteSnapshot len) = multipleFormats $
    [ (FormatUncompressed, FileSizeExact (trustedFileLength len)) ]
remoteFileSize (RemoteIndex lens) =
    fmap (FileSizeExact . trustedFileLength) lens
remoteFileSize (RemotePkgTarGz _pkgId len) = multipleFormats $
    [ (FormatCompressedGz, FileSizeExact (trustedFileLength len)) ]
