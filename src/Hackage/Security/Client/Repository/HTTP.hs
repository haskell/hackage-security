module Hackage.Security.Client.Repository.HTTP (
    HttpClient(..)
  , FileSize(..)
  , Cache
  , initRepo
  ) where

import Network.URI
import System.FilePath
import System.IO
import qualified Data.ByteString.Lazy as BS.L

import Hackage.Security.Client.Formats
import Hackage.Security.Client.Repository
import Hackage.Security.Client.Repository.Local (Cache)
import Hackage.Security.Trusted
import Hackage.Security.TUF
import Hackage.Security.Util.IO
import Hackage.Security.Util.Some
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
    --
    -- TODO: Once we put in estimates we should get rid of this.
  | FileSizeUnknown

-- | Abstraction over HTTP clients
--
-- This avoids insisting on a particular implementation (such as the HTTP
-- package) and allows for other implements (such as a conduit based one)
data HttpClient = HttpClient {
    -- | Download a file
    httpClientGet :: forall a. URI -> FileSize -> (TempPath -> IO a) -> IO a

    -- | Download a byte range
    --
    -- Range is starting and (exclusive) end offset in bytes.
  , httpClientGetRange :: forall a. URI -> (Int, Int) -> (TempPath -> IO a) -> IO a
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
           -> RemoteFile fs
           -> (SelectedFormat fs -> TempPath -> IO a) -> IO a
withRemote httpClient baseURI cache remoteFile callback = do
    -- We can do incremental updates only when the following conditions are met:
    --
    -- 1. The server must be able to provide the file in uncompressed format
    -- 2. We already have a local file to be updated
    --    (if not we should try to download the initial file in compressed form)
    -- TODO: Others (HTTP capabilities of the server, etc)
    mCachedIndex <- Local.getCachedIndex cache
    case (mCachedIndex, remoteFile) of
      (Just fp, RemoteIndex _ (FsUn lenUn))     -> incTar' (SZ FUn) lenUn fp
      (Just fp, RemoteIndex _ (FsUnGz lenUn _)) -> incTar' (SZ FUn) lenUn fp
      _otherwise -> getFile' remoteFile
  where
    incTar' sf = incTar  httpClient baseURI cache (callback sf)
    getFile'   = getFile httpClient baseURI cache callback

-- | Get a tar file incrementally
--
-- Sadly, this has some tar-specific functionality
incTar :: HttpClient -> URI -> Cache
       -> (TempPath -> IO a)
       -> Trusted FileLength -> FilePath -> IO a
incTar HttpClient{..} baseURI cache callback len cachedFile = do
    -- TODO: Once we have a local tarball index, this is not necessary
    currentSize <- getFileSize cachedFile
    let currentMinusTrailer = currentSize - 1024
        range = (fromInteger currentMinusTrailer, trustedFileLength len)
    httpClientGetRange uri range $ \tempRange -> do
      withSystemTempFile "00-index.tar" $ \tempPath h -> do
        BS.L.hPut h =<< BS.L.readFile cachedFile
        hSeek h AbsoluteSeek currentMinusTrailer
        BS.L.hPut h =<< BS.L.readFile tempRange
        hClose h
        result <- callback tempPath
        Local.cacheRemoteFile cache tempPath (Some FUn) CacheIndex
        return result
  where
    -- TODO: There are hardcoded references to "00-index.tar" and
    -- "00-index.tar.gz" everwhere. We should probably abstract over that.
    uri = baseURI { uriPath = uriPath baseURI </> "00-index.tar" }

-- | Get any file from the server, without using incremental updates
getFile :: HttpClient -> URI -> Cache
        -> (SelectedFormat fs -> TempPath -> IO a)
        -> RemoteFile fs -> IO a
getFile HttpClient{..} baseURI cache callback remoteFile =
    httpClientGet uri sz $ \tempPath -> do
      result <- callback format tempPath
      Local.cacheRemoteFile cache
                            tempPath
                            (selectedFormatSome format)
                            (mustCache remoteFile)
      return result
  where
    (format, (uri, sz)) = formatsPrefer
                            (remoteFileNonEmpty remoteFile)
                            FGz
                            (formatsZip
                              (remoteFileURI baseURI remoteFile)
                              (remoteFileSize remoteFile))


remoteFileURI :: URI -> RemoteFile fs -> Formats fs URI
remoteFileURI baseURI = fmap aux . remoteFilePath
  where
    aux :: FilePath -> URI
    aux remotePath = baseURI { uriPath = uriPath baseURI </> remotePath }

-- | Extracting or estimating file sizes
--
-- TODO: Put in estimates
remoteFileSize :: RemoteFile fs -> Formats fs FileSize
remoteFileSize (RemoteTimestamp) =
    FsUn FileSizeUnknown
remoteFileSize (RemoteRoot mLen) =
    FsUn $ maybe FileSizeUnknown (FileSizeExact . trustedFileLength) mLen
remoteFileSize (RemoteSnapshot len) =
    FsUn $ FileSizeExact (trustedFileLength len)
remoteFileSize (RemoteIndex _ lens) =
    fmap (FileSizeExact . trustedFileLength) lens
remoteFileSize (RemotePkgTarGz _pkgId len) =
    FsGz $ FileSizeExact (trustedFileLength len)
