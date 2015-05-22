module Hackage.Security.Client.Repository.Local (
    LocalRepo
  , Cache
  , initRepo
    -- * Low-level API (for the benefit of other Repository implementations)
  , getCached
  , getCachedRoot
  , getCachedIndex
  , clearCache
  , getFromIndex
  , cacheRemoteFile
  ) where

import Control.Exception
import System.Directory
import System.FilePath
import qualified Codec.Compression.GZip as GZip
import qualified Data.ByteString        as BS
import qualified Data.ByteString.Lazy   as BS.L

import Hackage.Security.Client.Repository
import Hackage.Security.Client.Formats
import Hackage.Security.Util.IO
import Hackage.Security.Util.Some
import qualified Hackage.Security.Client.IndexTarball as Index

{-------------------------------------------------------------------------------
  Top-level
-------------------------------------------------------------------------------}

type LocalRepo = FilePath
type Cache     = FilePath

-- | Initialy a local repository
initRepo :: LocalRepo             -- ^ Location of local repository
         -> Cache                 -- ^ Location of local cache
         -> (LogMessage -> IO ()) -- ^ Logger
         -> Repository
initRepo repo cache logger = Repository {
    repWithRemote    = withRemote repo cache
  , repGetCached     = getCached     cache
  , repGetCachedRoot = getCachedRoot cache
  , repClearCache    = clearCache    cache
  , repGetFromIndex  = getFromIndex  cache
  , repLog           = logger
  }

{-------------------------------------------------------------------------------
  Implementations of the various methods of Repository
-------------------------------------------------------------------------------}

-- | Get a file from the server
withRemote :: LocalRepo -> Cache
           -> RemoteFile fs -> (SelectedFormat fs -> TempPath -> IO a) -> IO a
withRemote repo cache remoteFile callback = do
    result <- callback format remotePath
    cacheRemoteFile cache
                    remotePath
                    (selectedFormatSome format)
                    (mustCache remoteFile)
    return result
  where
    (format, remotePath') = formatsPrefer
                              (remoteFileNonEmpty remoteFile)
                              FUn
                              (remoteFilePath remoteFile)
    remotePath = repo </> remotePath'

-- | Cache a previously downloaded remote file
cacheRemoteFile :: Cache -> TempPath -> Some Format -> IsCached -> IO ()
cacheRemoteFile cache tempPath (Some f) isCached =
    go f (cachedFileName isCached)
  where
    go :: Format f -> Maybe FilePath -> IO ()
    go _ Nothing =
      return () -- Don't cache
    go FUn (Just localName) = do
      -- TODO: (here and elsewhere): use atomic file operation instead
      copyFile tempPath (cache </> localName)
    go FGz (Just localName) = do
      compressed <- BS.L.readFile tempPath
      BS.L.writeFile (cache </> localName) $ GZip.decompress compressed

-- | The name of the file as cached
--
-- Returns @Nothing@ if we do not cache this file.
--
-- NOTE: We always cache files locally in uncompressed format. This is a
-- policy of this implementation of 'Repository', however, and other policies
-- are possible; that's why this lives here rather than in @Client.Repository@.
cachedFileName :: IsCached -> Maybe FilePath
cachedFileName (CacheAs cachedFile) = Just $ cachedFilePath cachedFile
cachedFileName CacheIndex           = Just "00-index.tar"
cachedFileName DontCache            = Nothing

-- | Get a cached file (if available)
getCached :: Cache -> CachedFile -> IO (Maybe FilePath)
getCached cache cachedFile = do
    exists <- doesFileExist localPath
    if exists then return $ Just localPath
              else return $ Nothing
  where
    localPath = cache </> cachedFilePath cachedFile

-- | Get the cached index (if available)
getCachedIndex :: Cache -> IO (Maybe FilePath)
getCachedIndex cache = do
    exists <- doesFileExist localPath
    if exists then return $ Just localPath
              else return $ Nothing
  where
    localPath = cache </> "00-index.tar"

-- | Get the cached root
getCachedRoot :: Cache -> IO FilePath
getCachedRoot cache = do
    mPath <- getCached cache CachedRoot
    case mPath of
      Just path -> return path
      Nothing   -> throwIO $ userError "Client missing root info"

-- | Get a file from the index
getFromIndex :: Cache -> IndexFile -> IO (Maybe BS.ByteString)
getFromIndex cache indexFile =
    force =<< Index.extractFile
      (cache </> "00-index.tar")
      (indexFilePath indexFile)
  where
    force :: Maybe BS.L.ByteString -> IO (Maybe BS.ByteString)
    force Nothing   = return Nothing
    force (Just bs) = Just <$> (evaluate . BS.concat . BS.L.toChunks $ bs)

-- | Delete a previously downloaded remote file
clearCache :: Cache -> IO ()
clearCache cache = ignoreDoesNotExist $ do
    removeFile $ cache </> cachedFilePath CachedTimestamp
    removeFile $ cache </> cachedFilePath CachedSnapshot
