module Hackage.Security.Client.Repository.Local (
    LocalRepo
  , Cache
  , initRepo
    -- * Low-level API (for the benefit of other Repository implementations)
  , getCached
  , getCachedRoot
  , clearCache
  , getFromIndex
  , cacheRemoteFile
  ) where

import Control.Exception
import System.Directory
import System.FilePath
import System.IO.Error
import qualified Codec.Compression.GZip as GZip
import qualified Data.ByteString        as BS
import qualified Data.ByteString.Lazy   as BS.L

import Hackage.Security.Client.Repository
import Hackage.Security.Client.Formats
import Hackage.Security.Util.Some
import qualified Hackage.Security.Client.IndexTarball as Index

{-------------------------------------------------------------------------------
  Top-level
-------------------------------------------------------------------------------}

type LocalRepo = FilePath
type Cache     = FilePath

-- | Initialy a local repository
initRepo :: LocalRepo -> Cache -> Repository
initRepo repo cache = Repository {
    repWithRemote    = withRemote repo cache
  , repGetCached     = getCached     cache
  , repGetCachedRoot = getCachedRoot cache
  , repClearCache    = clearCache    cache
  , repGetFromIndex  = getFromIndex  cache
  -- TODO: We should allow clients to plugin a proper logging message here
  -- (probably means accepting a callback to initRepo)
  , repLog = putStrLn . formatLogMessage
  }

{-------------------------------------------------------------------------------
  Implementations of the various methods of Repository
-------------------------------------------------------------------------------}

-- | Get a file from the server
withRemote :: LocalRepo -> Cache
           -> RemoteFile fs -> (FormatSum fs -> TempPath -> IO a) -> IO a
withRemote repo cache remoteFile callback = do
    result <- callback format remotePath
    cacheRemoteFile cache remotePath (formatSumSome format) (mustCache remoteFile)
    return result
  where
    (format, remotePath') = formatProdPrefer
                              (remoteFileNonEmpty remoteFile)
                              FormatUncompressed
                              (remoteFilePath remoteFile)
    remotePath = repo </> remotePath'

-- | Cache a previously downloaded remote file
cacheRemoteFile :: Cache -> TempPath -> Some Format -> IsCached -> IO ()
cacheRemoteFile cache tempPath (Some f) = go f
  where
    go :: Format f -> IsCached -> IO ()
    go FormatUncompressed (CacheAs cachedFile) = do
      let localPath = cache </> cachedFilePath cachedFile
      -- TODO: (here and elsewhere): use atomic file operation instead
      copyFile tempPath localPath
    go _ (CacheAs _) =
      error "the impossible happened: unexpected compressed file"
    go FormatUncompressed CacheIndex = do
      let localPath = cache </> "00-index.tar"
      copyFile tempPath localPath
    go FormatCompressedGz CacheIndex = do
      -- We always store the index uncompressed locally
      let localPath = cache </> "00-index.tar"
      compressed <- BS.L.readFile tempPath
      BS.L.writeFile localPath $ GZip.decompress compressed
    go _format DontCache =
      return ()

-- | Get a cached file (if available)
getCached :: Cache -> CachedFile -> IO (Maybe FilePath)
getCached cache cachedFile = do
    exists <- doesFileExist localPath
    if exists then return $ Just localPath
              else return $ Nothing
  where
    localPath = cache </> cachedFilePath cachedFile

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
clearCache cache = handle ignoreDoesNotExist $ do
    removeFile $ cache </> cachedFilePath CachedTimestamp
    removeFile $ cache </> cachedFilePath CachedSnapshot
  where
    ignoreDoesNotExist e =
      if isDoesNotExistError e
        then return ()
        else throwIO e
