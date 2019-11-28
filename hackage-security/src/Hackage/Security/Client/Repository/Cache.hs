{-# LANGUAGE BangPatterns #-}
-- | The files we cache from the repository
--
-- Both the Local and the Remote repositories make use of this module.
module Hackage.Security.Client.Repository.Cache (
    Cache(..)
  , getCached
  , getCachedRoot
  , getCachedIndex
  , clearCache
  , withIndex
  , getIndexIdx
  , cacheRemoteFile
  , lockCache
  , lockCacheWithLogger
  ) where

import Control.Exception
import Control.Monad
import Control.Monad.IO.Class
import Data.Maybe
import Codec.Archive.Tar (Entries(..))
import Codec.Archive.Tar.Index (TarIndex, IndexBuilder, TarEntryOffset)
import qualified Codec.Archive.Tar       as Tar
import qualified Codec.Archive.Tar.Index as TarIndex
import qualified Codec.Compression.GZip  as GZip
import qualified Data.ByteString         as BS
import qualified Data.ByteString.Lazy    as BS.L

import Hackage.Security.Client.Repository
import Hackage.Security.Client.Formats
import Hackage.Security.TUF
import Hackage.Security.Util.Checked
import Hackage.Security.Util.Exit
import Hackage.Security.Util.IO
import Hackage.Security.Util.Path

-- | Location and layout of the local cache
data Cache = Cache {
      cacheRoot   :: Path Absolute
    , cacheLayout :: CacheLayout
    }

-- | Cache a previously downloaded remote file
cacheRemoteFile :: forall down typ f. DownloadedFile down
                => Cache -> down typ -> Format f -> IsCached typ -> IO ()
cacheRemoteFile cache downloaded f isCached = do
    go f isCached
    case isCached of
      CacheIndex -> rebuildTarIndex cache
      _otherwise -> return ()
  where
    go :: Format f -> IsCached typ -> IO ()
    go _   DontCache      = return ()
    go FUn (CacheAs file) = copyTo (cachedFilePath cache file)
    go FGz CacheIndex     = copyTo (cachedIndexPath cache FGz) >> unzipIndex
    go _ _ = error "cacheRemoteFile: unexpected case" -- TODO: enforce in types?

    copyTo :: Path Absolute -> IO ()
    copyTo fp = do
      createDirectoryIfMissing True (takeDirectory fp)
      downloadedCopyTo downloaded fp

    -- Whether or not we downloaded the compressed index incrementally, we can
    -- update the uncompressed index incrementally (assuming the local files
    -- have not been corrupted).
    -- NOTE: This assumes we already updated the compressed file.
    unzipIndex :: IO ()
    unzipIndex = do
        createDirectoryIfMissing True (takeDirectory indexUn)
        shouldTryIncremental <- cachedIndexProbablyValid
        if shouldTryIncremental
          then do
            success <- unzipIncremental
            unless success unzipNonIncremental
          else unzipNonIncremental
      where
        unzipIncremental = do
          compressed <- readLazyByteString indexGz
          let uncompressed = GZip.decompress compressed

          -- compare prefix of old index with prefix of new index to
          -- ensure that it's safe to incrementally append
          (seekTo',newTail') <- withFile indexUn ReadMode $ \h ->
                                multipleExitPoints $ do
            currentSize <- liftIO $ hFileSize h
            let seekTo = 0 `max` (currentSize - tarTrailer)
                (newPrefix,newTail) = BS.L.splitAt (fromInteger seekTo)
                                      uncompressed

            (oldPrefix,oldTrailer) <- BS.L.splitAt (fromInteger seekTo) <$>
                                      liftIO (BS.L.hGetContents h)

            unless (oldPrefix == newPrefix) $
              exit (0,mempty) -- corrupted index.tar prefix

            -- sanity check: verify there's a 1KiB zero-filled trailer
            unless (oldTrailer == tarTrailerBs) $
              exit (0,mempty) -- corrupted .tar trailer

            return (seekTo,newTail)

          if seekTo' <= 0
          then return False -- fallback to non-incremental update
          else withFile indexUn ReadWriteMode $ \h -> do
            -- everything seems fine; append the new data
            liftIO $ hSeek h AbsoluteSeek seekTo'
            liftIO $ BS.L.hPut h newTail'
            return True

        unzipNonIncremental = do
          compressed <- readLazyByteString indexGz
          let uncompressed = GZip.decompress compressed
          withFile indexUn WriteMode $ \h ->
            BS.L.hPut h uncompressed
          void . handleDoesNotExist $
            removeFile indexIdx -- Force a full rebuild of the index too

        -- When we update the 00-index.tar we also update the 00-index.tar.idx
        -- so the expected state is that the modification time for the tar.idx
        -- is the same or later than the .tar file. But if someone modified
        -- the 00-index.tar then the modification times will be reversed. So,
        -- if the modification times are reversed then we should not do an
        -- incremental update but should rewrite the whole file.
        cachedIndexProbablyValid :: IO Bool
        cachedIndexProbablyValid =
          fmap (fromMaybe False) $
          handleDoesNotExist $ do
            tsUn  <- getModificationTime indexUn
            tsIdx <- getModificationTime indexIdx
            return (tsIdx >= tsUn)

        indexGz  = cachedIndexPath cache FGz
        indexUn  = cachedIndexPath cache FUn
        indexIdx = cachedIndexIdxPath cache

    tarTrailer :: Integer
    tarTrailer = 1024

    tarTrailerBs = BS.L.replicate (fromInteger tarTrailer) 0x00

-- | Rebuild the tarball index
--
-- Attempts to add to the existing index, if one exists.
--
-- TODO: Use throwChecked rather than throwUnchecked, and deal with the fallout.
-- See <https://github.com/well-typed/hackage-security/issues/84>.
rebuildTarIndex :: Cache -> IO ()
rebuildTarIndex cache = do
    (builder, offset) <- initBuilder <$> tryReadIndex (cachedIndexIdxPath cache)
    withFile (cachedIndexPath cache FUn) ReadMode $ \hTar -> do
      TarIndex.hSeekEntryOffset hTar offset
      newEntries <- Tar.read <$> BS.L.hGetContents hTar
      case addEntries builder newEntries of
        Left  ex  -> throwUnchecked ex
        Right idx -> withFile (cachedIndexIdxPath cache) WriteMode $ \hIdx -> do
                       hSetBuffering hIdx (BlockBuffering Nothing)
                       BS.hPut hIdx $ TarIndex.serialise idx
  where
    -- The initial index builder
    -- If we don't have an index (or it's broken), we start from scratch
    initBuilder :: Either e TarIndex -> (IndexBuilder, TarEntryOffset)
    initBuilder (Left  _)   = ( TarIndex.empty, 0 )
    initBuilder (Right idx) = ( TarIndex.unfinalise          idx
                              , TarIndex.indexEndEntryOffset idx
                              )

-- | Get a cached file (if available)
getCached :: Cache -> CachedFile -> IO (Maybe (Path Absolute))
getCached cache cachedFile = do
    exists <- doesFileExist localPath
    if exists then return $ Just localPath
              else return $ Nothing
  where
    localPath = cachedFilePath cache cachedFile

-- | Get the cached index (if available)
getCachedIndex :: Cache -> Format f -> IO (Maybe (Path Absolute))
getCachedIndex cache format = do
    exists <- doesFileExist localPath
    if exists then return $ Just localPath
              else return $ Nothing
  where
    localPath = cachedIndexPath cache format

-- | Get the cached root
--
-- Calling 'getCachedRoot' without root info available is a programmer error
-- and will result in an unchecked exception. See 'requiresBootstrap'.
getCachedRoot :: Cache -> IO (Path Absolute)
getCachedRoot cache = do
    mPath <- getCached cache CachedRoot
    case mPath of
      Just p  -> return p
      Nothing -> internalError "Client missing root info"

getIndexIdx :: Cache -> IO TarIndex
getIndexIdx cache = do
    mIndex <- tryReadIndex $ cachedIndexIdxPath cache
    case mIndex of
      Left  _   -> throwIO $ userError "Could not read index. Did you call 'checkForUpdates'?"
      Right idx -> return idx

withIndex :: Cache -> (Handle -> IO a) -> IO a
withIndex cache = withFile (cachedIndexPath cache FUn) ReadMode

-- | Delete a previously downloaded remote file
clearCache :: Cache -> IO ()
clearCache cache = void . handleDoesNotExist $ do
    removeFile $ cachedFilePath cache CachedTimestamp
    removeFile $ cachedFilePath cache CachedSnapshot

-- | Lock the cache
--
-- This avoids two concurrent processes updating the cache at the same time,
-- provided they both take the lock.
lockCache :: Cache -> IO () -> IO ()
lockCache Cache{..} = withDirLock (\_ -> return ()) cacheRoot

-- | Variant of 'lockCache' which emits 'LogMessage's before and after
-- a possibly blocking file-locking system call
--
-- @since 0.6.0
lockCacheWithLogger :: (LogMessage -> IO ()) -> Cache -> IO () -> IO ()
lockCacheWithLogger logger Cache{..} = withDirLock logger' cacheRoot
  where
    logger' (WithDirLockEventPre    fn) = logger (LogLockWait     fn)
    logger' (WithDirLockEventPost   fn) = logger (LogLockWaitDone fn)
    logger' (WithDirLockEventUnlock fn) = logger (LogUnlock       fn)

{-------------------------------------------------------------------------------
  Auxiliary: tar
-------------------------------------------------------------------------------}

-- | Variation on 'TarIndex.build' that takes in the initial 'IndexBuilder'
addEntries :: IndexBuilder -> Entries e -> Either e TarIndex
addEntries = go
  where
    go !builder (Next e es) = go (TarIndex.addNextEntry e builder) es
    go !builder  Done       = Right $! TarIndex.finalise builder
    go !_       (Fail err)  = Left err

-- TODO: How come 'deserialise' uses _strict_ ByteStrings?
tryReadIndex :: Path Absolute -> IO (Either (Maybe IOException) TarIndex)
tryReadIndex fp =
    aux <$> try (TarIndex.deserialise <$> readStrictByteString fp)
  where
    aux :: Either e (Maybe (a, leftover)) -> Either (Maybe e) a
    aux (Left e)              = Left (Just e)
    aux (Right Nothing)       = Left Nothing
    aux (Right (Just (a, _))) = Right a

{-------------------------------------------------------------------------------
  Auxiliary: paths
-------------------------------------------------------------------------------}

cachedFilePath :: Cache -> CachedFile -> Path Absolute
cachedFilePath Cache{cacheLayout=CacheLayout{..}, ..} file =
    anchorCachePath cacheRoot $ go file
  where
    go :: CachedFile -> CachePath
    go CachedRoot      = cacheLayoutRoot
    go CachedTimestamp = cacheLayoutTimestamp
    go CachedSnapshot  = cacheLayoutSnapshot
    go CachedMirrors   = cacheLayoutMirrors

cachedIndexPath :: Cache -> Format f -> Path Absolute
cachedIndexPath Cache{..} format =
    anchorCachePath cacheRoot $ go format
  where
    go :: Format f -> CachePath
    go FUn = cacheLayoutIndexTar   cacheLayout
    go FGz = cacheLayoutIndexTarGz cacheLayout

cachedIndexIdxPath :: Cache -> Path Absolute
cachedIndexIdxPath Cache{..} =
    anchorCachePath cacheRoot $ cacheLayoutIndexIdx cacheLayout
