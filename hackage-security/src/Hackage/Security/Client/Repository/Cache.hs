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
  , getFromIndex
  , cacheRemoteFile
  ) where

import Control.Exception
import Control.Monad
import Codec.Archive.Tar (Entries(..))
import Codec.Archive.Tar.Index (TarIndex, IndexBuilder, TarEntryOffset)
import qualified Codec.Archive.Tar       as Tar
import qualified Codec.Archive.Tar.Index as TarIndex
import qualified Codec.Compression.GZip  as GZip
import qualified Data.ByteString         as BS
import qualified Data.ByteString.Builder as BS.Builder
import qualified Data.ByteString.Lazy    as BS.L

import Hackage.Security.Client.Repository
import Hackage.Security.Client.Formats
import Hackage.Security.TUF
import Hackage.Security.Util.Checked
import Hackage.Security.Util.IO
import Hackage.Security.Util.Path

-- | Location and layout of the local cache
data Cache = Cache {
      cacheRoot   :: AbsolutePath
    , cacheLayout :: CacheLayout
    }

-- | Cache a previously downloaded remote file
cacheRemoteFile :: forall down typ f. DownloadedFile down
                => Cache -> down typ -> Format f -> IsCached typ -> IO ()
cacheRemoteFile cache downloaded f isCached = do
    go f isCached
    -- TODO: This recreates the tar index ahead of time. Alternatively, we
    -- could delete the index here and then it will be rebuilt on first access.
    case isCached of
      CacheIndex -> rebuildTarIndex cache
      _otherwise -> return ()
  where
    go :: Format f -> IsCached typ -> IO ()
    go _   DontCache      = return ()
    go FUn (CacheAs file) = copyTo (cachedFilePath cache file)
    go FGz CacheIndex     = copyTo (cachedIndexPath cache FGz) >> unzipIndex
    go _ _ = error "cacheRemoteFile: unexpected case" -- TODO: enforce in types?

    copyTo :: AbsolutePath -> IO ()
    copyTo fp = do
      createDirectoryIfMissing True (takeDirectory fp)
      downloadedCopyTo downloaded fp

    -- Whether or not we downloaded the compressed index incrementally, we can
    -- always update the uncompressed index incrementally.
    -- NOTE: This assumes we already updated the compressed file.
    unzipIndex :: typ ~ Binary => IO ()
    unzipIndex = do
        createDirectoryIfMissing True (takeDirectory indexUn)
        compressed <- readLazyByteString indexGz
        let uncompressed = GZip.decompress compressed
        withFile indexUn ReadWriteMode $ \h -> do
          currentSize <- hFileSize h
          let seekTo | currentSize == 0 = 0
                     | otherwise        = currentSize - tarTrailer
          hSeek h AbsoluteSeek seekTo
          BS.L.hPut h $ BS.L.drop (fromInteger seekTo) uncompressed
      where
        indexGz = cachedIndexPath cache FGz
        indexUn = cachedIndexPath cache FUn

    tarTrailer :: Integer
    tarTrailer = 1024

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
        Right idx -> atomicWithFile (cachedIndexIdxPath cache) $ \hIdx -> do
                       hSetBuffering hIdx (BlockBuffering Nothing)
                       BS.Builder.hPutBuilder hIdx $ TarIndex.serialise idx
  where
    -- The initial index builder
    -- If we don't have an index (or it's broken), we start from scratch
    initBuilder :: Either e TarIndex -> (IndexBuilder, TarEntryOffset)
    initBuilder (Left  _)   = ( TarIndex.emptyIndex, 0 )
    initBuilder (Right idx) = ( TarIndex.resumeIndexBuilder  idx
                              , TarIndex.indexEndEntryOffset idx
                              )

-- | Get a cached file (if available)
getCached :: Cache -> CachedFile -> IO (Maybe AbsolutePath)
getCached cache cachedFile = do
    exists <- doesFileExist localPath
    if exists then return $ Just localPath
              else return $ Nothing
  where
    localPath = cachedFilePath cache cachedFile

-- | Get the cached index (if available)
getCachedIndex :: Cache -> Format f -> IO (Maybe AbsolutePath)
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
getCachedRoot :: Cache -> IO AbsolutePath
getCachedRoot cache = do
    mPath <- getCached cache CachedRoot
    case mPath of
      Just p  -> return p
      Nothing -> internalError "Client missing root info"

-- | Get a file from the index
getFromIndex :: Cache -> IndexLayout -> IndexFile -> IO (Maybe BS.ByteString)
getFromIndex cache indexLayout indexFile = do
    mIndex <- tryReadIndex (cachedIndexIdxPath cache)
    case mIndex of
      Left _err -> do
        -- If index is corrupted, rebuild and try again
        rebuildTarIndex cache
        getFromIndex cache indexLayout indexFile
      Right index ->
        case tarIndexLookup index (tarPath (indexFilePath indexLayout indexFile)) of
          Just (TarIndex.TarFileEntry offset) ->
            -- TODO: We might want to keep this handle open
            withFile (cachedIndexPath cache FUn) ReadMode $ \h -> do
              entry <- TarIndex.hReadEntry h offset
              case Tar.entryContent entry of
                Tar.NormalFile lbs _size -> do
                  bs <- evaluate $ BS.concat . BS.L.toChunks $ lbs
                  return $ Just bs
                _otherwise ->
                  return Nothing
          _otherwise ->
            return Nothing
  where
    tarPath :: IndexPath -> TarballPath
    tarPath = castRoot

-- | Delete a previously downloaded remote file
clearCache :: Cache -> IO ()
clearCache cache = void . handleDoesNotExist $ do
    removeFile $ cachedFilePath cache CachedTimestamp
    removeFile $ cachedFilePath cache CachedSnapshot

{-------------------------------------------------------------------------------
  Auxiliary: tar
-------------------------------------------------------------------------------}

-- | Variation on 'TarIndex.build' that takes in the initial 'IndexBuilder'
addEntries :: IndexBuilder -> Entries e -> Either e TarIndex
addEntries = go
  where
    go !builder (Next e es) = go (TarIndex.addNextEntry e builder) es
    go !builder  Done       = Right $! TarIndex.finaliseIndex builder
    go !_       (Fail err)  = Left err

-- TODO: How come 'deserialise' uses _strict_ ByteStrings?
tryReadIndex :: AbsolutePath -> IO (Either (Maybe IOException) TarIndex)
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

cachedFilePath :: Cache -> CachedFile -> AbsolutePath
cachedFilePath Cache{cacheLayout=CacheLayout{..}, ..} file =
    anchorCachePath cacheRoot $ go file
  where
    go :: CachedFile -> CachePath
    go CachedRoot      = cacheLayoutRoot
    go CachedTimestamp = cacheLayoutTimestamp
    go CachedSnapshot  = cacheLayoutSnapshot
    go CachedMirrors   = cacheLayoutMirrors

cachedIndexPath :: Cache -> Format f -> AbsolutePath
cachedIndexPath Cache{..} format =
    anchorCachePath cacheRoot $ go format
  where
    go :: Format f -> CachePath
    go FUn = cacheLayoutIndexTar   cacheLayout
    go FGz = cacheLayoutIndexTarGz cacheLayout

cachedIndexIdxPath :: Cache -> AbsolutePath
cachedIndexIdxPath Cache{..} =
    anchorCachePath cacheRoot $ cacheLayoutIndexIdx cacheLayout
