-- | IO utilities
{-# LANGUAGE CPP #-}
module Hackage.Security.RepoTool.Util.IO (
    -- * Miscellaneous
    compress
  , getFileModTime
#ifndef mingw32_HOST_OS
  , createSymbolicLink
#endif
    -- * Tar archives
  , TarGzError
  , tarExtractFile
  ) where

import qualified Codec.Archive.Tar                 as Tar
import qualified Codec.Archive.Tar.Entry           as Tar
import qualified Codec.Compression.GZip            as GZip
import           Control.Exception
import qualified Data.ByteString.Lazy              as BS.L
import           Data.Typeable
import qualified System.Directory                  as Directory
import           System.IO.Error

-- hackage-security
import           Hackage.Security.Util.Path

-- hackage-repo-tool
import           Hackage.Security.RepoTool.Layout
import           Hackage.Security.RepoTool.Options
import           Hackage.Security.RepoTool.Paths

import           System.Posix.Types                (EpochTime)
#ifndef mingw32_HOST_OS
import qualified System.Posix.Files                as Posix
#endif

#if MIN_VERSION_directory(1,2,0)
import           Data.Time.Clock.POSIX             (utcTimeToPOSIXSeconds)
#else
import           System.Time                       (ClockTime (TOD))
#endif

-- | Get the modification time of the specified file
--
-- Returns 0 if the file does not exist .
getFileModTime :: GlobalOpts -> RepoLoc -> TargetPath' -> IO EpochTime
getFileModTime opts repoLoc targetPath =
    handle handler $
      -- Underlying implementation of 'Directory.getModificationTime' converts
      -- from POSIX seconds, so there shouldn't be loss of precision.
      -- NB: Apparently, this has low clock resolution on GHC < 7.8.
      -- I don't think we care.
#if MIN_VERSION_directory(1,2,0)
      fromInteger . floor . utcTimeToPOSIXSeconds
        <$> Directory.getModificationTime (toFilePath fp)
#else
      Directory.getModificationTime (toFilePath fp) >>= \(TOD s _) ->
        return (fromInteger s)
#endif
  where
    fp :: Path Absolute
    fp = anchorTargetPath' opts repoLoc targetPath

    handler :: IOException -> IO EpochTime
    handler ex = if isDoesNotExistError ex then return 0
                                           else throwIO ex

compress :: Path Absolute -> Path Absolute -> IO ()
compress src dst =
    withFile dst WriteMode $ \h ->
      BS.L.hPut h =<< GZip.compress <$> readLazyByteString src

#ifndef mingw32_HOST_OS
-- | Create a symbolic link (unix only)
--
-- Create the directory for the target if it does not exist.
--
-- TODO: Currently this always creates links to absolute locations, whether the
-- user specified an absolute or a relative target.
createSymbolicLink :: (FsRoot root, FsRoot root')
                   => Path root  -- ^ Link target
                   -> Path root' -- ^ Link location
                   -> IO ()
createSymbolicLink linkTarget linkLoc = do
    createDirectoryIfMissing True (takeDirectory linkLoc)
    linkTarget' <- toAbsoluteFilePath linkTarget
    linkLoc'    <- toAbsoluteFilePath linkLoc
    Posix.createSymbolicLink linkTarget' linkLoc'
#endif

{-------------------------------------------------------------------------------
  Working with tar archives
-------------------------------------------------------------------------------}

-- | Extract a file from a tar archive
--
-- Throws an exception if there is an error in the archive or when the entry
-- is not a file. Returns nothing if the entry cannot be found.
tarExtractFile :: GlobalOpts
               -> RepoLoc
               -> TargetPath'
               -> FilePath
               -> IO (Maybe (BS.L.ByteString, Tar.FileSize))
tarExtractFile opts repoLoc pathTarGz pathToExtract =
     handle (throwIO . TarGzError (prettyTargetPath' opts pathTarGz)) $ do
       let pathTarGz' = anchorTargetPath' opts repoLoc pathTarGz
       go =<< Tar.read . GZip.decompress <$> readLazyByteString pathTarGz'
  where
    go :: Exception e => Tar.Entries e -> IO (Maybe (BS.L.ByteString, Tar.FileSize))
    go Tar.Done        = return Nothing
    go (Tar.Fail err)  = throwIO err
    go (Tar.Next e es) =
      if Tar.entryPath e == pathToExtract
        then case Tar.entryContent e of
               Tar.NormalFile bs sz -> return $ Just (bs, sz)
               _ -> throwIO $ userError
                            $ "tarExtractFile: "
                           ++ pathToExtract ++ " not a normal file"
        else do -- putStrLn $ show (Tar.entryPath e) ++ " /= " ++ show path
                go es

data TarGzError = TarGzError FilePath SomeException
  deriving (Typeable)

instance Exception TarGzError where
#if MIN_VERSION_base(4,8,0)
  displayException (TarGzError path e) = path ++ ": " ++ displayException e

deriving instance Show TarGzError
#else
instance Show TarGzError where
  show (TarGzError path e) = path ++ ": " ++ show e
#endif
