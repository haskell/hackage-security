-- | IO utilities
{-# LANGUAGE CPP #-}
module Hackage.Security.Utility.Util.IO (
    -- * Miscellaneous
    compress
  , getFileModTime
  , createSymbolicLink
    -- * Tar archives
  , TarGzError
  , tarExtractFile
  ) where

import Control.Exception
import Data.Typeable
import System.IO.Error
import qualified Codec.Archive.Tar       as Tar
import qualified Codec.Archive.Tar.Entry as Tar
import qualified Codec.Compression.GZip  as GZip
import qualified Data.ByteString.Lazy    as BS.L

-- Unlike the hackage-security library properly,
-- this currently works on unix systems only
import System.Posix.Types (EpochTime)
import qualified System.Posix.Files as Posix

-- hackage-security
import Hackage.Security.Util.Path

-- hackage-security-utility
import Hackage.Security.Utility.Options
import Hackage.Security.Utility.Layout

-- | Get the modification time of the specified file
--
-- Returns 0 if the file does not exist .
getFileModTime :: GlobalOpts -> RepoLoc -> TargetPath' -> IO EpochTime
getFileModTime GlobalOpts{..} repoLoc targetPath =
    handle handler $
      Posix.modificationTime <$> Posix.getFileStatus (toFilePath fp)
  where
    fp :: AbsolutePath
    fp = anchorTargetPath' globalRepoLayout repoLoc targetPath

    handler :: IOException -> IO EpochTime
    handler ex = if isDoesNotExistError ex then return 0
                                           else throwIO ex

compress :: AbsolutePath -> AbsolutePath -> IO ()
compress src dst =
    withFile dst WriteMode $ \h ->
      BS.L.hPut h =<< GZip.compress <$> readLazyByteString src

-- | Create a symbolic link (unix only)
--
-- Create the directory for the target if it does not exist.
--
-- TODO: Currently this always creates links to absolute locations, whether the
-- user specified an absolute or a relative target.
createSymbolicLink :: (IsFileSystemRoot root, IsFileSystemRoot root')
                   => Path (Rooted root)  -- ^ Link target
                   -> Path (Rooted root') -- ^ Link location
                   -> IO ()
createSymbolicLink linkTarget linkLoc = do
    createDirectoryIfMissing True (takeDirectory linkLoc)
    linkTarget' <- toAbsoluteFilePath linkTarget
    linkLoc'    <- toAbsoluteFilePath linkLoc
    Posix.createSymbolicLink linkTarget' linkLoc'

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
tarExtractFile GlobalOpts{..} repoLoc pathTarGz pathToExtract =
     handle (throwIO . TarGzError (prettyTargetPath' globalRepoLayout pathTarGz)) $ do
       let pathTarGz' = anchorTargetPath' globalRepoLayout repoLoc pathTarGz
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
