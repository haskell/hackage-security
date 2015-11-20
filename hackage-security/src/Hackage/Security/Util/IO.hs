module Hackage.Security.Util.IO (
    -- * Miscelleneous
    withTempFile
  , getFileSize
  , handleDoesNotExist
    -- * Atomic file operations
  , atomicCopyFile
  , atomicWriteFile
  , atomicWithFile
    -- * Debugging
  , timedIO
  ) where

import Control.Exception
import Control.Monad
import Data.Time
import System.IO hiding (openTempFile)
import System.IO.Error
import qualified Data.ByteString.Lazy as BS.L

import Hackage.Security.Util.Path

{-------------------------------------------------------------------------------
  Miscelleneous
-------------------------------------------------------------------------------}

-- | Create a short-lived temporary file
--
-- Creates the directory where the temp file should live if it does not exist.
withTempFile :: forall a root. IsFileSystemRoot root
             => Path (Rooted root)                -- ^ Temp directory
             -> String                            -- ^ Template
             -> (AbsolutePath -> Handle -> IO a)  -- ^ Callback
             -> IO a
withTempFile tmpDir template callback = do
    createDirectoryIfMissing True tmpDir
    bracket (openTempFile tmpDir template) closeAndDelete (uncurry callback)
  where
    closeAndDelete :: (AbsolutePath, Handle) -> IO ()
    closeAndDelete (fp, h) = do
      hClose h
      void $ handleDoesNotExist $ removeFile fp

getFileSize :: IsFileSystemRoot root => Path (Rooted root) -> IO Integer
getFileSize fp = withFileInReadMode fp hFileSize

handleDoesNotExist :: IO a -> IO (Maybe a)
handleDoesNotExist act =
   handle aux (Just <$> act)
  where
    aux e =
      if isDoesNotExistError e
        then return Nothing
        else throwIO e

{-------------------------------------------------------------------------------
  Atomic file operations
-------------------------------------------------------------------------------}

-- | Copy a file atomically
--
-- If both files live in the same directory, we call 'renameFile'. Otherwise
-- we read the source file and call 'atomicWriteFile' (because only when the
-- two files live in the same directory can be sure that the two locations are
-- on the same physical device).
atomicCopyFile :: AbsolutePath  -- ^ Source
               -> AbsolutePath  -- ^ Destination
               -> IO ()
atomicCopyFile src dst = do
    if takeDirectory src == takeDirectory dst
      then renameFile src dst
      else atomicWriteFile dst =<< readLazyByteString src

-- | Atomically write a bytestring
--
-- We write to a temporary file in the destination folder and then rename.
atomicWriteFile :: AbsolutePath      -- ^ Source
                -> BS.L.ByteString   -- ^ Destination
                -> IO ()
atomicWriteFile dst src = atomicWithFile dst $ \h -> BS.L.hPut h src

-- | Like 'withFile .. WriteMode', but overwrite the destination atomically.
--
-- We open a handle to a temporary file in the same directory as the final
-- location, then call the callback, and only when there are no exceptions
-- finally rename the temporary file to the final destination.
atomicWithFile :: AbsolutePath      -- ^ Final destination
               -> (Handle -> IO a)  -- ^ Callback
               -> IO a
atomicWithFile final callback =
    withTempFile finalDir finalFileName $ \tempPath h -> do
      a <- callback h
      hClose h
      renameFile tempPath final
      return a
  where
    finalDir      = takeDirectory final
    finalFileName = unFragment (takeFileName final)

{-------------------------------------------------------------------------------
  Debugging
-------------------------------------------------------------------------------}

timedIO :: String -> IO a -> IO a
timedIO label act = do
    before <- getCurrentTime
    result <- act
    after  <- getCurrentTime
    hPutStrLn stderr $ label ++ ": " ++ show (after `diffUTCTime` before)
    hFlush stderr
    return result
