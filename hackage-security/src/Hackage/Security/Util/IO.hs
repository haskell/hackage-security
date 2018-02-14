module Hackage.Security.Util.IO (
    -- * Miscelleneous
    getFileSize
  , handleDoesNotExist
  , withDirLock
    -- * Debugging
  , timedIO
  ) where

import Control.Monad (unless)
import Control.Exception
import Data.Time
import System.IO hiding (openTempFile, withFile)
import System.IO.Error

import Hackage.Security.Util.Path
import Hackage.Security.Util.FileLock (hTryLock, LockMode(ExclusiveLock), FileLockingNotSupported)

{-------------------------------------------------------------------------------
  Miscelleneous
-------------------------------------------------------------------------------}

getFileSize :: (Num a, FsRoot root) => Path root -> IO a
getFileSize fp = fromInteger <$> withFile fp ReadMode hFileSize

handleDoesNotExist :: IO a -> IO (Maybe a)
handleDoesNotExist act =
   handle aux (Just <$> act)
  where
    aux e =
      if isDoesNotExistError e
        then return Nothing
        else throwIO e

-- | Attempt to create a filesystem lock in the specified directory.
--
-- This will use OS-specific file locking primitives: "GHC.IO.Handle.Lock" with
-- @base-4.10" and later or a shim for @base@ versions.
--
-- Throws an exception if the lock is already present.
--
-- May fallback to locking via creating a directory:
-- Given a file @/path/to@, we do this by attempting to create the directory
-- @//path/to/hackage-security-lock@, and deleting the directory again
-- afterwards. Creating a directory that already exists will throw an exception
-- on most OSs (certainly Linux, OSX and Windows) and is a reasonably common way
-- to implement a lock file.
withDirLock :: Path Absolute -> IO a -> IO a
withDirLock dir = bracket takeLock releaseLock . const
  where
    lock :: Path Absolute
    lock = dir </> fragment "hackage-security-lock"

    lock' :: FilePath
    lock' = toFilePath lock

    takeLock = do
        h <- openFile lock' ReadWriteMode
        handle (takeDirLock h) $ do
            gotlock <- hTryLock h ExclusiveLock
            unless gotlock $
                fail $ "hTryLock: lock already exists: " ++ lock'
            return (Just h)

    takeDirLock :: Handle -> FileLockingNotSupported -> IO (Maybe Handle)
    takeDirLock h _ = do
        -- We fallback to directory locking
        -- so we need to cleanup lock file first: close and remove
        hClose h
        handle onIOError (removeFile lock)
        createDirectory lock
        return Nothing

    onIOError :: IOError -> IO ()
    onIOError _ = hPutStrLn stderr
        "withDirLock: cannot remove lock file before directory lock fallback"

    releaseLock (Just h) = hClose h
    releaseLock Nothing  = removeDirectory lock

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
