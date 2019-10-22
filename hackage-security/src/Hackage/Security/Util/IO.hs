module Hackage.Security.Util.IO (
    -- * Miscelleneous
    getFileSize
  , handleDoesNotExist
  , withDirLock
    -- * Debugging
  , timedIO
  ) where

import Control.Concurrent (threadDelay)
import Control.Exception
import Data.Time
import System.IO hiding (openTempFile, withFile)
import System.IO.Error

import Hackage.Security.Util.Path
import Hackage.Security.Util.FileLock (hLock, LockMode(ExclusiveLock), FileLockingNotSupported, hUnlock)

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
-- Blocks if the lock is already present.
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
        handle (fallbackToDirLock h) $ do
            hLock h ExclusiveLock
            return (Just h)

    -- If file locking isn't supported then we fallback to directory locking,
    -- polling if necessary.
    fallbackToDirLock :: Handle -> FileLockingNotSupported -> IO (Maybe Handle)
    fallbackToDirLock h _ = takeDirLock >> return Nothing
      where
        takeDirLock :: IO ()
        takeDirLock = do
            -- We fallback to directory locking
            -- so we need to cleanup lock file first: close and remove
            hClose h
            handle onIOError (removeFile lock)
            handle onCreateDirError (createDirectory lock)

        onCreateDirError :: IOError -> IO ()
        onCreateDirError ioe
          | isAlreadyExistsError ioe = threadDelay (1*1000*1000) >> takeDirLock
          | otherwise = fail (me++"error creating directory lock: "++show ioe)

        onIOError :: IOError -> IO ()
        onIOError _ = hPutStrLn stderr
            (me++"cannot remove lock file before directory lock fallback")

    me = "Hackage.Security.Util.IO.withDirLock: "

    releaseLock (Just h) = hUnlock h >> hClose h
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
