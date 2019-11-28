{-# LANGUAGE CPP #-}
module Hackage.Security.Util.Lock (
    withDirLock
  ) where

import Control.Concurrent (threadDelay)
import Control.Exception (bracket, handle, onException)
import System.IO.Error (isAlreadyExistsError)

import Hackage.Security.Util.Path

#ifdef MIN_VERSION_lukko
import Lukko (FD, fileLockingSupported, fdOpen, fdClose, fdLock, fdUnlock, LockMode(ExclusiveLock))
#else
import GHC.IO.Handle.Lock (hLock, LockMode(ExclusiveLock), FileLockingNotSupported)
#if MIN_VERSION_base(4,11,0)
import GHC.IO.Handle.Lock (hUnlock)
#endif
#endif

{-------------------------------------------------------------------------------
  Miscelleneous
-------------------------------------------------------------------------------}

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

    me = "Hackage.Security.Util.IO.withDirLock: "

#ifdef MIN_VERSION_lukko
    takeLock :: IO FD
    takeLock
        | fileLockingSupported = do
            h <- fdOpen lock'
            fdLock h ExclusiveLock `onException` fdClose h
            return h
        | otherwise = takeDirLock
      where
        takeDirLock :: IO FD
        takeDirLock = handle onCreateDirError $ do
            createDirectory lock
            return (undefined :: FD)

        onCreateDirError :: IOError -> IO FD
        onCreateDirError ioe
          | isAlreadyExistsError ioe = threadDelay (1*1000*1000) >> takeDirLock
          | otherwise = fail (me++"error creating directory lock: "++show ioe)

    releaseLock h
        | fileLockingSupported = do
            fdUnlock h
            fdClose h
        | otherwise =
            removeDirectory lock

#else
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

    releaseLock (Just h) =
        hClose h
#if MIN_VERSION_base(4,11,0)
        >> hUnlock h
#endif
    releaseLock Nothing  = removeDirectory lock
#endif
