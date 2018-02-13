{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE CPP #-}

-- | This module provides a portable interface to file locks as a mechanism for
-- inter-process synchronization.
--
-- Each file lock is associated with a file. When taking a lock, the assiciated
-- file is created if it's not present, then the file is locked in an
-- OS-dependent way. While the lock is being held, no other process or
-- thread can take it, unless the specified 'SharedExclusive' values
-- allow it.
--
-- All locks held by a process are released when the process exits. They can
-- also be explicitly released using 'unlockFile'.
--
-- It is not recommended to open or otherwise use lock files for other
-- purposes, because it tends to expose differences between operating systems.
-- For example, on Windows 'System.IO.openFile' for a lock file will fail when
-- the lock is held, but on Unix it won't.
--
-- Note on the implementation: currently the module uses flock(2) on non-Windows
-- platforms, and LockFileEx on Windows.
module System.FileLock
  ( FileLock
  , SharedExclusive(..)
  , lockFile
  , tryLockFile
  , unlockFile
  , withFileLock
  , withTryFileLock
  ) where

import Control.Applicative
import qualified Control.Exception as E
import Control.Monad
import Data.IORef
import Data.Traversable (traverse)
import Data.Typeable
import Prelude

#ifdef USE_FLOCK
import qualified System.FileLock.Internal.Flock as I
#elif USE_LOCKFILEEX
import qualified System.FileLock.Internal.LockFileEx as I
#else
#error No backend is available
#endif

-- | A token that represents ownership of a lock.
data FileLock = Lock
  {-# UNPACk #-} !I.Lock
  {-# UNPACk #-} !(IORef Bool) -- alive?
  deriving (Typeable)

instance Eq FileLock where
  Lock _ x == Lock _ y = x == y

newLock :: I.Lock -> IO FileLock
newLock x = Lock x <$> newIORef True

-- | A type of lock to be taken.
data SharedExclusive
  = Shared -- ^ Other process can hold a shared lock at the same time.
  | Exclusive -- ^ No other process can hold a lock, shared or exclusive.
  deriving (Show, Eq, Typeable)

-- | Take a lock. This function blocks until the lock is available.
lockFile :: FilePath -> SharedExclusive -> IO FileLock
lockFile path mode = newLock =<< I.lock path (mode == Exclusive)

-- | Try to take a lock. This function does not block. If the lock is not
-- immediately available, it returns Nothing.
tryLockFile :: FilePath -> SharedExclusive -> IO (Maybe FileLock)
tryLockFile path mode = traverse newLock =<< I.tryLock path (mode == Exclusive)

-- | Release the lock.
unlockFile :: FileLock -> IO ()
unlockFile (Lock l ref) = do
  wasAlive <- atomicModifyIORef ref $ \old -> (False, old)
  when wasAlive $ I.unlock l

-- | Perform some action with a lock held. Blocks until the lock is available.
withFileLock :: FilePath -> SharedExclusive -> (FileLock -> IO a) -> IO a
withFileLock path mode = E.bracket (lockFile path mode) unlockFile

-- | Perform sme action with a lock held. Non-blocking.
withTryFileLock :: FilePath -> SharedExclusive -> (FileLock -> IO a) -> IO (Maybe a)
withTryFileLock path mode f = E.bracket (tryLockFile path mode) (traverse unlockFile) (traverse f)
