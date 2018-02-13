module System.FileLock.Internal.Flock
#ifndef USE_FLOCK
  () where
#else
  (Lock, lock, tryLock, unlock) where

#include <sys/file.h>

import Control.Applicative
import qualified Control.Exception as E
import Data.Bits
import Foreign.C.Error
import Foreign.C.Types
import System.Posix.Files
import System.Posix.IO (openFd, closeFd, defaultFileFlags, OpenMode(..))
import System.Posix.Types
import Prelude

type Lock = Fd

lock :: FilePath -> Bool -> IO Lock
lock path exclusive = do
  fd <- open path
  (`E.onException` closeFd fd) $ do
    True <- flock fd exclusive True
    return fd

tryLock :: FilePath -> Bool -> IO (Maybe Lock)
tryLock path exclusive = do
  fd <- open path
  (`E.onException` closeFd fd) $ do
    success <- flock fd exclusive False
    if success
      then return $ Just $ fd
      else Nothing <$ closeFd fd

unlock :: Lock -> IO ()
unlock fd = closeFd fd

open :: FilePath -> IO Fd
open path = openFd path WriteOnly (Just stdFileMode) defaultFileFlags

flock :: Fd -> Bool -> Bool -> IO Bool
flock (Fd fd) exclusive block = do
  r <- c_flock fd $ modeOp .|. blockOp
  if r == 0
    then return True -- success
    else do
      errno <- getErrno
      case () of
        _ | errno == eWOULDBLOCK
            -> return False -- already taken
          | errno == eINTR
            -> flock (Fd fd) exclusive block
          | otherwise -> throwErrno "flock"
  where
    modeOp = case exclusive of
      False -> #{const LOCK_SH}
      True -> #{const LOCK_EX}
    blockOp = case block of
      True -> 0
      False -> #{const LOCK_NB}

foreign import ccall "flock"
  c_flock :: CInt -> CInt -> IO CInt

#endif /* USE_FLOCK */
