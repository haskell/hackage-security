module System.FileLock.Internal.LockFileEx
#ifndef USE_LOCKFILEEX
  () where
#else
  (Lock, lock, tryLock, unlock) where

#include <windows.h>

import Control.Applicative
import qualified Control.Exception as E
import Data.Bits
import Foreign.Marshal.Alloc
import System.Win32.File
import System.Win32.Mem
import System.Win32.Types

type Lock = HANDLE

lock :: FilePath -> Bool -> IO Lock
lock path exclusive = do
  file <- open path
  (`E.onException` closeHandle file) $ do
    True <- lockFirstByte file exclusive True
    return file

tryLock :: FilePath -> Bool -> IO (Maybe Lock)
tryLock path exclusive = do
  file <- open path
  (`E.onException` closeHandle file) $ do
    r <- lockFirstByte file exclusive False
    if r
      then return $ Just file
      else Nothing <$ closeHandle file

unlock :: Lock -> IO ()
unlock = closeHandle

open :: FilePath -> IO HANDLE
open path =
  createFile path gENERIC_WRITE (fILE_SHARE_READ .|. fILE_SHARE_WRITE)
    Nothing oPEN_ALWAYS fILE_ATTRIBUTE_NORMAL Nothing

lockFirstByte :: HANDLE -> Bool -> Bool -> IO Bool
lockFirstByte handle exclusive block
    = allocaBytes sizeof_OVERLAPPED $ \op -> do
  zeroMemory op $ fromIntegral sizeof_OVERLAPPED
  -- Offset and OffsetHigh fields are set to 0 by zeroMemory.
  r <- c_lockFileEx handle (exFlag .|. blockFlag) 0{-reserved-}
    1{-number of bytes, lower dword-}
    0{-number of bytes, higher dword-}
    op
  if r
    then return True -- success
    else do
      code <- getLastError
      if code == #{const ERROR_LOCK_VIOLATION}
        then return False -- already taken
        else failWith "LockFileEx" code
  where
    exFlag = if exclusive then #{const LOCKFILE_EXCLUSIVE_LOCK} else 0
    blockFlag = if block then 0 else #{const LOCKFILE_FAIL_IMMEDIATELY}
    sizeof_OVERLAPPED = #{size OVERLAPPED}

foreign import stdcall "LockFileEx" c_lockFileEx
  :: HANDLE -> DWORD -> DWORD -> DWORD -> DWORD -> LPOVERLAPPED -> IO BOOL

#endif /* USE_LOCKFILEEX */
