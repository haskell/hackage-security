module Hackage.Security.Util.IO (
    -- * Miscelleneous
    getFileSize
  , handleDoesNotExist
  , withDirLock
    -- * Debugging
  , timedIO
  ) where

import Control.Exception
import Data.Time
import System.IO hiding (openTempFile, withFile)
import System.IO.Error
import qualified System.FileLock as FL

import Hackage.Security.Util.Path

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
-- This will use OS-specific file locking primitives, and throw an
-- exception if the lock is already present.
withDirLock :: Path Absolute -> IO a -> IO a
withDirLock dir act = do
    res <- FL.withTryFileLock lock FL.Exclusive (const act)
    case res of
        Just a -> return a
        Nothing -> error $ "withFileLock: lock already exists: " ++ lock
  where
    lock :: FilePath
    lock = toFilePath $ dir </> fragment "hackage-security-lock"

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
