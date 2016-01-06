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

-- | Attempt to create a filesystem lock in the specified directory
--
-- Given a file @/path/to@, we do this by attempting to create the directory
-- @//path/to/hackage-security-lock@, and deleting the directory again
-- afterwards. Creating a directory that already exists will throw an exception
-- on most OSs (certainly Linux, OSX and Windows) and is a reasonably common way
-- to implement a lock file.
withDirLock :: Path Absolute -> IO a -> IO a
withDirLock dir = bracket_ takeLock releaseLock
  where
    lock :: Path Absolute
    lock = dir </> fragment "hackage-security-lock"

    takeLock, releaseLock :: IO ()
    takeLock    = createDirectory lock
    releaseLock = removeDirectory lock

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
