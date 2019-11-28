module Hackage.Security.Util.IO (
    -- * Miscelleneous
    getFileSize
  , handleDoesNotExist
    -- * Debugging
  , timedIO
  ) where

import Control.Exception (handle, throwIO)
import Data.Time (getCurrentTime, diffUTCTime)
import System.IO (hPutStrLn, stderr, hFlush)
import System.IO.Error (isDoesNotExistError)

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
