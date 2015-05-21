module Hackage.Security.Util.IO (
    withSystemTempFile
  , getFileSize
  , ignoreDoesNotExist
  ) where

import Control.Exception
import System.Directory
import System.IO
import System.IO.Error

withSystemTempFile :: String -> (FilePath -> Handle -> IO a) -> IO a
withSystemTempFile template callback = do
    tmpDir <- getTemporaryDirectory
    bracket (openTempFile tmpDir template) closeAndDelete (uncurry callback)
  where
    closeAndDelete :: (FilePath, Handle) -> IO ()
    closeAndDelete (fp, h) = do
      hClose h
      ignoreDoesNotExist $ removeFile fp

getFileSize :: FilePath -> IO Integer
getFileSize fp = withFile fp ReadMode hFileSize

ignoreDoesNotExist :: IO () -> IO ()
ignoreDoesNotExist = handle aux
  where
    aux e =
      if isDoesNotExistError e
        then return ()
        else throwIO e
