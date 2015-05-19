-- | Server-side funtionality for creating index tarballs
{-# LANGUAGE BangPatterns #-}
module Hackage.Security.Server.IndexTarball (
    appendToTarball
  ) where

import Control.Exception
import System.Directory
import System.IO
import qualified Codec.Archive.Tar       as Tar
import qualified Codec.Archive.Tar.Index as Tar
import qualified Data.ByteString.Lazy    as BS.L

-- | Append (or create) asome files to tarball
appendToTarball :: FilePath -> FilePath -> [FilePath] -> IO ()
appendToTarball tar baseDir newFiles = 
    bracket openOrCreate hClose $ \h -> do
      newEntries <- Tar.pack baseDir newFiles
      BS.L.hPut h $ Tar.write newEntries
  where
    openOrCreate :: IO Handle
    openOrCreate = do
      tarExists <- doesFileExist tar
      if not tarExists
        then openFile tar WriteMode
        else do
          entries <- Tar.read <$> BS.L.readFile tar
          moffset <- evaluate $ findLastEntry entries
          case moffset of
            Left err -> throwIO err
            Right offset -> do
              h <- openFile tar ReadWriteMode -- necessary to be able to seek
              hSeek h AbsoluteSeek (tarEntryOffsetToByteOffset offset)
              return h

-- | Convert a TarEntryOffset to an absolute offset into the file
--
-- TODO: This should really live in the tar package
tarEntryOffsetToByteOffset :: Tar.TarEntryOffset -> Integer
tarEntryOffsetToByteOffset offset = 512 * fromIntegral offset

findLastEntry :: Tar.Entries e -> Either e Tar.TarEntryOffset
findLastEntry = go Tar.emptyIndex
  where
    go !builder (Tar.Next e es) = go (Tar.skipNextEntry e builder) es
    go !builder Tar.Done        = Right $ Tar.nextEntryOffset builder
    go !_       (Tar.Fail err)  = Left err
