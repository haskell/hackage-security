-- | Thin wrapper around the tar package
module Hackage.Security.Client.IndexTarball (
    -- * Low-level tar utilites
    extractFile
  ) where

import Control.Exception
import Control.Monad.Except
import Data.Maybe
import qualified Codec.Archive.Tar    as Tar
import qualified Data.ByteString.Lazy as BS.L

{-------------------------------------------------------------------------------
  Tar utilities
-------------------------------------------------------------------------------}

-- | Extract a file from a tarball
--
-- Can throw a FormatError exception.
--
-- TODO: support for tarball indices
extractFile :: FilePath   -- ^ Path to the tarball
            -> FilePath   -- ^ File to extract
            -> IO (Maybe BS.L.ByteString)
extractFile tarball entryPath = do
    mEntries <- (entriesToList . Tar.read) <$> BS.L.readFile tarball
    case mEntries of
      Left  err     -> throwIO err
      Right entries -> return $ findEntry entryPath entries

findEntry :: FilePath -> [Tar.Entry] -> Maybe BS.L.ByteString
findEntry entryPath = listToMaybe . mapMaybe match
  where
    match :: Tar.Entry -> Maybe BS.L.ByteString
    match entry = do
      guard (Tar.entryPath entry == entryPath)
      case Tar.entryContent entry of
        Tar.NormalFile bs _size -> Just bs
        _otherwise              -> Nothing

-- TODO: This means we need to load the entire tar file into memory
-- Entries is designed precisely so that we don't need to do that
entriesToList :: forall e. Tar.Entries e -> Either e [Tar.Entry]
entriesToList = runExcept . Tar.foldEntries (liftM . (:)) (return []) throwError
