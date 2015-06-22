-- | Information about files
--
-- Intended to be double imported
--
-- > import Hackage.Security.TUF.FileMap (FileMap)
-- > import qualified Hackage.Security.TUF.FileMap as FileMap
module Hackage.Security.TUF.FileMap (
    FileMap -- opaque
    -- * Standard accessors
  , empty
  , lookup
  , (!)
  , insert
  , fromList
    -- * Convenience accessors
  , lookupM
    -- * Comparing file maps
  , FileChange(..)
  , fileMapChanges
  ) where

import Prelude hiding (lookup)
import Control.Arrow (second)
import Data.Map (Map)
import qualified Data.Map as Map

import Hackage.Security.JSON
import Hackage.Security.TUF.FileInfo
import Hackage.Security.Util.Path

{-------------------------------------------------------------------------------
  Datatypes
-------------------------------------------------------------------------------}

-- | Mapping from paths to file info
--
-- File maps are used in target files; the paths are relative to the location
-- of the target files containing the file map.
newtype FileMap = FileMap { fileMap :: Map RelativePath FileInfo }

{-------------------------------------------------------------------------------
  Standard accessors
-------------------------------------------------------------------------------}

empty :: FileMap
empty = FileMap Map.empty

lookup :: RelativePath -> FileMap -> Maybe FileInfo
lookup fp = Map.lookup fp . fileMap

(!) :: FileMap -> RelativePath -> FileInfo
fm ! fp = fileMap fm Map.! fp

insert :: RelativePath -> FileInfo -> FileMap -> FileMap
insert fp nfo = FileMap . Map.insert fp nfo . fileMap

fromList :: [(RelativePath, FileInfo)] -> FileMap
fromList = FileMap . Map.fromList

{-------------------------------------------------------------------------------
  Convenience accessors
-------------------------------------------------------------------------------}

lookupM :: Monad m => FileMap -> RelativePath -> m FileInfo
lookupM m fp =
    case lookup fp m of
      Nothing  -> fail $ "Could not find entry for " ++ show fp ++ " in filemap"
      Just nfo -> return nfo

{-------------------------------------------------------------------------------
  Comparing filemaps
-------------------------------------------------------------------------------}

data FileChange =
    -- | File got added or modified; we record the new file info
    FileChanged FileInfo

    -- | File got deleted
  | FileDeleted
  deriving (Eq, Ord, Show)

fileMapChanges :: FileMap  -- ^ Old
               -> FileMap  -- ^ New
               -> Map RelativePath FileChange
fileMapChanges (FileMap a) (FileMap b) =
    Map.fromList $ go (Map.toList a) (Map.toList b)
  where
    -- Assumes the old and new lists are sorted alphabetically
    -- (Map.toList guarantees this)
    go :: [(RelativePath, FileInfo)]
       -> [(RelativePath, FileInfo)]
       -> [(RelativePath, FileChange)]
    go [] new = map (second FileChanged) new
    go old [] = map (second (const FileDeleted)) old
    go old@((fp, nfo):old') new@((fp', nfo'):new')
      | fp < fp'    = (fp , FileDeleted     ) : go old' new
      | fp > fp'    = (fp', FileChanged nfo') : go old  new'
      | nfo /= nfo' = (fp , FileChanged nfo') : go old' new'
      | otherwise   = go old' new'

{-------------------------------------------------------------------------------
  JSON
-------------------------------------------------------------------------------}

instance Monad m => ToJSON m FileMap where
  toJSON (FileMap metaFiles) = toJSON metaFiles

instance ReportSchemaErrors m => FromJSON m FileMap where
  fromJSON enc = FileMap <$> fromJSON enc
