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

newtype FileMap = FileMap { fileMap :: Map Path FileInfo }

{-------------------------------------------------------------------------------
  Standard accessors
-------------------------------------------------------------------------------}

empty :: FileMap
empty = FileMap Map.empty

lookup :: Path -> FileMap -> Maybe FileInfo
lookup fp = Map.lookup fp . fileMap

(!) :: FileMap -> Path -> FileInfo
fm ! fp = fileMap fm Map.! fp

insert :: Path -> FileInfo -> FileMap -> FileMap
insert fp nfo = FileMap . Map.insert fp nfo . fileMap

fromList :: [(Path, FileInfo)] -> FileMap
fromList = FileMap . Map.fromList

{-------------------------------------------------------------------------------
  Convenience accessors
-------------------------------------------------------------------------------}

lookupM :: Monad m => FileMap -> Path -> m FileInfo
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
               -> Map Path FileChange
fileMapChanges (FileMap a) (FileMap b) =
    Map.fromList $ go (Map.toList a) (Map.toList b)
  where
    -- Assumes the old and new lists are sorted alphabetically
    -- (Map.toList guarantees this)
    go :: [(Path, FileInfo)]
       -> [(Path, FileInfo)]
       -> [(Path, FileChange)]
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

instance ToJSON FileMap where
  toJSON (FileMap metaFiles) = toJSON metaFiles

instance ReportSchemaErrors m => FromJSON m FileMap where
  fromJSON enc = FileMap <$> fromJSON enc
