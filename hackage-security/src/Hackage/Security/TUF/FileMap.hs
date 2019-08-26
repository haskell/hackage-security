-- | Information about files
--
-- Intended to be double imported
--
-- > import Hackage.Security.TUF.FileMap (FileMap)
-- > import qualified Hackage.Security.TUF.FileMap as FileMap
module Hackage.Security.TUF.FileMap (
    FileMap -- opaque
  , TargetPath(..)
    -- * Standard accessors
  , empty
  , lookup
  , (!)
  , insert
  , fromList
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
import Hackage.Security.TUF.Paths
import Hackage.Security.Util.Path
import Hackage.Security.Util.Pretty

{-------------------------------------------------------------------------------
  Datatypes
-------------------------------------------------------------------------------}

-- | Mapping from paths to file info
--
-- File maps are used in target files; the paths are relative to the location
-- of the target files containing the file map.
newtype FileMap = FileMap { fileMap :: Map TargetPath FileInfo }
  deriving (Show)

-- | Entries in 'FileMap' either talk about the repository or the index
data TargetPath =
    TargetPathRepo  RepoPath
  | TargetPathIndex IndexPath
  deriving (Show, Eq, Ord)

instance Pretty TargetPath where
  pretty (TargetPathRepo  path) = pretty path
  pretty (TargetPathIndex path) = pretty path

{-------------------------------------------------------------------------------
  Standard accessors
-------------------------------------------------------------------------------}

empty :: FileMap
empty = FileMap Map.empty

lookup :: TargetPath -> FileMap -> Maybe FileInfo
lookup fp = Map.lookup fp . fileMap

(!) :: FileMap -> TargetPath -> FileInfo
fm ! fp = fileMap fm Map.! fp

insert :: TargetPath -> FileInfo -> FileMap -> FileMap
insert fp nfo = FileMap . Map.insert fp nfo . fileMap

fromList :: [(TargetPath, FileInfo)] -> FileMap
fromList = FileMap . Map.fromList

{-------------------------------------------------------------------------------
  Comparing filemaps
-------------------------------------------------------------------------------}

data FileChange =
    -- | File got added or modified; we record the new file info
    FileChanged FileInfo

    -- | File got deleted
  | FileDeleted
  deriving (Show)

fileMapChanges :: FileMap  -- ^ Old
               -> FileMap  -- ^ New
               -> Map TargetPath FileChange
fileMapChanges (FileMap a) (FileMap b) =
    Map.fromList $ go (Map.toList a) (Map.toList b)
  where
    -- Assumes the old and new lists are sorted alphabetically
    -- (Map.toList guarantees this)
    go :: [(TargetPath, FileInfo)]
       -> [(TargetPath, FileInfo)]
       -> [(TargetPath, FileChange)]
    go [] new = map (second FileChanged) new
    go old [] = map (second (const FileDeleted)) old
    go old@((fp, nfo):old') new@((fp', nfo'):new')
      | fp < fp'  = (fp , FileDeleted     ) : go old' new
      | fp > fp'  = (fp', FileChanged nfo') : go old  new'
      | knownFileInfoEqual nfo nfo' = (fp , FileChanged nfo') : go old' new'
      | otherwise = go old' new'

{-------------------------------------------------------------------------------
  JSON
-------------------------------------------------------------------------------}

instance Monad m => ToJSON m FileMap where
  toJSON (FileMap metaFiles) = toJSON metaFiles

instance ReportSchemaErrors m => FromJSON m FileMap where
  fromJSON enc = FileMap <$> fromJSON enc

instance Monad m => ToObjectKey m TargetPath where
  toObjectKey = return . pretty

instance ReportSchemaErrors m => FromObjectKey m TargetPath where
  fromObjectKey ('<':'r':'e':'p':'o':'>':'/':path) =
    return . Just . TargetPathRepo  . rootPath . fromUnrootedFilePath $ path
  fromObjectKey ('<':'i':'n':'d':'e':'x':'>':'/':path) =
    return . Just . TargetPathIndex . rootPath . fromUnrootedFilePath $ path
  fromObjectKey _str = return Nothing
