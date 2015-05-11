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
import Hackage.Security.Trusted.Unsafe
import Hackage.Security.TUF.FileInfo

{-------------------------------------------------------------------------------
  Datatypes
-------------------------------------------------------------------------------}

newtype FileMap = FileMap { fileMap :: Map FilePath FileInfo }

{-------------------------------------------------------------------------------
  Standard accessors
-------------------------------------------------------------------------------}

empty :: FileMap
empty = FileMap Map.empty

lookup :: FilePath -> FileMap -> Maybe FileInfo
lookup fp = Map.lookup fp . fileMap

(!) :: FileMap -> FilePath -> FileInfo
fm ! fp = fileMap fm Map.! fp

insert :: FilePath -> FileInfo -> FileMap -> FileMap
insert fp nfo = FileMap . Map.insert fp nfo . fileMap

fromList :: [(FilePath, FileInfo)] -> FileMap
fromList = FileMap . Map.fromList

{-------------------------------------------------------------------------------
  Convenience accessors
-------------------------------------------------------------------------------}

lookupM :: Monad m => FileMap -> FilePath -> m FileInfo
lookupM m fp =
    case lookup fp m of
      Nothing  -> fail $ "Could not find entry for " ++ show fp ++ " in filemap"
      Just nfo -> return nfo

{-------------------------------------------------------------------------------
  Comparing filemaps
-------------------------------------------------------------------------------}

data FileChange =
    -- | File got added or modified; we record the new file info
    FileChanged (Trusted FileInfo)

    -- | File got deleted
  | FileDeleted
  deriving (Eq, Ord, Show)

fileMapChanges :: Trusted FileMap  -- ^ Old
               -> Trusted FileMap  -- ^ New
               -> Map FilePath FileChange
fileMapChanges (trusted -> FileMap a) (trusted -> FileMap b) =
    Map.fromList $ go (Map.toList a) (Map.toList b)
  where
    -- Assumes the old and new lists are sorted alphabetically
    -- (Map.toList guarantees this)
    go :: [(FilePath, FileInfo)]
       -> [(FilePath, FileInfo)]
       -> [(FilePath, FileChange)]
    go [] new = map (second fileChanged) new
    go old [] = map (second (const FileDeleted)) old
    go old@((fp, nfo):old') new@((fp', nfo'):new')
      | fp < fp'    = (fp , FileDeleted     ) : go old' new
      | fp > fp'    = (fp', fileChanged nfo') : go old  new'
      | nfo /= nfo' = (fp , fileChanged nfo') : go old' new'
      | otherwise   = go old' new'

    -- DeclareTrusted okay because FileInfo from Trusted FileMaps
    fileChanged = FileChanged . DeclareTrusted

{-------------------------------------------------------------------------------
  JSON
-------------------------------------------------------------------------------}

instance ToJSON FileMap where
  toJSON (FileMap metaFiles) = toJSON metaFiles

instance ReportSchemaErrors m => FromJSON m FileMap where
  fromJSON enc = FileMap <$> fromJSON enc
