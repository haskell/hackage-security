-- | Information about files
--
-- Used in the snapshot, timestamp and target files.
--
-- Intended to be double imported
--
-- > import Hackage.Security.TUF.FileMap (FileMap, FileInfo(..), HashFn(..))
-- > import qualified Hackage.Security.TUF.FileMap as FileMap
module Hackage.Security.TUF.FileMap (
    FileMap -- opaque
  , FileInfo(..)
  , HashFn(..)
  , Hash(..)
    -- * Standard accessors
  , empty
  , lookup
  , (!)
  , insert
  , fromList
    -- * Utility
  , fileInfo
  , fileInfoJSON
  , verifyFileInfoJSON
    -- * Comparing file maps
  , FileChange(..)
  , fileMapChanges
  ) where

import Prelude hiding (lookup)
import Data.Map (Map)
import Data.Digest.Pure.SHA
import qualified Data.Map             as Map
import qualified Data.ByteString.Lazy as BS.L

import Hackage.Security.JSON
import Hackage.Security.Key.ExplicitSharing (renderJSON)
import Hackage.Security.Trusted
import Hackage.Security.TUF.Common

{-------------------------------------------------------------------------------
  Datatypes
-------------------------------------------------------------------------------}

data HashFn = HashFnSHA256
  deriving (Show, Eq, Ord)

newtype FileMap = FileMap { fileMap :: Map FilePath FileInfo }

data FileInfo = FileInfo {
    fileInfoLength :: FileLength
  , fileInfoHashes :: Map HashFn Hash
  }
  deriving Eq

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
  Utility
-------------------------------------------------------------------------------}

-- | Compute 'FileInfo'
fileInfo :: BS.L.ByteString -> FileInfo
fileInfo bs = FileInfo {
      fileInfoLength = FileLength . fromIntegral $ BS.L.length bs
    , fileInfoHashes = Map.fromList [
          (HashFnSHA256, Hash $ showDigest (sha256 bs))
        ]
    }

-- | Compute 'FileInfo' over the canonical JSON form
fileInfoJSON :: ToJSON a => a -> FileInfo
fileInfoJSON = fileInfo . renderJSON

verifyFileInfoJSON :: ToJSON a => Trusted FileInfo -> a -> Bool
verifyFileInfoJSON info a = trusted info == fileInfoJSON a

{-------------------------------------------------------------------------------
  Comparing filemaps
-------------------------------------------------------------------------------}

data FileChange =
    FileNew     FilePath
  | FileDeleted FilePath
  | FileChanged FilePath
  deriving (Eq, Ord, Show)

fileMapChanges :: FileMap -> FileMap -> [FileChange]
fileMapChanges (FileMap a) (FileMap b) = go (Map.toList a) (Map.toList b)
  where
    -- Assumes the old and new lists are sorted alphabetically
    -- (Map.toList guarantees this)
    go :: [(FilePath, FileInfo)] -> [(FilePath, FileInfo)] -> [FileChange]
    go [] new = map (FileNew     . fst) new
    go old [] = map (FileDeleted . fst) old
    go old@((fp, nfo):old') new@((fp', nfo'):new')
      | fp < fp'    = FileDeleted fp  : go old' new
      | fp > fp'    = FileNew     fp' : go old  new'
      | nfo /= nfo' = FileChanged fp  : go old' new'
      | otherwise   = go old' new'

{-------------------------------------------------------------------------------
  JSON
-------------------------------------------------------------------------------}

instance ToObjectKey HashFn where
  toObjectKey HashFnSHA256 = "sha256"

instance ReportSchemaErrors m => FromObjectKey m HashFn where
  fromObjectKey "sha256"   = return HashFnSHA256
  fromObjectKey _otherwise = expected "valid hash function"

instance ToJSON FileMap where
  toJSON (FileMap metaFiles) = toJSON metaFiles

instance ReportSchemaErrors m => FromJSON m FileMap where
  fromJSON enc = FileMap <$> fromJSON enc

instance ToJSON FileInfo where
  toJSON FileInfo{..} = JSObject [
        ("length", toJSON fileInfoLength)
      , ("hashes", toJSON fileInfoHashes)
      ]

instance ReportSchemaErrors m => FromJSON m FileInfo where
  fromJSON enc = do
    fileInfoLength <- fromJSField enc "length"
    fileInfoHashes <- fromJSField enc "hashes"
    return FileInfo{..}
