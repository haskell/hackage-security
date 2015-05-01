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
    -- * Standard accessors
  , empty
  , lookup
  , insert
  , fromList
    -- * Utility
  , fileInfo
  , fileInfoJSON
  ) where

import Prelude hiding (lookup)
import Data.Map (Map)
import Data.Digest.Pure.SHA
import qualified Data.Map             as Map
import qualified Data.ByteString.Lazy as BS.L

import Hackage.Security.JSON
import Hackage.Security.TUF.Ints

{-------------------------------------------------------------------------------
  Datatypes
-------------------------------------------------------------------------------}

data HashFn = HashFnSHA256
  deriving (Show, Eq, Ord)

newtype FileMap = FileMap { fileMap :: Map FilePath FileInfo }

data FileInfo = FileInfo {
    fileInfoLength :: Length
  , fileInfoHashes :: Map HashFn String
  }

{-------------------------------------------------------------------------------
  Standard accessors
-------------------------------------------------------------------------------}

empty :: FileMap
empty = FileMap Map.empty

lookup :: FilePath -> FileMap -> Maybe FileInfo
lookup fp = Map.lookup fp . fileMap

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
      fileInfoLength = Length . fromIntegral $ BS.L.length bs
    , fileInfoHashes = Map.fromList [
          (HashFnSHA256, showDigest (sha256 bs))
        ]
    }

-- | Compute 'FileInfo' over the canonical JSON form
fileInfoJSON :: ToJSON a => a -> FileInfo
fileInfoJSON = fileInfo . fst . renderJSON

{-------------------------------------------------------------------------------
  JSON
-------------------------------------------------------------------------------}

instance ToObjectKey HashFn where
  toObjectKey HashFnSHA256 = "sha256"

instance FromObjectKey HashFn where
  fromObjectKey "sha256"   = return HashFnSHA256
  fromObjectKey _otherwise = expected "valid hash function"

instance ToJSON FileMap where
  toJSON (FileMap metaFiles) = toJSON metaFiles

instance FromJSON FileMap where
  fromJSON enc = FileMap <$> fromJSON enc

instance ToJSON FileInfo where
  toJSON FileInfo{..} = do
    fileInfoLength' <- toJSON fileInfoLength
    fileInfoHashes' <- toJSON fileInfoHashes
    return $ JSObject [
        ("length", fileInfoLength')
      , ("hashes", fileInfoHashes')
      ]

instance FromJSON FileInfo where
  fromJSON enc = do
    fileInfoLength <- fromJSField enc "length"
    fileInfoHashes <- fromJSField enc "hashes"
    return FileInfo{..}
