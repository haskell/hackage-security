-- | Datatypes common to multiple roles
module Hackage.Security.FileType.Common (
    -- * Simple wrappers
    Version(..)
  , KeyThreshold(..)
  , Length(..)
    -- ** Utility
  , incrementVersion
    -- * Metadata
  , HashFn(..)
  , MetaFiles(..)
  , MetaInfo(..)
  , emptyMetaFiles
  , lookupMetaFile
  , insertMetaFile
  , metaInfo
  , jsonMetaInfo
  ) where

import Data.Map (Map)
import Data.Digest.Pure.SHA
import qualified Data.Map             as Map
import qualified Data.ByteString.Lazy as BS.L

import Hackage.Security.JSON

{-------------------------------------------------------------------------------
  Simple wrappers
-------------------------------------------------------------------------------}

newtype Version      = Version Int       deriving (Eq, Ord)
newtype KeyThreshold = KeyThreshold Int  deriving (Eq, Ord)
newtype Length       = Length Int        deriving (Eq, Ord)

incrementVersion :: Version -> Version
incrementVersion (Version i) = Version (i + 1)

{-------------------------------------------------------------------------------
  JSON
-------------------------------------------------------------------------------}

instance ToJSON Version where
  toJSON (Version i) = toJSON i

instance FromJSON Version where
  fromJSON enc = Version <$> fromJSON enc

instance ToJSON KeyThreshold where
  toJSON (KeyThreshold i) = toJSON i

instance FromJSON KeyThreshold where
  fromJSON enc = KeyThreshold <$> fromJSON enc

instance ToJSON Length where
  toJSON (Length i) = toJSON i

instance FromJSON Length where
  fromJSON enc = Length <$> fromJSON enc

{-------------------------------------------------------------------------------
  Information about metadata

  Used both in the snapshot and the timestamp files
-------------------------------------------------------------------------------}

data HashFn = HashFnSHA256
  deriving (Show, Eq, Ord)

newtype MetaFiles = MetaFiles (Map FilePath MetaInfo)

data MetaInfo = MetaInfo {
    metaInfoLength :: Length
  , metaInfoHashes :: Map HashFn String
  }

emptyMetaFiles :: MetaFiles
emptyMetaFiles = MetaFiles Map.empty

lookupMetaFile :: FilePath -> MetaFiles -> Maybe MetaInfo
lookupMetaFile fp (MetaFiles mp) = Map.lookup fp mp

insertMetaFile :: FilePath -> MetaInfo -> MetaFiles -> MetaFiles
insertMetaFile fp nfo (MetaFiles mp) = MetaFiles (Map.insert fp nfo mp)

{-------------------------------------------------------------------------------
  Computing metadata
-------------------------------------------------------------------------------}

-- | Compute meta info
metaInfo :: BS.L.ByteString -> MetaInfo
metaInfo bs = MetaInfo {
      metaInfoLength = Length . fromIntegral $ BS.L.length bs
    , metaInfoHashes = Map.fromList [
          (HashFnSHA256, showDigest (sha256 bs))
        ]
    }

-- | Compute meta information over the canonical JSON form
jsonMetaInfo :: ToJSON a => a -> MetaInfo
jsonMetaInfo = metaInfo . fst . renderJSON

{-------------------------------------------------------------------------------
  JSON
-------------------------------------------------------------------------------}

instance ToObjectKey HashFn where
  toObjectKey HashFnSHA256 = "sha256"

instance FromObjectKey HashFn where
  fromObjectKey "sha256"   = return HashFnSHA256
  fromObjectKey _otherwise = expected "valid hash function"

instance ToJSON MetaFiles where
  toJSON (MetaFiles metaFiles) = toJSON metaFiles

instance FromJSON MetaFiles where
  fromJSON enc = MetaFiles <$> fromJSON enc

instance ToJSON MetaInfo where
  toJSON MetaInfo{..} = do
    metaInfoLength' <- toJSON metaInfoLength
    metaInfoHashes' <- toJSON metaInfoHashes
    return $ JSObject [
        ("length", metaInfoLength')
      , ("hashes", metaInfoHashes')
      ]

instance FromJSON MetaInfo where
  fromJSON enc = do
    metaInfoLength <- fromJSField enc "length"
    metaInfoHashes <- fromJSField enc "hashes"
    return MetaInfo{..}
