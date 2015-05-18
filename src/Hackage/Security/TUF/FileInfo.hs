-- | Information about files
module Hackage.Security.TUF.FileInfo (
    FileInfo(..)
  , HashFn(..)
  , Hash(..)
    -- * Extracting trusted info
  , trustedFileInfoLength
    -- * Utility
  , fileInfo
  , computeFileInfo
  , verifyFileInfo
  ) where

import Prelude hiding (lookup)
import Data.Map (Map)
import Data.Digest.Pure.SHA
import qualified Data.Map             as Map
import qualified Data.ByteString.Lazy as BS.L

import Hackage.Security.JSON
import Hackage.Security.Trusted.Unsafe
import Hackage.Security.TUF.Common

{-------------------------------------------------------------------------------
  Datatypes
-------------------------------------------------------------------------------}

data HashFn = HashFnSHA256
  deriving (Show, Eq, Ord)

-- | File information
--
-- NOTE: Throughout we compute file information always over the raw bytes.
-- For example, when @timestamp.json@ lists the hash of @snapshot.json@, this
-- hash is computed over the actual @snapshot.json@ file (as opposed to the
-- canonical form of the embedded JSON). This brings it in line with the hash
-- computed over target files, where that is the only choice available.
data FileInfo = FileInfo {
    fileInfoLength :: FileLength
  , fileInfoHashes :: Map HashFn Hash
  }
  deriving (Eq, Ord, Show)

{-------------------------------------------------------------------------------
  Extracting trusted information
-------------------------------------------------------------------------------}

trustedFileInfoLength :: Trusted FileInfo -> Trusted FileLength
trustedFileInfoLength = DeclareTrusted . fileInfoLength . trusted

{-------------------------------------------------------------------------------
  Utility
-------------------------------------------------------------------------------}

-- | Compute 'FileInfo'
--
-- TODO: Currently this will load the entire input bytestring into memory.
-- We need to make this incremental, by computing the length and all hashes
-- in a single traversal over the input. However, the precise way to
-- do that will depend on the hashing package we will use, and we have
-- yet to pick that package.
fileInfo :: BS.L.ByteString -> FileInfo
fileInfo bs = FileInfo {
      fileInfoLength = FileLength . fromIntegral $ BS.L.length bs
    , fileInfoHashes = Map.fromList [
          (HashFnSHA256, Hash $ showDigest (sha256 bs))
        ]
    }

-- | Compute 'FileInfo'
computeFileInfo :: FilePath -> IO FileInfo
computeFileInfo fp = fileInfo <$> BS.L.readFile fp

-- | Verify 'FileInfo'
verifyFileInfo :: FilePath -> Trusted FileInfo -> IO Bool
verifyFileInfo fp info = (== trusted info) <$> computeFileInfo fp

{-------------------------------------------------------------------------------
  JSON
-------------------------------------------------------------------------------}

instance ToObjectKey HashFn where
  toObjectKey HashFnSHA256 = "sha256"

instance ReportSchemaErrors m => FromObjectKey m HashFn where
  fromObjectKey "sha256" = return HashFnSHA256
  fromObjectKey str      = expected "valid hash function" (Just str)

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
