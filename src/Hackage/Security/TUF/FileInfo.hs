-- | Information about files
module Hackage.Security.TUF.FileInfo (
    FileInfo(..)
  , HashFn(..)
  , Hash(..)
    -- * Utility
  , fileInfo
  , fileInfoJSON
  , fileInfoTargetFile
  , verifyFileInfo
  ) where

import Prelude hiding (lookup)
import Data.Map (Map)
import Data.Digest.Pure.SHA
import qualified Data.Map             as Map
import qualified Data.ByteString.Lazy as BS.L

import Hackage.Security.JSON
import Hackage.Security.Key.ExplicitSharing (renderJSON)
import Hackage.Security.Trusted.Unsafe
import Hackage.Security.TUF.Common

{-------------------------------------------------------------------------------
  Datatypes
-------------------------------------------------------------------------------}

data HashFn = HashFnSHA256
  deriving (Show, Eq, Ord)

data FileInfo = FileInfo {
    fileInfoLength :: FileLength
  , fileInfoHashes :: Map HashFn Hash
  }
  deriving (Eq, Ord, Show)

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

-- | Compute 'FileInfo' over target files on disk
--
-- NOTE: This should not be used on metadata files (for which we additionally
-- need to compute the canonical JSON form first).
--
-- TODO: When we call this on the index tarball it will load the entirely
-- index into memory. We should probably address that (but the way we address
-- it will depend on the package that we use to compute hashes, which might
-- still change).
fileInfoTargetFile :: FilePath -> IO FileInfo
fileInfoTargetFile fp = fileInfo <$> BS.L.readFile fp

-- | Compare reported (trusted) file info with computed file info.
verifyFileInfo :: Trusted FileInfo -> FileInfo -> Bool
verifyFileInfo info info' = trusted info == info'

{-------------------------------------------------------------------------------
  JSON
-------------------------------------------------------------------------------}

instance ToObjectKey HashFn where
  toObjectKey HashFnSHA256 = "sha256"

instance ReportSchemaErrors m => FromObjectKey m HashFn where
  fromObjectKey "sha256"   = return HashFnSHA256
  fromObjectKey _otherwise = expected "valid hash function"

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
