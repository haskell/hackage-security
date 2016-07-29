-- | Information about files
module Hackage.Security.TUF.FileInfo (
    FileInfo(..)
  , HashFn(..)
  , Hash(..)
    -- * Utility
  , fileInfo
  , computeFileInfo
  , compareTrustedFileInfo
  , knownFileInfoEqual
  , fileInfoSHA256
    -- ** Re-exports
  , Int54
  ) where

import Prelude hiding (lookup)
import Data.Map (Map)
import qualified Crypto.Hash.SHA256   as SHA256
import qualified Data.Map             as Map
import qualified Data.ByteString.Base16 as Base16
import qualified Data.ByteString.Lazy as BS.L
import qualified Data.ByteString.Char8 as BS.C8

import Hackage.Security.JSON
import Hackage.Security.TUF.Common
import Hackage.Security.Util.Path

{-------------------------------------------------------------------------------
  Datatypes
-------------------------------------------------------------------------------}

data HashFn = HashFnSHA256
            | HashFnMD5
  deriving (Show, Eq, Ord)

-- | File information
--
-- This intentionally does not have an 'Eq' instance; see 'knownFileInfoEqual'
-- and 'verifyFileInfo' instead.
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
  deriving (Show)

{-------------------------------------------------------------------------------
  Utility
-------------------------------------------------------------------------------}

-- | Compute 'FileInfo'
--
-- TODO: Currently this will load the entire input bytestring into memory.
-- We need to make this incremental, by computing the length and all hashes
-- in a single traversal over the input.
fileInfo :: BS.L.ByteString -> FileInfo
fileInfo bs = FileInfo {
      fileInfoLength = FileLength . fromIntegral $ BS.L.length bs
    , fileInfoHashes = Map.fromList [
          -- Note: if you add or change hash functions here and you want to
          -- make them compulsory then you also need to update
          -- 'compareTrustedFileInfo' below.
          (HashFnSHA256, Hash $ BS.C8.unpack $ Base16.encode $ SHA256.hashlazy bs)
        ]
    }

-- | Compute 'FileInfo'
computeFileInfo :: FsRoot root => Path root -> IO FileInfo
computeFileInfo fp = fileInfo <$> readLazyByteString fp

-- | Compare the expected trusted file info against the actual file info of a
-- target file.
--
-- This should be used only when the 'FileInfo' is already known. If we want
-- to compare known 'FileInfo' against a file on disk we should delay until we
-- have confirmed that the file lengths match (see 'downloadedVerify').
--
compareTrustedFileInfo :: FileInfo -- ^ expected (from trusted TUF files)
                       -> FileInfo -- ^ actual (from 'fileInfo' on target file)
                       -> Bool
compareTrustedFileInfo expectedInfo actualInfo =
    -- The expected trusted file info may have hashes for several hash
    -- functions, including ones we do not care about and do not want to
    -- check. In particular the file info may have an md5 hash, but this
    -- is not one that we want to check.
    --
    -- Our current policy is to check sha256 only and ignore md5:
    sameLength expectedInfo actualInfo
 && sameSHA256 expectedInfo actualInfo
  where
    sameLength a b = fileInfoLength a
                  == fileInfoLength b

    sameSHA256 a b = case (fileInfoSHA256 a,
                           fileInfoSHA256 b) of
                       (Just ha, Just hb) -> ha == hb
                       _                  -> False

knownFileInfoEqual :: FileInfo -> FileInfo -> Bool
knownFileInfoEqual a b = (==) (fileInfoLength a, fileInfoHashes a)
                              (fileInfoLength b, fileInfoHashes b)

-- | Extract SHA256 hash from 'FileInfo' (if present)
fileInfoSHA256 :: FileInfo -> Maybe Hash
fileInfoSHA256 FileInfo{..} = Map.lookup HashFnSHA256 fileInfoHashes

{-------------------------------------------------------------------------------
  JSON
-------------------------------------------------------------------------------}

instance Monad m => ToObjectKey m HashFn where
  toObjectKey HashFnSHA256 = return "sha256"
  toObjectKey HashFnMD5    = return "md5"

instance ReportSchemaErrors m => FromObjectKey m HashFn where
  fromObjectKey "sha256" = return (Just HashFnSHA256)
  fromObjectKey "md5"    = return (Just HashFnMD5)
  fromObjectKey _        = return Nothing

instance Monad m => ToJSON m FileInfo where
  toJSON FileInfo{..} = mkObject [
        ("length", toJSON fileInfoLength)
      , ("hashes", toJSON fileInfoHashes)
      ]

instance ReportSchemaErrors m => FromJSON m FileInfo where
  fromJSON enc = do
    fileInfoLength <- fromJSField enc "length"
    fileInfoHashes <- fromJSField enc "hashes"
    return FileInfo{..}
