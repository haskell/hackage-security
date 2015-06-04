-- | Simple type wrappers
module Hackage.Security.TUF.Common (
    -- * Types
    FileLength(..)
  , Hash(..)
  , KeyThreshold(..)
    -- ** Trusted info
  , trustedFileLength
  ) where

import Hackage.Security.JSON
import Hackage.Security.Trusted

{-------------------------------------------------------------------------------
  Simple types
-------------------------------------------------------------------------------}

-- | File length
--
-- Having verified file length information means we can protect against
-- endless data attacks and similar.
newtype FileLength = FileLength Int
  deriving (Eq, Ord, Show)

-- | Key threshold
--
-- The key threshold is the minimum number of keys a document must be signed
-- with. Key thresholds are specified in 'RoleSpec' or 'DelegationsSpec'.
newtype KeyThreshold = KeyThreshold Int
  deriving (Eq, Ord, Show)

-- | File hash
newtype Hash = Hash String
  deriving (Eq, Ord, Show)

{-------------------------------------------------------------------------------
  Extracting trusted information
-------------------------------------------------------------------------------}

trustedFileLength :: Trusted FileLength -> Int
trustedFileLength (trusted -> FileLength n) = n

{-------------------------------------------------------------------------------
  JSON
-------------------------------------------------------------------------------}

instance ToJSON KeyThreshold where
  toJSON (KeyThreshold i) = toJSON i

instance ToJSON FileLength where
  toJSON (FileLength i) = toJSON i

instance ToJSON Hash where
  toJSON (Hash str) = toJSON str

instance ReportSchemaErrors m => FromJSON m KeyThreshold where
  fromJSON enc = KeyThreshold <$> fromJSON enc

instance ReportSchemaErrors m => FromJSON m FileLength where
  fromJSON enc = FileLength <$> fromJSON enc

instance ReportSchemaErrors m => FromJSON m Hash where
  fromJSON enc = Hash <$> fromJSON enc
