-- | Properties and simple type wrappers common to all top-level TUF types
module Hackage.Security.TUF.Common (
    -- * Classes
    TUFHeader(..)
    -- * Types
  , FileVersion(..)
  , FileExpires(..)
  , FileLength(..)
  , Hash(..)
  , KeyThreshold(..)
    -- ** Utility
  , incrementFileVersion
  ) where

import Data.Time

import Hackage.Security.JSON

{-------------------------------------------------------------------------------
  Type classes
-------------------------------------------------------------------------------}

class TUFHeader a where
  fileExpires :: a -> FileExpires
  fileVersion :: a -> FileVersion

{-------------------------------------------------------------------------------
  Simple types
-------------------------------------------------------------------------------}

-- | File version
--
-- The file version is a flat integer which must monotonically increase on
-- every file update.
newtype FileVersion = FileVersion Int
  deriving (Eq, Ord, Show)

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

-- | File expiry date
newtype FileExpires = FileExpires UTCTime
  deriving (Eq, Ord, Show)

{-------------------------------------------------------------------------------
  Utility
-------------------------------------------------------------------------------}

incrementFileVersion :: FileVersion -> FileVersion
incrementFileVersion (FileVersion i) = FileVersion (i + 1)

{-------------------------------------------------------------------------------
  JSON
-------------------------------------------------------------------------------}

instance ToJSON FileVersion where
  toJSON (FileVersion i) = toJSON i

instance ToJSON KeyThreshold where
  toJSON (KeyThreshold i) = toJSON i

instance ToJSON FileLength where
  toJSON (FileLength i) = toJSON i

instance ToJSON Hash where
  toJSON (Hash str) = toJSON str

instance ToJSON FileExpires where
  toJSON (FileExpires str) = toJSON str

instance ReportSchemaErrors m => FromJSON m FileVersion where
  fromJSON enc = FileVersion <$> fromJSON enc

instance ReportSchemaErrors m => FromJSON m KeyThreshold where
  fromJSON enc = KeyThreshold <$> fromJSON enc

instance ReportSchemaErrors m => FromJSON m FileLength where
  fromJSON enc = FileLength <$> fromJSON enc

instance ReportSchemaErrors m => FromJSON m Hash where
  fromJSON enc = Hash <$> fromJSON enc

instance ReportSchemaErrors m => FromJSON m FileExpires where
  fromJSON enc = FileExpires <$> fromJSON enc
