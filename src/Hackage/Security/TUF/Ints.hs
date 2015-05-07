-- | Some simple wrappers around integer values
module Hackage.Security.TUF.Ints (
    FileVersion(..)
  , FileLength(..)
  , KeyThreshold(..)
    -- * Utility
  , incrementFileVersion
  ) where

import Hackage.Security.JSON

{-------------------------------------------------------------------------------
  Simple wrappers
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

instance ReportSchemaErrors m => FromJSON m FileVersion where
  fromJSON enc = FileVersion <$> fromJSON enc

instance ToJSON KeyThreshold where
  toJSON (KeyThreshold i) = toJSON i

instance ReportSchemaErrors m => FromJSON m KeyThreshold where
  fromJSON enc = KeyThreshold <$> fromJSON enc

instance ToJSON FileLength where
  toJSON (FileLength i) = toJSON i

instance ReportSchemaErrors m => FromJSON m FileLength where
  fromJSON enc = FileLength <$> fromJSON enc
