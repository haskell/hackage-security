-- | Header used by all TUF types
module Hackage.Security.TUF.Header (
    TUFHeader(..)
  , FileVersion  -- opaque
  , FileExpires  -- opaque
    -- ** Utility
  , expiresInDays
  , isExpired
  , versionInitial
  , versionIncrement
  ) where

import Data.Time

import Hackage.Security.JSON

{-------------------------------------------------------------------------------
  TUF header
-------------------------------------------------------------------------------}

class TUFHeader a where
  -- | File expiry date
  fileExpires :: a -> Maybe FileExpires

  -- | File version (monotonically increasing counter)
  fileVersion :: a -> FileVersion

  -- | Describe this file (for use in error messages)
  describeFile :: a -> String

-- | File version
--
-- The file version is a flat integer which must monotonically increase on
-- every file update.
newtype FileVersion = FileVersion Int
  deriving (Eq, Ord, Show)

-- | File expiry date
newtype FileExpires = FileExpires UTCTime
  deriving (Eq, Ord, Show)

{-------------------------------------------------------------------------------
  Utility
-------------------------------------------------------------------------------}

expiresInDays :: UTCTime -> Integer -> FileExpires
expiresInDays now n = FileExpires $ addUTCTime (fromInteger n * oneDay) now

isExpired :: UTCTime -> FileExpires -> Bool
isExpired now (FileExpires e) = e < now

versionInitial :: FileVersion
versionInitial = FileVersion 1

versionIncrement :: FileVersion -> FileVersion
versionIncrement (FileVersion i) = FileVersion (i + 1)

{-------------------------------------------------------------------------------
  JSON
-------------------------------------------------------------------------------}

instance ToJSON FileVersion where
  toJSON (FileVersion i) = toJSON i

instance ToJSON FileExpires where
  toJSON (FileExpires str) = toJSON str

instance ReportSchemaErrors m => FromJSON m FileVersion where
  fromJSON enc = FileVersion <$> fromJSON enc

instance ReportSchemaErrors m => FromJSON m FileExpires where
  fromJSON enc = FileExpires <$> fromJSON enc

{-------------------------------------------------------------------------------
  Auxiliary
-------------------------------------------------------------------------------}

oneDay :: NominalDiffTime
oneDay = 24 * 60 * 60
