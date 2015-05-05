-- | Some simple wrappers around integer values
module Hackage.Security.TUF.Ints (
    Version(..)
  , KeyThreshold(..)
  , Length(..)
    -- * Utility
  , incrementVersion
  ) where

import Hackage.Security.JSON

{-------------------------------------------------------------------------------
  Simple wrappers
-------------------------------------------------------------------------------}

newtype Version      = Version Int      deriving (Eq, Ord)
newtype KeyThreshold = KeyThreshold Int deriving (Eq, Ord)
newtype Length       = Length Int       deriving (Eq, Ord)

{-------------------------------------------------------------------------------
  Utility
-------------------------------------------------------------------------------}

incrementVersion :: Version -> Version
incrementVersion (Version i) = Version (i + 1)

{-------------------------------------------------------------------------------
  JSON
-------------------------------------------------------------------------------}

instance Monad m => ToJSON m Version where
  toJSON (Version i) = toJSON i

instance ReportSchemaErrors m => FromJSON m Version where
  fromJSON enc = Version <$> fromJSON enc

instance Monad m => ToJSON m KeyThreshold where
  toJSON (KeyThreshold i) = toJSON i

instance ReportSchemaErrors m => FromJSON m KeyThreshold where
  fromJSON enc = KeyThreshold <$> fromJSON enc

instance Monad m => ToJSON m Length where
  toJSON (Length i) = toJSON i

instance ReportSchemaErrors m => FromJSON m Length where
  fromJSON enc = Length <$> fromJSON enc
