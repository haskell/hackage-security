-- | Header used by all TUF types
module Hackage.Security.TUF.Header (
    HasHeader(..)
  , FileVersion(..)
  , FileExpires(..)
  , Header(..)
    -- ** Utility
  , expiresInDays
  , expiresNever
  , isExpired
  , versionInitial
  , versionIncrement
  ) where

import Data.Time
import Data.Typeable (Typeable)

import Hackage.Security.JSON
import Hackage.Security.Util.Lens

{-------------------------------------------------------------------------------
  TUF header
-------------------------------------------------------------------------------}

class HasHeader a where
  -- | File expiry date
  fileExpires :: Lens' a FileExpires

  -- | File version (monotonically increasing counter)
  fileVersion :: Lens' a FileVersion

-- | File version
--
-- The file version is a flat integer which must monotonically increase on
-- every file update.
--
-- 'Show' and 'Read' instance are defined in terms of the underlying 'Int'
-- (this is use for example by hackage during the backup process).
newtype FileVersion = FileVersion Int54
  deriving (Eq, Ord, Typeable)

instance Show FileVersion where
  show (FileVersion v) = show v

instance Read FileVersion where
  readsPrec p = map (\(v, xs) -> (FileVersion v, xs)) . readsPrec p

-- | File expiry date
--
-- A 'Nothing' value here means no expiry. That makes it possible to set some
-- files to never expire. (Note that not having the Maybe in the type here still
-- allows that, because you could set an expiry date 2000 years into the future.
-- By having the Maybe here we avoid the _need_ for such encoding issues.)
newtype FileExpires = FileExpires (Maybe UTCTime)
  deriving (Eq, Ord, Show, Typeable)

-- | Occassionally it is useful to read only a header from a file.
--
-- 'HeaderOnly' intentionally only has a 'FromJSON' instance (no 'ToJSON').
data Header = Header {
    headerExpires :: FileExpires
  , headerVersion :: FileVersion
  }

instance HasHeader Header where
  fileExpires f x = (\y -> x { headerExpires = y }) <$> f (headerExpires x)
  fileVersion f x = (\y -> x { headerVersion = y }) <$> f (headerVersion x)

{-------------------------------------------------------------------------------
  Utility
-------------------------------------------------------------------------------}

expiresNever :: FileExpires
expiresNever = FileExpires Nothing

expiresInDays :: UTCTime -> Integer -> FileExpires
expiresInDays now n =
    FileExpires . Just $ addUTCTime (fromInteger n * oneDay) now

isExpired :: UTCTime -> FileExpires -> Bool
isExpired _   (FileExpires Nothing)  = False
isExpired now (FileExpires (Just e)) = e < now

versionInitial :: FileVersion
versionInitial = FileVersion 1

versionIncrement :: FileVersion -> FileVersion
versionIncrement (FileVersion i) = FileVersion (i + 1)

{-------------------------------------------------------------------------------
  JSON
-------------------------------------------------------------------------------}

instance Monad m => ToJSON m FileVersion where
  toJSON (FileVersion i) = toJSON i

instance Monad m => ToJSON m FileExpires where
  toJSON (FileExpires (Just e)) = toJSON e
  toJSON (FileExpires Nothing)  = return JSNull

instance ReportSchemaErrors m => FromJSON m FileVersion where
  fromJSON enc = FileVersion <$> fromJSON enc

instance ReportSchemaErrors m => FromJSON m FileExpires where
  fromJSON JSNull = return $ FileExpires Nothing
  fromJSON enc    = FileExpires . Just <$> fromJSON enc

instance ReportSchemaErrors m => FromJSON m Header where
  fromJSON enc = do
    headerExpires <- fromJSField enc "expires"
    headerVersion <- fromJSField enc "version"
    return Header{..}

{-------------------------------------------------------------------------------
  Auxiliary
-------------------------------------------------------------------------------}

oneDay :: NominalDiffTime
oneDay = 24 * 60 * 60
