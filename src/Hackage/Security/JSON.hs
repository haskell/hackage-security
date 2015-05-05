{-# LANGUAGE OverlappingInstances #-}
{-# LANGUAGE CPP #-}
module Hackage.Security.JSON (
    -- * Type classes
    ToJSON(..)
  , FromJSON(..)
  , ToObjectKey(..)
  , FromObjectKey(..)
  , ReportSchemaErrors(..)
    -- * Utility
  , fromJSObject
  , fromJSField
    -- * Re-exports
  , JSValue(..)
  ) where

import Control.Monad
import Data.Map (Map)
import Data.Time
import Text.JSON.Canonical
import qualified Data.Map as Map

#if !MIN_VERSION_base(4,6,0)
import System.Locale
#endif

{-------------------------------------------------------------------------------
  ToJSON and FromJSON classes

  We parameterize over the monad here to avoid mutual module dependencies.
-------------------------------------------------------------------------------}

class ToJSON m a where
  toJSON :: a -> m JSValue

class FromJSON m a where
  fromJSON :: JSValue -> m a

-- | Used in the 'ToJSON' instance for 'Map'
class ToObjectKey m a where
  toObjectKey :: a -> m String

-- | Used in the 'FromJSON' instance for 'Map'
class FromObjectKey m a where
  fromObjectKey :: String -> m a

-- | Monads in which we can report schema errors
class (Applicative m, Monad m) => ReportSchemaErrors m where
  expected :: String -> m a

{-------------------------------------------------------------------------------
  ToObjectKey and FromObjectKey instances
-------------------------------------------------------------------------------}

instance Monad m => ToObjectKey m String where
  toObjectKey = return

instance Monad m => FromObjectKey m String where
  fromObjectKey = return

{-------------------------------------------------------------------------------
  ToJSON and FromJSON instances
-------------------------------------------------------------------------------}

instance Monad m => ToJSON m JSValue where
  toJSON = return

instance Monad m => FromJSON m JSValue where
  fromJSON = return

instance Monad m => ToJSON m String where
  toJSON = return . JSString

instance ReportSchemaErrors m => FromJSON m String where
  fromJSON (JSString str) = return str
  fromJSON _              = expected "string"

instance Monad m => ToJSON m Int where
  toJSON = return . JSNum

instance ReportSchemaErrors m => FromJSON m Int where
  fromJSON (JSNum i) = return i
  fromJSON _         = expected "int"

instance (Monad m, ToJSON m a) => ToJSON m [a] where
  toJSON = liftM JSArray . mapM toJSON

instance (ReportSchemaErrors m, FromJSON m a) => FromJSON m [a] where
  fromJSON (JSArray as) = mapM fromJSON as
  fromJSON _            = expected "array"

instance Monad m => ToJSON m UTCTime where
  toJSON = return . JSString . formatTime defaultTimeLocale "%FT%TZ"

instance ReportSchemaErrors m => FromJSON m UTCTime where
  fromJSON enc = do
    str <- fromJSON enc
    case parseTimeM False defaultTimeLocale "%FT%TZ" str of
      Just time -> return time
      Nothing   -> expected "valid date-time string"
#if !MIN_VERSION_base(4,6,0)
    where
      parseTimeM _trim = parseTime
#endif

instance ( Monad m
         , ToObjectKey m k
         , ToJSON m a
         ) => ToJSON m (Map k a) where
  toJSON = liftM JSObject . mapM aux . Map.toList
    where
      aux :: (k, a) -> m (String, JSValue)
      aux (k, a) = liftM2 (,) (toObjectKey k) (toJSON a)

instance ( ReportSchemaErrors m
         , Ord k
         , FromObjectKey m k
         , FromJSON m a
         ) => FromJSON m (Map k a) where
  fromJSON enc = do
      obj <- fromJSObject enc
      Map.fromList <$> mapM aux obj
    where
      aux :: (String, JSValue) -> m (k, a)
      aux (k, a) = (,) <$> fromObjectKey k <*> fromJSON a

{-------------------------------------------------------------------------------
  Utility
-------------------------------------------------------------------------------}

fromJSObject :: ReportSchemaErrors m => JSValue -> m [(String, JSValue)]
fromJSObject (JSObject obj) = return obj
fromJSObject _              = expected "object"

-- | Extract a field from a JSON object
fromJSField :: (ReportSchemaErrors m, FromJSON m a) => JSValue -> String -> m a
fromJSField val nm = do
    obj <- fromJSObject val
    case lookup nm obj of
      Just fld -> fromJSON fld
      Nothing  -> expected $ "field " ++ show nm
