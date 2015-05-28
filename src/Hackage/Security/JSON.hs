{-# LANGUAGE OverlappingInstances #-}
{-# LANGUAGE CPP #-}
module Hackage.Security.JSON (
    -- * Type classes
    ToJSON(..)
  , FromJSON(..)
  , ToObjectKey(..)
  , FromObjectKey(..)
  , ReportSchemaErrors(..)
  , Expected
  , Got
  , expected'
    -- * Utility
  , fromJSObject
  , fromJSField
  , fromJSOptField
    -- * Re-exports
  , JSValue(..)
  ) where

import Data.Map (Map)
import Data.Time
import Text.JSON.Canonical
import Network.URI
import qualified Data.Map as Map

#if !MIN_VERSION_base(4,6,0)
import System.Locale
#endif

{-------------------------------------------------------------------------------
  ToJSON and FromJSON classes

  We parameterize over the monad here to avoid mutual module dependencies.
-------------------------------------------------------------------------------}

class ToJSON a where
  toJSON :: a -> JSValue

class FromJSON m a where
  fromJSON :: JSValue -> m a

-- | Used in the 'ToJSON' instance for 'Map'
class ToObjectKey a where
  toObjectKey :: a -> String

-- | Used in the 'FromJSON' instance for 'Map'
class FromObjectKey m a where
  fromObjectKey :: String -> m a

-- | Monads in which we can report schema errors
class (Applicative m, Monad m) => ReportSchemaErrors m where
  expected :: Expected -> Maybe Got -> m a

type Expected = String
type Got      = String

expected' :: ReportSchemaErrors m => Expected -> JSValue -> m a
expected' descr val = expected descr (Just (describeValue val))
  where
    describeValue :: JSValue -> String
    describeValue (JSNull    ) = "null"
    describeValue (JSBool   _) = "bool"
    describeValue (JSNum    _) = "num"
    describeValue (JSString _) = "string"
    describeValue (JSArray  _) = "array"
    describeValue (JSObject _) = "object"

unknownField :: ReportSchemaErrors m => String -> m a
unknownField field = expected ("field " ++ show field) Nothing

{-------------------------------------------------------------------------------
  ToObjectKey and FromObjectKey instances
-------------------------------------------------------------------------------}

instance ToObjectKey String where
  toObjectKey = id

instance Monad m => FromObjectKey m String where
  fromObjectKey = return

{-------------------------------------------------------------------------------
  ToJSON and FromJSON instances
-------------------------------------------------------------------------------}

instance ToJSON JSValue where
  toJSON = id

instance Monad m => FromJSON m JSValue where
  fromJSON = return

instance ToJSON String where
  toJSON = JSString

instance ReportSchemaErrors m => FromJSON m String where
  fromJSON (JSString str) = return str
  fromJSON val            = expected' "string" val

instance ToJSON Int where
  toJSON = JSNum

instance ReportSchemaErrors m => FromJSON m Int where
  fromJSON (JSNum i) = return i
  fromJSON val       = expected' "int" val

instance ToJSON a => ToJSON [a] where
  toJSON = JSArray . map toJSON

instance (ReportSchemaErrors m, FromJSON m a) => FromJSON m [a] where
  fromJSON (JSArray as) = mapM fromJSON as
  fromJSON val          = expected' "array" val

instance ToJSON UTCTime where
  toJSON = JSString . formatTime defaultTimeLocale "%FT%TZ"

instance ReportSchemaErrors m => FromJSON m UTCTime where
  fromJSON enc = do
    str <- fromJSON enc
    case parseTimeM False defaultTimeLocale "%FT%TZ" str of
      Just time -> return time
      Nothing   -> expected "valid date-time string" (Just str)
#if !MIN_VERSION_base(4,6,0)
    where
      parseTimeM _trim = parseTime
#endif

instance ( ToObjectKey k
         , ToJSON a
         ) => ToJSON (Map k a) where
  toJSON = JSObject . map aux . Map.toList
    where
      aux :: (k, a) -> (String, JSValue)
      aux (k, a) = (toObjectKey k, toJSON a)

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

instance ToJSON URI where
  toJSON = toJSON . show

instance ReportSchemaErrors m => FromJSON m URI where
  fromJSON enc = do
    str <- fromJSON enc
    case parseURI str of
      Nothing  -> expected "valid URI" (Just str)
      Just uri -> return uri

{-------------------------------------------------------------------------------
  Utility
-------------------------------------------------------------------------------}

fromJSObject :: ReportSchemaErrors m => JSValue -> m [(String, JSValue)]
fromJSObject (JSObject obj) = return obj
fromJSObject val            = expected' "object" val

-- | Extract a field from a JSON object
fromJSField :: (ReportSchemaErrors m, FromJSON m a)
            => JSValue -> String -> m a
fromJSField val nm = do
    obj <- fromJSObject val
    case lookup nm obj of
      Just fld -> fromJSON fld
      Nothing  -> unknownField nm

fromJSOptField :: (ReportSchemaErrors m, FromJSON m a)
               => JSValue -> String -> m (Maybe a)
fromJSOptField val nm = do
    obj <- fromJSObject val
    case lookup nm obj of
      Just fld -> Just <$> fromJSON fld
      Nothing  -> return Nothing
