{-# LANGUAGE CPP #-}
#if __GLASGOW_HASKELL__ < 710
{-# LANGUAGE OverlappingInstances #-}
#endif
-- |
module Hackage.Security.Util.JSON (
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
  , mkObject
    -- * Re-exports
  , JSValue(..)
  , Int54
  ) where

import Control.Monad (liftM)
import Data.Maybe (catMaybes)
import Data.Map (Map)
import Data.Time
import Text.JSON.Canonical
import Network.URI
import qualified Data.Map as Map

#if !MIN_VERSION_time(1,5,0)
import System.Locale (defaultTimeLocale)
#endif

import Hackage.Security.Util.Path

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
  fromObjectKey :: String -> m (Maybe a)

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

instance Monad m => ToObjectKey m String where
  toObjectKey = return

instance Monad m => FromObjectKey m String where
  fromObjectKey = return . Just

instance Monad m => ToObjectKey m (Path root) where
  toObjectKey (Path fp) = return fp

instance Monad m => FromObjectKey m (Path root) where
  fromObjectKey = liftM (fmap Path) . fromObjectKey

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
  fromJSON val            = expected' "string" val

instance Monad m => ToJSON m Int54 where
  toJSON = return . JSNum

instance ReportSchemaErrors m => FromJSON m Int54 where
  fromJSON (JSNum i) = return i
  fromJSON val       = expected' "int" val

instance
#if __GLASGOW_HASKELL__ >= 710
  {-# OVERLAPPABLE #-}
#endif
    (Monad m, ToJSON m a) => ToJSON m [a] where
  toJSON = liftM JSArray . mapM toJSON

instance
#if __GLASGOW_HASKELL__ >= 710
  {-# OVERLAPPABLE #-}
#endif
    (ReportSchemaErrors m, FromJSON m a) => FromJSON m [a] where
  fromJSON (JSArray as) = mapM fromJSON as
  fromJSON val          = expected' "array" val

instance Monad m => ToJSON m UTCTime where
  toJSON = return . JSString . formatTime defaultTimeLocale "%FT%TZ"

instance ReportSchemaErrors m => FromJSON m UTCTime where
  fromJSON enc = do
    str <- fromJSON enc
    case parseTimeM False defaultTimeLocale "%FT%TZ" str of
      Just time -> return time
      Nothing   -> expected "valid date-time string" (Just str)
#if !MIN_VERSION_time(1,5,0)
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
      aux (k, a) = do k' <- toObjectKey k; a' <- toJSON a; return (k', a')

instance ( ReportSchemaErrors m
         , Ord k
         , FromObjectKey m k
         , FromJSON m a
         ) => FromJSON m (Map k a) where
  fromJSON enc = do
      obj <- fromJSObject enc
      Map.fromList . catMaybes <$> mapM aux obj
    where
      aux :: (String, JSValue) -> m (Maybe (k, a))
      aux (k, a) = knownKeys <$> fromObjectKey k <*> fromJSON a
      knownKeys :: Maybe k -> a -> Maybe (k, a)
      knownKeys Nothing  _ = Nothing
      knownKeys (Just k) a = Just (k, a)

instance Monad m => ToJSON m URI where
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

mkObject :: forall m. Monad m => [(String, m JSValue)] -> m JSValue
mkObject = liftM JSObject . sequenceFields
  where
    sequenceFields :: [(String, m JSValue)] -> m [(String, JSValue)]
    sequenceFields []               = return []
    sequenceFields ((fld,val):flds) = do val' <- val
                                         flds' <- sequenceFields flds
                                         return ((fld,val'):flds')
