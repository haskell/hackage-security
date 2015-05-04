{-# LANGUAGE OverlappingInstances #-}
{-# LANGUAGE CPP #-}
module Hackage.Security.JSON (
    -- * Monads for writing and reading JSON
    -- ** Writing
    WriteJSON
  , getAccumulatedKeys
    -- ** Reading
  , ReadJSON
  , DeserializationError(..)
  , expected
  , validate
    -- * Type classes
  , ToJSON(..)
  , FromJSON(..)
  , ToObjectKey(..)
  , FromObjectKey(..)
  , renderJSON
  , parseJSON
    -- * Utility
  , fromJSObject
  , fromJSField
    -- * I/O
  , writeCanonical
  , readCanonical
    -- * Re-exports
  , JSValue(..)
  ) where

import Control.Monad
import Control.Monad.State
import Control.Monad.Except
import Data.Time
import Data.Map (Map)
import qualified Data.ByteString.Lazy as BS.Lazy
import qualified Data.Map             as Map

#if !MIN_VERSION_base(4,6,0)
import System.Locale
#endif

import {-# SOURCE #-} Hackage.Security.Key
import Text.JSON.Canonical

{-------------------------------------------------------------------------------
  Monads for reading and writing JSON
-------------------------------------------------------------------------------}

data DeserializationError =
    -- | Malformed JSON has syntax errors in the JSON itself
    -- (i.e., we cannot even parse it to a JSValue)
    DeserializationErrorMalformed String

    -- | Invalid JSON has valid syntax but invalid structure
    --
    -- The string gives a hint about what we expected instead
  | DeserializationErrorSchema String

    -- | The JSON file contains a key ID of an unknown key
  | DeserializationErrorUnknownKey KeyId

    -- | Some verification step failed
  | DeserializationErrorValidation String
  deriving Show

newtype WriteJSON a = WriteJSON {
    unWriteJSON :: State KeyEnv a
  }
  deriving ( Functor
           , Applicative
           , Monad
           , MonadState KeyEnv
           )

runWriteJSON :: WriteJSON a -> (a, KeyEnv)
runWriteJSON act = runState (unWriteJSON act) keyEnvEmpty

newtype ReadJSON a = ReadJSON {
    unReadJSON :: ExceptT DeserializationError (State KeyEnv) a
  }
  deriving ( Functor
           , Applicative
           , Monad
           , MonadError DeserializationError
           , MonadState KeyEnv
           )

runReadJSON :: KeyEnv -> ReadJSON a -> (Either DeserializationError a, KeyEnv)
runReadJSON env act = runState (runExceptT (unReadJSON act)) env

getAccumulatedKeys :: MonadState KeyEnv m => m KeyEnv
getAccumulatedKeys = get

expected :: String -> ReadJSON a
expected str = throwError $ DeserializationErrorSchema $ "Expected " ++ str

validate :: String -> Bool -> ReadJSON ()
validate _   True  = return ()
validate msg False = throwError $ DeserializationErrorValidation msg

{-------------------------------------------------------------------------------
  Type classes
-------------------------------------------------------------------------------}

class ToJSON a where
  toJSON :: a -> WriteJSON JSValue

class FromJSON a where
  fromJSON :: JSValue -> ReadJSON a

-- | Used in the 'ToJSON' instance for 'Map'
class ToObjectKey a where
  toObjectKey :: a -> String

-- | Used in the 'FromJSON' instance for 'Map'
class FromObjectKey a where
  fromObjectKey :: String -> ReadJSON a

instance ToJSON JSValue where
  toJSON = return

instance FromJSON JSValue where
  fromJSON = return

instance ToObjectKey String where
  toObjectKey = id

instance FromObjectKey String where
  fromObjectKey = return

instance ToJSON String where
  toJSON = return . JSString

instance FromJSON String where
  fromJSON (JSString str) = return str
  fromJSON _              = expected "string"

instance ToJSON Int where
  toJSON = return . JSNum

instance FromJSON Int where
  fromJSON (JSNum i) = return i
  fromJSON _         = expected "int"

instance ToJSON a => ToJSON [a] where
  toJSON = liftM JSArray . mapM toJSON

instance FromJSON a => FromJSON [a] where
  fromJSON (JSArray as) = mapM fromJSON as
  fromJSON _            = expected "array"

instance ToJSON UTCTime where
  toJSON = return . JSString . formatTime defaultTimeLocale "%FT%TZ"

instance FromJSON UTCTime where
  fromJSON = parseTimeM False defaultTimeLocale "%FT%TZ" <=< fromJSON
#if !MIN_VERSION_base(4,6,0)
    where
      parseTimeM _trim loc format input =
        case parseTime loc format input of
          Just time -> return time
          Nothing   -> expected "valid date-time string"
#endif

instance (ToObjectKey k, ToJSON a) => ToJSON (Map k a) where
  toJSON = liftM JSObject . mapM aux . Map.toList
    where
      aux :: (k, a) -> WriteJSON (String, JSValue)
      aux (k, a) = (toObjectKey k, ) <$> toJSON a

instance (Ord k, FromObjectKey k, FromJSON a) => FromJSON (Map k a) where
  fromJSON enc = do
      obj <- fromJSObject enc
      Map.fromList <$> mapM aux obj
    where
      aux :: (String, JSValue) -> ReadJSON (k, a)
      aux (k, a) = (,) <$> fromObjectKey k <*> fromJSON a

renderJSON :: ToJSON a => a -> (BS.Lazy.ByteString, KeyEnv)
renderJSON a = let (val, keyEnv) = runWriteJSON (toJSON a)
               in (renderCanonicalJSON val, keyEnv)

parseJSON :: FromJSON a
          => KeyEnv
          -> BS.Lazy.ByteString
          -> (Either DeserializationError a, KeyEnv)
parseJSON env bs =
    case parseCanonicalJSON bs of
      Left  err -> (Left (DeserializationErrorMalformed err), env)
      Right val -> runReadJSON env (fromJSON val)

{-------------------------------------------------------------------------------
  Utility
-------------------------------------------------------------------------------}

fromJSObject :: JSValue -> ReadJSON [(String, JSValue)]
fromJSObject (JSObject obj) = return obj
fromJSObject _              = expected "object"

-- | Extract a field from a JSON object
fromJSField :: FromJSON a => JSValue -> String -> ReadJSON a
fromJSField val nm = do
    obj <- fromJSObject val
    case lookup nm obj of
      Just fld -> fromJSON fld
      Nothing  -> expected $ "field " ++ show nm

{-------------------------------------------------------------------------------
  I/O
-------------------------------------------------------------------------------}

writeCanonical :: ToJSON a => FilePath -> a -> IO KeyEnv
writeCanonical fp a = do
     let (bs, env) = renderJSON a
     BS.Lazy.writeFile fp bs
     return env

readCanonical :: FromJSON a
              => KeyEnv
              -> FilePath
              -> IO (Either DeserializationError a, KeyEnv)
readCanonical env fp = parseJSON env <$> BS.Lazy.readFile fp
