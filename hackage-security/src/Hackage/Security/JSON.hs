-- | Hackage-specific wrappers around the Util.JSON module
module Hackage.Security.JSON (
    -- * Reading
    DeserializationError(..)
  , ReadJSON -- opaque
  , runReadJSON
    -- ** Primitive operations
  , validate
  , addKeys
  , withKeys
  , readKeyAsId
  , lookupKey
    -- ** Utility
  , parseJSON
  , readCanonical
  , formatDeserializationError
    -- ** Reading without keys
  , parseNoKeys
  , readNoKeys
    -- * Writing
  , WriteJSON
  , runWriteJSON
    -- ** Utility
  , renderJSON
  , writeCanonical
  , writeKeyAsId
    -- * Re-exports
  , module Hackage.Security.Util.JSON
  ) where

import Control.Arrow (first)
import Control.Exception
import Control.Monad.Except
import Control.Monad.Reader
import Data.Typeable (Typeable)
import qualified Data.ByteString.Lazy as BS.L

import Hackage.Security.Key
import Hackage.Security.Key.Env (KeyEnv)
import Hackage.Security.TUF.Layout
import Hackage.Security.Util.JSON
import Hackage.Security.Util.Path
import Hackage.Security.Util.Some
import Text.JSON.Canonical
import qualified Hackage.Security.Key.Env as KeyEnv

{-------------------------------------------------------------------------------
  Reading
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
  deriving (Typeable, Show)

instance Exception DeserializationError

-- Access to the key environment is intentially hidden.
newtype ReadJSON a = ReadJSON {
    unReadJSON :: ExceptT DeserializationError (Reader (RepoLayout, KeyEnv)) a
  }
  deriving ( Functor
           , Applicative
           , Monad
           , MonadError DeserializationError
           )

instance ReportSchemaErrors ReadJSON where
  expected str mgot = throwError $ expectedError str mgot

instance MonadReader RepoLayout ReadJSON where
  ask         = ReadJSON $ fst `liftM` ask
  local f act = ReadJSON $ local (first f) (unReadJSON act)

expectedError :: Expected -> Maybe Got -> DeserializationError
expectedError str mgot = DeserializationErrorSchema msg
  where
    msg = case mgot of
            Nothing  -> "Expected " ++ str
            Just got -> "Expected " ++ str ++ " but got " ++ got

runReadJSON :: RepoLayout -> KeyEnv -> ReadJSON a -> Either DeserializationError a
runReadJSON repoLayout keyEnv act =
    runReader (runExceptT (unReadJSON act)) (repoLayout, keyEnv)

{-------------------------------------------------------------------------------
  Reading: Primitive operations
-------------------------------------------------------------------------------}

validate :: String -> Bool -> ReadJSON ()
validate _   True  = return ()
validate msg False = throwError $ DeserializationErrorValidation msg

addKeys :: KeyEnv -> ReadJSON a -> ReadJSON a
addKeys keys (ReadJSON act) = ReadJSON $ local aux act
  where
    aux :: (RepoLayout, KeyEnv) -> (RepoLayout, KeyEnv)
    aux (repoLayout, keyEnv) = (repoLayout, KeyEnv.union keys keyEnv)

withKeys :: KeyEnv -> ReadJSON a -> ReadJSON a
withKeys keys (ReadJSON act) = ReadJSON $ local aux act
  where
    aux :: (RepoLayout, KeyEnv) -> (RepoLayout, KeyEnv)
    aux (repoLayout, _keyEnv) = (repoLayout, keys)

readKeyAsId :: JSValue -> ReadJSON (Some PublicKey)
readKeyAsId (JSString kId) = lookupKey (KeyId kId)
readKeyAsId val = expected' "key ID" val

lookupKey :: KeyId -> ReadJSON (Some PublicKey)
lookupKey kId = do
    (_repoLayout, keyEnv) <- ReadJSON $ ask
    case KeyEnv.lookup kId keyEnv of
      Just key -> return key
      Nothing  -> throwError $ DeserializationErrorUnknownKey kId

{-------------------------------------------------------------------------------
  Reading: Utility
-------------------------------------------------------------------------------}

parseJSON :: FromJSON ReadJSON a
          => RepoLayout
          -> KeyEnv
          -> BS.L.ByteString
          -> Either DeserializationError a
parseJSON repoLayout keyEnv bs =
    case parseCanonicalJSON bs of
      Left  err -> Left (DeserializationErrorMalformed err)
      Right val -> runReadJSON repoLayout keyEnv (fromJSON val)

readCanonical :: (IsFileSystemRoot root, FromJSON ReadJSON a)
              => RepoLayout
              -> KeyEnv
              -> Path (Rooted root)
              -> IO (Either DeserializationError a)
readCanonical repoLayout keyEnv fp = do
    withFile fp ReadMode $ \h -> do
      bs <- BS.L.hGetContents h
      evaluate $ parseJSON repoLayout keyEnv bs

formatDeserializationError :: DeserializationError -> String
formatDeserializationError (DeserializationErrorMalformed str) =
    "Malformed: " ++ str
formatDeserializationError (DeserializationErrorSchema str) =
    "Schema error: " ++ str
formatDeserializationError (DeserializationErrorUnknownKey kId) =
    "Unknown key: " ++ keyIdString kId
formatDeserializationError (DeserializationErrorValidation str) =
    "Invalid: " ++ str

{-------------------------------------------------------------------------------
  Reading datatypes that do not require keys
-------------------------------------------------------------------------------}

newtype NoKeys a = NoKeys {
    unNoKeys :: Except DeserializationError a
  }
  deriving (Functor, Applicative, Monad, MonadError DeserializationError)

instance ReportSchemaErrors NoKeys where
  expected str mgot = throwError $ expectedError str mgot

runNoKeys :: NoKeys a -> Either DeserializationError a
runNoKeys = runExcept . unNoKeys

parseNoKeys :: FromJSON NoKeys a
            => BS.L.ByteString -> Either DeserializationError a
parseNoKeys bs =
    case parseCanonicalJSON bs of
      Left  err -> Left (DeserializationErrorMalformed err)
      Right val -> runNoKeys (fromJSON val)

readNoKeys :: (IsFileSystemRoot root, FromJSON NoKeys a)
           => Path (Rooted root) -> IO (Either DeserializationError a)
readNoKeys fp = do
    withFile fp ReadMode $ \h -> do
      bs <- BS.L.hGetContents h
      evaluate $ parseNoKeys bs

{-------------------------------------------------------------------------------
  Writing
-------------------------------------------------------------------------------}

newtype WriteJSON a = WriteJSON {
    unWriteJSON :: Reader RepoLayout a
  }
  deriving ( Functor
           , Applicative
           , Monad
           , MonadReader RepoLayout
           )

runWriteJSON :: RepoLayout -> WriteJSON a -> a
runWriteJSON repoLayout act = runReader (unWriteJSON act) repoLayout

{-------------------------------------------------------------------------------
  Writing: Utility
-------------------------------------------------------------------------------}

renderJSON :: ToJSON WriteJSON a => RepoLayout -> a -> BS.L.ByteString
renderJSON repoLayout = renderCanonicalJSON . runWriteJSON repoLayout . toJSON

writeCanonical :: (IsFileSystemRoot root, ToJSON WriteJSON a)
               => RepoLayout -> Path (Rooted root) -> a -> IO ()
writeCanonical repoLayout fp = writeLazyByteString fp . renderJSON repoLayout

writeKeyAsId :: Some PublicKey -> JSValue
writeKeyAsId = JSString . keyIdString . someKeyId
