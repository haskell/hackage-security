module Hackage.Security.Key.ExplicitSharing (
    DeserializationError(..)
  , WriteJSON -- opaque
  , ReadJSON  -- opaque
  , runWriteJSON
  , runReadJSON
    -- * Primitive functions
  , getAccumulatedKeys
  , validate
  , writeKeyAsId
  , readKeyAsId
  , recordKey
  , lookupKey
    -- * Utility
  , renderJSON
  , parseJSON
  , writeCanonical
  , readCanonical
  ) where

import Control.Monad.Except
import Control.Monad.State
import qualified Data.ByteString.Lazy as BS.L

import Hackage.Security.Key
import Hackage.Security.Key.Env (KeyEnv)
import Hackage.Security.JSON
import Hackage.Security.Some
import Text.JSON.Canonical
import qualified Hackage.Security.Key.Env as KeyEnv

{-------------------------------------------------------------------------------
  Monads
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
runWriteJSON act = runState (unWriteJSON act) KeyEnv.empty

newtype ReadJSON a = ReadJSON {
    unReadJSON :: ExceptT DeserializationError (State KeyEnv) a
  }
  deriving ( Functor
           , Applicative
           , Monad
           , MonadError DeserializationError
           , MonadState KeyEnv
           )

instance ReportSchemaErrors ReadJSON where
  expected str = throwError $ DeserializationErrorSchema $ "Expected " ++ str

runReadJSON :: KeyEnv -> ReadJSON a -> (Either DeserializationError a, KeyEnv)
runReadJSON env act = runState (runExceptT (unReadJSON act)) env

{-------------------------------------------------------------------------------
  Primitive functions
-------------------------------------------------------------------------------}

getAccumulatedKeys :: MonadState KeyEnv m => m KeyEnv
getAccumulatedKeys = get

validate :: String -> Bool -> ReadJSON ()
validate _   True  = return ()
validate msg False = throwError $ DeserializationErrorValidation msg

writeKeyAsId :: Some PublicKey -> WriteJSON JSValue
writeKeyAsId key = do
    recordKey key
    return $ JSString . keyIdString . someKeyId $ key

readKeyAsId :: JSValue -> ReadJSON (Some PublicKey)
readKeyAsId (JSString kId) = lookupKey (KeyId kId)
readKeyAsId _ = expected "key ID"

recordKey :: MonadState KeyEnv m => Some PublicKey -> m ()
recordKey key = modify $ KeyEnv.insert key

lookupKey :: KeyId -> ReadJSON (Some PublicKey)
lookupKey kId = do
    env <- get
    case KeyEnv.lookup kId env of
      Just key -> return key
      Nothing  -> throwError $ DeserializationErrorUnknownKey kId

{-------------------------------------------------------------------------------
  Utility
-------------------------------------------------------------------------------}

renderJSON :: ToJSON WriteJSON a => a -> (BS.L.ByteString, KeyEnv)
renderJSON a = let (val, keyEnv) = runWriteJSON (toJSON a)
               in (renderCanonicalJSON val, keyEnv)

parseJSON :: FromJSON ReadJSON a
          => KeyEnv
          -> BS.L.ByteString
          -> (Either DeserializationError a, KeyEnv)
parseJSON env bs =
    case parseCanonicalJSON bs of
      Left  err -> (Left (DeserializationErrorMalformed err), env)
      Right val -> runReadJSON env (fromJSON val)

writeCanonical :: ToJSON WriteJSON a => FilePath -> a -> IO KeyEnv
writeCanonical fp a = do
     let (bs, env) = renderJSON a
     BS.L.writeFile fp bs
     return env

readCanonical :: FromJSON ReadJSON a
              => KeyEnv
              -> FilePath
              -> IO (Either DeserializationError a, KeyEnv)
readCanonical env fp = parseJSON env <$> BS.L.readFile fp
