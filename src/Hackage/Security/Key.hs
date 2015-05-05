module Hackage.Security.Key (
    -- * Key types
    Ed25519
    -- * Opaque types abstracting over key types
  , Key
  , PublicKey
  , PrivateKey
    -- * Key types in isolation
  , KeyType(..)
    -- * Hiding key types
  , somePublicKeyType
  , someKeyId
    -- * Operations on keys
  , publicKey
  , privateKey
  , createKey
    -- * Key IDs
  , KeyId(..)
  , HasKeyId(..)
    -- * Explicit sharing
  , KeyEnv(..)
  , keyEnvEmpty
  , keyEnvInsert
  , keyEnvLookup
  , writeKeyAsId
  , readKeyAsId
    -- * JSON auxiliary
  , WriteJSON(..)
  , ReadJSON(..)
  , renderJSON
  , validate
  , getAccumulatedKeys
  , writeCanonical
  , readCanonical
    -- * Signing
  , sign
  , verify
  ) where

import Control.Monad.Except
import Control.Monad.State
import Data.Digest.Pure.SHA
import Data.Map (Map)
import Text.JSON.Canonical
import qualified Crypto.Sign.Ed25519  as Ed25519
import qualified Data.ByteString      as BS
import qualified Data.ByteString.Lazy as BS.L
import qualified Data.Map             as Map

import Hackage.Security.JSON
import Hackage.Security.Some
import qualified Hackage.Security.Base64 as B64

{-------------------------------------------------------------------------------
  Generalization over key types
-------------------------------------------------------------------------------}

data Ed25519

data Key a where
    KeyEd25519 :: Ed25519.PublicKey -> Ed25519.SecretKey -> Key Ed25519

data PublicKey a where
    PublicKeyEd25519 :: Ed25519.PublicKey -> PublicKey Ed25519

data PrivateKey a where
    PrivateKeyEd25519 :: Ed25519.SecretKey -> PrivateKey Ed25519

deriving instance Show (Key        typ)
deriving instance Show (PublicKey  typ)
deriving instance Show (PrivateKey typ)

deriving instance Eq (Key        typ)
deriving instance Eq (PublicKey  typ)
deriving instance Eq (PrivateKey typ)

deriving instance Ord (Key        typ)
deriving instance Ord (PublicKey  typ)
deriving instance Ord (PrivateKey typ)

publicKey :: Key a -> PublicKey a
publicKey (KeyEd25519 pub _pri) = PublicKeyEd25519 pub

privateKey :: Key a -> PrivateKey a
privateKey (KeyEd25519 _pub pri) = PrivateKeyEd25519 pri

{-------------------------------------------------------------------------------
  Sometimes it's useful to talk about the type of a key independent of the key
-------------------------------------------------------------------------------}

data KeyType typ where
  KeyTypeEd25519 :: KeyType Ed25519

deriving instance Show (KeyType typ)
deriving instance Eq   (KeyType typ)
deriving instance Ord  (KeyType typ)

instance Unify KeyType where
  unify KeyTypeEd25519 KeyTypeEd25519 = Just Refl

type instance TypeOf Key        = KeyType
type instance TypeOf PublicKey  = KeyType
type instance TypeOf PrivateKey = KeyType

instance Typed Key where
  typeOf (KeyEd25519 _ _) = KeyTypeEd25519

instance Typed PublicKey where
  typeOf (PublicKeyEd25519 _) = KeyTypeEd25519

instance Typed PrivateKey where
  typeOf (PrivateKeyEd25519 _) = KeyTypeEd25519

{-------------------------------------------------------------------------------
  We don't always know the key type
-------------------------------------------------------------------------------}

somePublicKeyType :: Some PublicKey -> Some KeyType
somePublicKeyType (Some pub) = Some (typeOf pub)

someKeyId :: HasKeyId key => Some key -> KeyId
someKeyId (Some a) = keyId a

{-------------------------------------------------------------------------------
  Creating keys
-------------------------------------------------------------------------------}

createKey :: KeyType key -> IO (Key key)
createKey KeyTypeEd25519 = uncurry KeyEd25519 <$> Ed25519.createKeypair

{-------------------------------------------------------------------------------
  Key IDs
-------------------------------------------------------------------------------}

-- | The key ID of a key, by definition, is the hexdigest of the SHA-256 hash of
-- the canonical JSON form of the key where the private object key is excluded.
--
-- NOTE: The FromJSON and ToJSON instances for KeyId are ntentially omitted. Use
-- writeKeyAsId instead.
newtype KeyId = KeyId { keyIdString :: String }
  deriving (Show, Eq, Ord)

instance Monad m => ToObjectKey m KeyId where
  toObjectKey = return . keyIdString

instance Monad m => FromObjectKey m KeyId where
  fromObjectKey = return . KeyId

-- | Compute the key ID of a key
class HasKeyId key where
  keyId :: key typ -> KeyId

instance HasKeyId PublicKey where
  keyId = KeyId . showDigest . sha256 . fst . renderJSON

instance HasKeyId Key where
  keyId = keyId . publicKey

{-------------------------------------------------------------------------------
  Signing
-------------------------------------------------------------------------------}

-- | Sign a bytestring and return the signature
--
-- TODO: It is unfortunate that we have to convert to a strict bytestring for
-- ed25519
sign :: PrivateKey typ -> BS.L.ByteString -> BS.ByteString
sign (PrivateKeyEd25519 pri) =
    Ed25519.unSignature . Ed25519.sign' pri . BS.concat . BS.L.toChunks

verify :: PublicKey typ -> BS.L.ByteString -> BS.ByteString -> Bool
verify (PublicKeyEd25519 pub) inp sig =
    Ed25519.verify' pub (BS.concat $ BS.L.toChunks inp) (Ed25519.Signature sig)

{-------------------------------------------------------------------------------
  Monads we use for writing and reading JSON with explicit key sharing
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

instance ReportSchemaErrors ReadJSON where
  expected str = throwError $ DeserializationErrorSchema $ "Expected " ++ str

runReadJSON :: KeyEnv -> ReadJSON a -> (Either DeserializationError a, KeyEnv)
runReadJSON env act = runState (runExceptT (unReadJSON act)) env

getAccumulatedKeys :: MonadState KeyEnv m => m KeyEnv
getAccumulatedKeys = get

validate :: String -> Bool -> ReadJSON ()
validate _   True  = return ()
validate msg False = throwError $ DeserializationErrorValidation msg

{-------------------------------------------------------------------------------
  Explicit sharing
-------------------------------------------------------------------------------}

newtype KeyEnv = KeyEnv {
    keyEnvMap :: Map KeyId (Some PublicKey)
  }

keyEnvEmpty :: KeyEnv
keyEnvEmpty = KeyEnv Map.empty

keyEnvInsert :: Some PublicKey -> KeyEnv -> KeyEnv
keyEnvInsert key (KeyEnv env) = KeyEnv $ Map.insert (someKeyId key) key env

keyEnvLookup :: KeyId -> KeyEnv -> Maybe (Some PublicKey)
keyEnvLookup kId (KeyEnv env) = Map.lookup kId env

writeKeyAsId :: Some PublicKey -> WriteJSON JSValue
writeKeyAsId key = do
    recordKey key
    return $ JSString . keyIdString . someKeyId $ key

readKeyAsId :: JSValue -> ReadJSON (Some PublicKey)
readKeyAsId (JSString kId) = lookupKey (KeyId kId)
readKeyAsId _ = expected "key ID"

{-------------------------------------------------------------------------------
  JSON auxiliary
-------------------------------------------------------------------------------}

recordKey :: MonadState KeyEnv m => Some PublicKey -> m ()
recordKey key = modify $ keyEnvInsert key

lookupKey :: KeyId -> ReadJSON (Some PublicKey)
lookupKey kId = do
    env <- get
    case keyEnvLookup kId env of
      Just key -> return key
      Nothing  -> throwError $ DeserializationErrorUnknownKey kId

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

{-------------------------------------------------------------------------------
  JSON encoding and decoding
-------------------------------------------------------------------------------}

instance Monad m => ToJSON m (Key typ) where
  toJSON key = case key of
      KeyEd25519 pub pri ->
        enc "ed25519" (Ed25519.unPublicKey pub) (Ed25519.unSecretKey pri)
    where
      enc :: String -> BS.ByteString -> BS.ByteString -> m JSValue
      enc tag pub pri = do
        pub' <- toJSON (B64.fromByteString pub)
        pri' <- toJSON (B64.fromByteString pri)
        return $ JSObject [
            ("keytype", JSString tag)
          , ("keyval", JSObject [
                ("public",  pub')
              , ("private", pri')
              ])
          ]

instance ReportSchemaErrors m => FromJSON m (Some Key) where
  fromJSON enc = do
      (tag, pub, pri) <- dec enc
      case tag of
        "ed25519" -> return . Some $
          KeyEd25519 (Ed25519.PublicKey pub) (Ed25519.SecretKey pri)
        _otherwise ->
          expected "valid key type"
    where
      dec :: JSValue -> m (String, BS.ByteString, BS.ByteString)
      dec obj = do
        tag <- fromJSField obj "keytype"
        val <- fromJSField obj "keyval"
        pub <- fromJSField val "public"
        pri <- fromJSField val "private"
        return (tag, B64.toByteString pub, B64.toByteString pri)

instance Monad m => ToJSON m (PublicKey typ) where
  toJSON key = case key of
      PublicKeyEd25519 pub ->
        enc "ed25519" (Ed25519.unPublicKey pub)
    where
      enc :: String -> BS.ByteString -> m JSValue
      enc tag pub = do
        pub' <- toJSON (B64.fromByteString pub)
        return $ JSObject [
            ("keytype", JSString tag)
          , ("keyval", JSObject [
                ("public", pub')
              ])
          ]

instance Monad m => ToJSON m (Some PublicKey) where
  toJSON (Some pub) = toJSON pub

instance Monad m => ToJSON m (Some KeyType) where
  toJSON (Some pub) = toJSON pub

instance ReportSchemaErrors m => FromJSON m (Some PublicKey) where
  fromJSON enc = do
      (tag, pub) <- dec enc
      case tag of
        "ed25519" -> return . Some $
          PublicKeyEd25519 (Ed25519.PublicKey pub)
        _otherwise ->
          expected "valid key type"
    where
      dec :: JSValue -> m (String, BS.ByteString)
      dec obj = do
        tag <- fromJSField obj "keytype"
        val <- fromJSField obj "keyval"
        pub <- fromJSField val "public"
        return (tag, B64.toByteString pub)

instance Monad m => ToJSON m (KeyType typ) where
  toJSON KeyTypeEd25519 = return $ JSString "ed25519"

instance ReportSchemaErrors m => FromJSON m (Some KeyType) where
  fromJSON enc = do
    tag <- fromJSON enc
    case tag of
      "ed25519"  -> return . Some $ KeyTypeEd25519
      _otherwise -> expected "valid key type"

instance Monad m => ToJSON m KeyEnv where
  toJSON (KeyEnv keyEnv) = toJSON keyEnv

-- TODO: verify key ID matches
instance ReportSchemaErrors m => FromJSON m KeyEnv where
  fromJSON enc = KeyEnv <$> fromJSON enc
