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
  , somePublicKey
  , somePublicKeyType
  , someKeyId
    -- * Operations on keys
  , publicKey
  , privateKey
  , createKey
  , createKey'
    -- * Key IDs
  , KeyId(..)
  , HasKeyId(..)
    -- * Signing
  , sign
  , verify
  ) where

import Control.Monad
import Data.Digest.Pure.SHA
import Text.JSON.Canonical
import qualified Crypto.Sign.Ed25519  as Ed25519
import qualified Data.ByteString      as BS
import qualified Data.ByteString.Lazy as BS.L

import Hackage.Security.JSON
import Hackage.Security.Util.Some
import Hackage.Security.Util.TypedEmbedded
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

somePublicKey :: Some Key -> Some PublicKey
somePublicKey (Some key) = Some (publicKey key)

somePublicKeyType :: Some PublicKey -> Some KeyType
somePublicKeyType (Some pub) = Some (typeOf pub)

someKeyId :: HasKeyId key => Some key -> KeyId
someKeyId (Some a) = keyId a

{-------------------------------------------------------------------------------
  Creating keys
-------------------------------------------------------------------------------}

createKey :: KeyType key -> IO (Key key)
createKey KeyTypeEd25519 = uncurry KeyEd25519 <$> Ed25519.createKeypair

createKey' :: KeyType key -> IO (Some Key)
createKey' = liftM Some . createKey

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

instance ToObjectKey KeyId where
  toObjectKey = keyIdString

instance Monad m => FromObjectKey m KeyId where
  fromObjectKey = return . KeyId

-- | Compute the key ID of a key
class HasKeyId key where
  keyId :: key typ -> KeyId

instance HasKeyId PublicKey where
  keyId = KeyId
        . showDigest
        . sha256
        . renderCanonicalJSON
        . toJSON

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
  JSON encoding and decoding
-------------------------------------------------------------------------------}

instance ToJSON (Key typ) where
  toJSON key = case key of
      KeyEd25519 pub pri ->
        enc "ed25519" (Ed25519.unPublicKey pub) (Ed25519.unSecretKey pri)
    where
      enc :: String -> BS.ByteString -> BS.ByteString -> JSValue
      enc tag pub pri = JSObject [
            ("keytype", JSString tag)
          , ("keyval", JSObject [
                ("public",  toJSON (B64.fromByteString pub))
              , ("private", toJSON (B64.fromByteString pri))
              ])
          ]

instance ReportSchemaErrors m => FromJSON m (Some Key) where
  fromJSON enc = do
      (tag, pub, pri) <- dec enc
      case tag of
        "ed25519" -> return . Some $
          KeyEd25519 (Ed25519.PublicKey pub) (Ed25519.SecretKey pri)
        _otherwise ->
          expected "valid key type" (Just tag)
    where
      dec :: JSValue -> m (String, BS.ByteString, BS.ByteString)
      dec obj = do
        tag <- fromJSField obj "keytype"
        val <- fromJSField obj "keyval"
        pub <- fromJSField val "public"
        pri <- fromJSField val "private"
        return (tag, B64.toByteString pub, B64.toByteString pri)

instance ToJSON (PublicKey typ) where
  toJSON key = case key of
      PublicKeyEd25519 pub ->
        enc "ed25519" (Ed25519.unPublicKey pub)
    where
      enc :: String -> BS.ByteString -> JSValue
      enc tag pub = JSObject [
            ("keytype", JSString tag)
          , ("keyval", JSObject [
                ("public", toJSON (B64.fromByteString pub))
              ])
          ]

instance ToJSON (Some Key)        where toJSON (Some a) = toJSON a
instance ToJSON (Some PublicKey)  where toJSON (Some a) = toJSON a
instance ToJSON (Some KeyType)    where toJSON (Some a) = toJSON a

instance ReportSchemaErrors m => FromJSON m (Some PublicKey) where
  fromJSON enc = do
      (tag, pub) <- dec enc
      case tag of
        "ed25519" -> return . Some $
          PublicKeyEd25519 (Ed25519.PublicKey pub)
        _otherwise ->
          expected "valid key type" (Just tag)
    where
      dec :: JSValue -> m (String, BS.ByteString)
      dec obj = do
        tag <- fromJSField obj "keytype"
        val <- fromJSField obj "keyval"
        pub <- fromJSField val "public"
        return (tag, B64.toByteString pub)

instance ToJSON (KeyType typ) where
  toJSON KeyTypeEd25519 = JSString "ed25519"

instance ReportSchemaErrors m => FromJSON m (Some KeyType) where
  fromJSON enc = do
    tag <- fromJSON enc
    case tag of
      "ed25519"  -> return . Some $ KeyTypeEd25519
      _otherwise -> expected "valid key type" (Just tag)
