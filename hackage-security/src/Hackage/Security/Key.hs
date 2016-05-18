{-# LANGUAGE CPP #-}
module Hackage.Security.Key (
    -- * Key types
    Ed25519
    -- * Types abstracting over key types
  , Key(..)
  , PublicKey(..)
  , PrivateKey(..)
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
import Data.Functor.Identity
import Data.Typeable (Typeable)
import Text.JSON.Canonical
import qualified Crypto.Hash.SHA256   as SHA256
import qualified Crypto.Sign.Ed25519  as Ed25519
import qualified Data.ByteString      as BS
import qualified Data.ByteString.Char8 as BS.C8
import qualified Data.ByteString.Base16 as Base16
import qualified Data.ByteString.Lazy as BS.L

#if !MIN_VERSION_base(4,7,0)
import qualified Data.Typeable as Typeable
#endif

import Hackage.Security.Util.JSON
import Hackage.Security.Util.Some
import Hackage.Security.Util.TypedEmbedded
import qualified Hackage.Security.Util.Base64 as B64

{-------------------------------------------------------------------------------
  Generalization over key types
-------------------------------------------------------------------------------}

data Ed25519

data Key a where
    KeyEd25519 :: Ed25519.PublicKey -> Ed25519.SecretKey -> Key Ed25519
  deriving (Typeable)

data PublicKey a where
    PublicKeyEd25519 :: Ed25519.PublicKey -> PublicKey Ed25519
  deriving (Typeable)

data PrivateKey a where
    PrivateKeyEd25519 :: Ed25519.SecretKey -> PrivateKey Ed25519
  deriving (Typeable)

deriving instance Show (Key        typ)
deriving instance Show (PublicKey  typ)
deriving instance Show (PrivateKey typ)

deriving instance Eq (Key        typ)
deriving instance Eq (PublicKey  typ)
deriving instance Eq (PrivateKey typ)

instance SomeShow Key        where someShow = DictShow
instance SomeShow PublicKey  where someShow = DictShow
instance SomeShow PrivateKey where someShow = DictShow

instance SomeEq Key        where someEq = DictEq
instance SomeEq PublicKey  where someEq = DictEq
instance SomeEq PrivateKey where someEq = DictEq

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

instance SomeShow KeyType where someShow = DictShow
instance SomeEq   KeyType where someEq   = DictEq

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

instance Monad m => ToObjectKey m KeyId where
  toObjectKey = return . keyIdString

instance Monad m => FromObjectKey m KeyId where
  fromObjectKey = return . Just . KeyId

-- | Compute the key ID of a key
class HasKeyId key where
  keyId :: key typ -> KeyId

instance HasKeyId PublicKey where
  keyId = KeyId
        . BS.C8.unpack
        . Base16.encode
        . SHA256.hashlazy
        . renderCanonicalJSON
        . runIdentity
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
    Ed25519.unSignature . dsign pri . BS.concat . BS.L.toChunks
  where
#if MIN_VERSION_ed25519(0,0,4)
    dsign = Ed25519.dsign
#else
    dsign = Ed25519.sign'
#endif

verify :: PublicKey typ -> BS.L.ByteString -> BS.ByteString -> Bool
verify (PublicKeyEd25519 pub) inp sig =
    dverify pub (BS.concat $ BS.L.toChunks inp) (Ed25519.Signature sig)
  where
#if MIN_VERSION_ed25519(0,0,4)
    dverify = Ed25519.dverify
#else
    dverify = Ed25519.verify'
#endif

{-------------------------------------------------------------------------------
  JSON encoding and decoding
-------------------------------------------------------------------------------}

instance Monad m => ToJSON m (Key typ) where
  toJSON key = case key of
      KeyEd25519 pub pri ->
        enc "ed25519" (Ed25519.unPublicKey pub) (Ed25519.unSecretKey pri)
    where
      enc :: String -> BS.ByteString -> BS.ByteString -> m JSValue
      enc tag pub pri = mkObject [
            ("keytype", return $ JSString tag)
          , ("keyval", mkObject [
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

instance Monad m => ToJSON m (PublicKey typ) where
  toJSON key = case key of
      PublicKeyEd25519 pub ->
        enc "ed25519" (Ed25519.unPublicKey pub)
    where
      enc :: String -> BS.ByteString -> m JSValue
      enc tag pub = mkObject [
            ("keytype", return $ JSString tag)
          , ("keyval", mkObject [
                ("public", toJSON (B64.fromByteString pub))
              ])
          ]

instance Monad m => ToJSON m (Some Key)        where toJSON (Some a) = toJSON a
instance Monad m => ToJSON m (Some PublicKey)  where toJSON (Some a) = toJSON a
instance Monad m => ToJSON m (Some KeyType)    where toJSON (Some a) = toJSON a

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

instance Monad m => ToJSON m (KeyType typ) where
  toJSON KeyTypeEd25519 = return $ JSString "ed25519"

instance ReportSchemaErrors m => FromJSON m (Some KeyType) where
  fromJSON enc = do
    tag <- fromJSON enc
    case tag of
      "ed25519"  -> return . Some $ KeyTypeEd25519
      _otherwise -> expected "valid key type" (Just tag)

{-------------------------------------------------------------------------------
  Orphans

  Pre-7.8 (base 4.7) we cannot have Typeable instance for higher-kinded types.
  Instead, here we provide some instance for specific instantiations.
-------------------------------------------------------------------------------}

#if !MIN_VERSION_base(4,7,0)
tyConKey, tyConPublicKey, tyConPrivateKey :: Typeable.TyCon
tyConKey        = Typeable.mkTyCon3 "hackage-security" "Hackage.Security.Key" "Key"
tyConPublicKey  = Typeable.mkTyCon3 "hackage-security" "Hackage.Security.Key" "PublicKey"
tyConPrivateKey = Typeable.mkTyCon3 "hackage-security" "Hackage.Security.Key" "PrivateKey"

instance Typeable (Some Key) where
  typeOf _ = Typeable.mkTyConApp tyConSome [Typeable.mkTyConApp tyConKey []]

instance Typeable (Some PublicKey) where
  typeOf _ = Typeable.mkTyConApp tyConSome [Typeable.mkTyConApp tyConPublicKey []]

instance Typeable (Some PrivateKey) where
  typeOf _ = Typeable.mkTyConApp tyConSome [Typeable.mkTyConApp tyConPrivateKey []]
#endif
