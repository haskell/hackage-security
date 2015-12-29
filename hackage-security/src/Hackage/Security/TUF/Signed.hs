-- | Wrapper around an arbitrary datatype that adds signatures
--
-- Note that in the spec there is explicit sharing of keys through key IDs;
-- we translate this to implicit sharing in our Haskell datatypes, with the
-- translation done in the JSON serialization/deserialization.
module Hackage.Security.TUF.Signed (
    -- * TUF types
    Signed(..)
  , Signatures(..)
  , Signature(..)
    -- * Construction and verification
  , unsigned
  , withSignatures
  , withSignatures'
  , signRendered
  , verifySignature
    -- * JSON aids
  , signedFromJSON
  , verifySignatures
    -- * Avoid interpreting signatures
  , UninterpretedSignatures(..)
  , PreSignature(..)
    -- ** Utility
  , fromPreSignature
  , fromPreSignatures
  , toPreSignature
  , toPreSignatures
  ) where

import Control.Monad
import Data.Functor.Identity
import qualified Data.ByteString      as BS
import qualified Data.ByteString.Lazy as BS.L
import qualified Data.Set             as Set

import Hackage.Security.JSON
import Hackage.Security.Key
import Hackage.Security.TUF.Layout.Repo
import Hackage.Security.Util.Some
import Text.JSON.Canonical
import qualified Hackage.Security.Util.Base64 as B64

{-------------------------------------------------------------------------------
  Signed objects
-------------------------------------------------------------------------------}

data Signed a = Signed {
    signed     :: a
  , signatures :: Signatures
  }

-- | A list of signatures
--
-- Invariant: each signature must be made with a different key.
-- We enforce this invariant for incoming untrusted data ('fromPreSignatures')
-- but not for lists of signatures that we create in code.
newtype Signatures = Signatures [Signature]

data Signature = Signature {
    signature    :: BS.ByteString
  , signatureKey :: Some PublicKey
  }

-- | Create a new document without any signatures
unsigned :: a -> Signed a
unsigned a = Signed { signed = a, signatures = Signatures [] }

-- | Sign a document
withSignatures :: ToJSON WriteJSON a => RepoLayout -> [Some Key] -> a -> Signed a
withSignatures repoLayout keys doc = Signed {
      signed     = doc
    , signatures = signRendered keys $ renderJSON repoLayout doc
    }

-- | Variation on 'withSignatures' that doesn't need the repo layout
withSignatures' :: ToJSON Identity a => [Some Key] -> a -> Signed a
withSignatures' keys doc = Signed {
      signed     = doc
    , signatures = signRendered keys $ renderJSON_NoLayout doc
    }

-- | Construct signatures for already rendered value
signRendered :: [Some Key] -> BS.L.ByteString -> Signatures
signRendered keys rendered = Signatures $ map go keys
  where
    go :: Some Key -> Signature
    go (Some key) = Signature {
        signature    = sign (privateKey key) rendered
      , signatureKey = Some $ publicKey key
      }

verifySignature :: BS.L.ByteString -> Signature -> Bool
verifySignature inp Signature{signature = sig, signatureKey = Some pub} =
  verify pub inp sig

instance (Monad m, ToJSON m a) => ToJSON m (Signed a) where
  toJSON Signed{..} = mkObject [
         ("signed"     , toJSON signed)
       , ("signatures" , toJSON signatures)
       ]

instance Monad m => ToJSON m Signatures where
  toJSON = toJSON . toPreSignatures

instance MonadKeys m => FromJSON m Signatures where
  fromJSON = fromPreSignatures <=< fromJSON

{-------------------------------------------------------------------------------
  JSON aids
-------------------------------------------------------------------------------}

-- | General FromJSON instance for signed datatypes
--
-- We don't give a general FromJSON instance for Signed because for some
-- datatypes we need to do something special (datatypes where we need to
-- read key environments); for instance, see the "Signed Root" instance.
signedFromJSON :: (MonadKeys m, FromJSON m a) => JSValue -> m (Signed a)
signedFromJSON envelope = do
    enc        <- fromJSField envelope "signed"
    signed     <- fromJSON enc
    signatures <- fromJSField envelope "signatures"
    validate "signatures" $ verifySignatures enc signatures
    return Signed{..}

-- | Signature verification
--
-- NOTES:
-- 1. By definition, the signature must be verified against the canonical
--    JSON format. This means we _must_ parse and then pretty print (as
--    we do here) because the document as stored may or may not be in
--    canonical format.
-- 2. However, it is important that we NOT translate from the JSValue
--    to whatever internal datatype we are using and then back to JSValue,
--    because that may not roundtrip: we must allow for additional fields
--    in the JSValue that we ignore (and would therefore lose when we
--    attempt to roundtrip).
-- 3. We verify that all signatures are valid, but we cannot verify (here)
--    that these signatures are signed with the right key, or that we
--    have a sufficient number of signatures. This will be the
--    responsibility of the calling code.
verifySignatures :: JSValue -> Signatures -> Bool
verifySignatures parsed (Signatures sigs) =
    all (verifySignature $ renderCanonicalJSON parsed) sigs

{-------------------------------------------------------------------------------
  Uninterpreted signatures
-------------------------------------------------------------------------------}

-- | File with uninterpreted signatures
--
-- Sometimes we want to be able to read a file without interpreting the
-- signatures (that is, resolving the key IDs) or doing any kind of checks on
-- them. One advantage of this is that this allows us to read many file types
-- without any key environment at all, which is sometimes useful.
data UninterpretedSignatures a = UninterpretedSignatures {
    uninterpretedSigned     :: a
  , uninterpretedSignatures :: [PreSignature]
  }
  deriving (Show)

-- | A signature with a key ID (rather than an actual key)
--
-- This corresponds precisely to the TUF representation of a signature.
data PreSignature = PreSignature {
    presignature :: BS.ByteString
  , presigMethod :: Some KeyType
  , presigKeyId  :: KeyId
  }
  deriving (Show)

-- | Convert a pre-signature to a signature
--
-- Verifies that the key type matches the advertised method.
fromPreSignature :: MonadKeys m => PreSignature -> m Signature
fromPreSignature PreSignature{..} = do
    key <- lookupKey presigKeyId
    validate "key type" $ typecheckSome key presigMethod
    return Signature {
        signature    = presignature
      , signatureKey = key
      }

-- | Convert signature to pre-signature
toPreSignature :: Signature -> PreSignature
toPreSignature Signature{..} = PreSignature {
      presignature = signature
    , presigMethod = somePublicKeyType signatureKey
    , presigKeyId  = someKeyId         signatureKey
    }

-- | Convert a list of 'PreSignature's to a list of 'Signature's
--
-- This verifies the invariant that all signatures are made with different keys.
-- We do this on the presignatures rather than the signatures so that we can do
-- the check on key IDs, rather than keys (the latter don't have an Ord
-- instance).
fromPreSignatures :: MonadKeys m => [PreSignature] -> m Signatures
fromPreSignatures sigs = do
      validate "all signatures made with different keys" $
        Set.size (Set.fromList (map presigKeyId sigs)) == length sigs
      Signatures <$> mapM fromPreSignature sigs

-- | Convert list of pre-signatures to a list of signatures
toPreSignatures :: Signatures -> [PreSignature]
toPreSignatures (Signatures sigs) = map toPreSignature sigs

instance ReportSchemaErrors m => FromJSON m PreSignature where
  fromJSON enc = do
    kId    <- fromJSField enc "keyid"
    method <- fromJSField enc "method"
    sig    <- fromJSField enc "sig"
    return PreSignature {
        presignature = B64.toByteString sig
      , presigMethod = method
      , presigKeyId  = KeyId kId
      }

instance Monad m => ToJSON m PreSignature where
  toJSON PreSignature{..} = mkObject [
         ("keyid"  , return $ JSString . keyIdString $ presigKeyId)
       , ("method" , toJSON $ presigMethod)
       , ("sig"    , toJSON $ B64.fromByteString presignature)
       ]

instance ( ReportSchemaErrors m
         , FromJSON m a
         ) => FromJSON m (UninterpretedSignatures a) where
  fromJSON envelope = do
    enc <- fromJSField envelope "signed"
    uninterpretedSigned     <- fromJSON enc
    uninterpretedSignatures <- fromJSField envelope "signatures"
    return UninterpretedSignatures{..}

instance (Monad m, ToJSON m a) => ToJSON m (UninterpretedSignatures a) where
  toJSON UninterpretedSignatures{..} = mkObject [
         ("signed"     , toJSON uninterpretedSigned)
       , ("signatures" , toJSON uninterpretedSignatures)
       ]
