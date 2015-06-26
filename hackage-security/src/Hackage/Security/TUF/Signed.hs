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
  , verifySignature
    -- * JSON aids
  , signedFromJSON
  , verifySignatures
    -- * Ignoring signatures
  , IgnoreSigned(..)
  ) where

import Data.Functor.Identity
import qualified Data.ByteString      as BS
import qualified Data.ByteString.Lazy as BS.L
import qualified Data.Set             as Set

import Hackage.Security.JSON
import Hackage.Security.Key
import Hackage.Security.TUF.Layout
import Hackage.Security.Util.Some
import Text.JSON.Canonical
import qualified Hackage.Security.Util.Base64 as B64

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

-- | Construct signatures for already rendered value (internal function)
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
  toJSON (Signatures sigs) = toJSON sigs

instance Monad m => ToJSON m Signature where
  toJSON Signature{..} = mkObject [
         ("keyid"  , return $ writeKeyAsId signatureKey)
       , ("method" , toJSON $ somePublicKeyType signatureKey)
       , ("sig"    , toJSON $ B64.fromByteString signature)
       ]

instance MonadKeys m => FromJSON m Signatures where
  fromJSON enc = do
      preSigs <- fromJSON enc
      sigs    <- fromPreSignatures preSigs
      return $ Signatures sigs

{-------------------------------------------------------------------------------
  Auxiliary
-------------------------------------------------------------------------------}

-- | A signature with a key ID (rather than an actual key)
data PreSignature = PreSignature {
    presignature :: BS.ByteString
  , presigMethod :: Some KeyType
  , presigKeyId  :: KeyId
  }

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

fromPreSignature :: MonadKeys m => PreSignature -> m Signature
fromPreSignature PreSignature{..} = do
    key <- lookupKey presigKeyId
    validate "key type" $ typecheckSome key presigMethod
    return Signature {
        signature    = presignature
      , signatureKey = key
      }

-- | Convert a list of 'PreSignature's to a list of 'Signature's
--
-- This verifies the invariant that all signatures are made with different keys.
-- We do this on the presignatures rather than the signatures so that we can do
-- the check on key IDs, rather than keys (the latter don't have an Ord
-- instance).
fromPreSignatures :: MonadKeys m => [PreSignature] -> m [Signature]
fromPreSignatures sigs = do
      validate "all signatures made with different keys" $
        Set.size (Set.fromList (map presigKeyId sigs)) == length sigs
      mapM fromPreSignature sigs

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
  Ignoring signatures
-------------------------------------------------------------------------------}

-- | Sometimes we may want to ignore the signatures on a file
--
-- Perhaps we want to ignore the signatures because they have already been
-- verified (trusted local files). Moreover, many file formats (that don't
-- contain any other keys) can then be read without any key environment at all,
-- which is occassionally useful.
--
-- This is only relevant for _reading_ files, so this only has a 'FromJSON'
-- instance (and no 'ToJSON' instance).
newtype IgnoreSigned a = IgnoreSigned { ignoreSigned :: a }

instance (ReportSchemaErrors m, FromJSON m a) => FromJSON m (IgnoreSigned a) where
  fromJSON envelope = do
    enc          <- fromJSField envelope "signed"
    ignoreSigned <- fromJSON enc
    return IgnoreSigned{..}
