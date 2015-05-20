-- | Wrapper around an arbitrary datatype that adds signatures
--
-- Note that in the spec there is explicit sharing of keys through key IDs;
-- we translate this to implicit sharing in our Haskell datatypes, with the
-- translation done in the JSON serialization/deserialization.
module Hackage.Security.TUF.Signed (
    -- * TUF types
    Signed(..)
  , Signature(..)
    -- * Construction and verification
  , unsigned
  , withSignatures
  , addSignature
  , verifySignature
    -- * JSON aids
  , signedFromJSON
  , verifySignatures
  ) where

import qualified Data.ByteString      as BS
import qualified Data.ByteString.Lazy as BS.L

import Hackage.Security.JSON
import Hackage.Security.Key
import Hackage.Security.Key.ExplicitSharing
import Hackage.Security.Util.Some
import Text.JSON.Canonical
import qualified Hackage.Security.Base64 as B64

data Signed a = Signed {
    signed     :: a
  , signatures :: [Signature]
  }

data Signature = Signature {
    signature    :: BS.ByteString
  , signatureKey :: Some PublicKey
  }

-- | Create a new document without any signatures
unsigned :: a -> Signed a
unsigned a = Signed { signed = a, signatures = [] }

withSignatures :: ToJSON a => [Some Key] -> a -> Signed a
withSignatures []                = unsigned
withSignatures (Some key : keys) = addSignature key . withSignatures keys

-- | Add a new signature to a signed document
addSignature :: ToJSON a => Key typ -> Signed a -> Signed a
addSignature key doc = doc { signatures = newSignature : signatures doc }
  where
    newSignature = Signature {
        signature    = sign (privateKey key) . renderJSON $ signed doc
      , signatureKey = Some $ publicKey key
      }

verifySignature :: BS.L.ByteString -> Signature -> Bool
verifySignature inp Signature{signature = sig, signatureKey = Some pub} =
  verify pub inp sig

instance ToJSON a => ToJSON (Signed a) where
  toJSON Signed{..} = JSObject [
         ("signed"     , toJSON signed)
       , ("signatures" , toJSON signatures)
       ]

instance ToJSON Signature where
  toJSON Signature{..} = JSObject [
         ("keyid"  , writeKeyAsId signatureKey)
       , ("method" , toJSON $ somePublicKeyType signatureKey)
       , ("sig"    , toJSON $ B64.fromByteString signature)
       ]

instance FromJSON ReadJSON Signature where
  fromJSON enc = do
      key    <- readKeyAsId =<< fromJSField enc "keyid"
      method <- fromJSField enc "method"
      sig    <- fromJSField enc "sig"
      validate "key type" $ typecheckSome key method
      return Signature {
          signature    = B64.toByteString sig
        , signatureKey = key
        }

{-------------------------------------------------------------------------------
  JSON aids
-------------------------------------------------------------------------------}

-- | General FromJSON instance for signed datatypes
--
-- We don't give a general FromJSON instance for Signed because for some
-- datatypes we need to do something special (datatypes where we need to
-- read key environments); for instance, see the "Signed Root" instance.
signedFromJSON :: FromJSON ReadJSON a => JSValue -> ReadJSON (Signed a)
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
verifySignatures :: JSValue -> [Signature] -> Bool
verifySignatures = all . verifySignature . renderCanonicalJSON
