-- | Wrapper around an arbitrary datatype that adds signatures
--
-- Note that in the spec there is explicit sharing of keys through key IDs;
-- we translate this to implicit sharing in our Haskell datatypes, with the
-- translation done in the JSON serialization/deserialization.
module Hackage.Security.Signed (
    Signed(..)
  , Signature(..)
  , unsigned
  , withSignatures
  , addSignature
  , verifySignature
  ) where

import qualified Data.ByteString      as BS
import qualified Data.ByteString.Lazy as BS.L

import Hackage.Security.Key
import Hackage.Security.JSON
import qualified Hackage.Security.Base64 as B64
import Text.JSON.Canonical

data Signed a = Signed {
    unsign     :: a
  , signatures :: [Signature]
  }

data Signature = Signature {
    signature    :: BS.ByteString
  , signatureKey :: Some PublicKey
  }

-- | Create a new document without any signatures
unsigned :: a -> Signed a
unsigned a = Signed { unsign = a, signatures = [] }

withSignatures :: ToJSON a => [Some Key] -> a -> Signed a
withSignatures []                = unsigned
withSignatures (Some key : keys) = addSignature key . withSignatures keys

-- | Add a new signature to a signed document
addSignature :: ToJSON a => Key typ -> Signed a -> Signed a
addSignature key doc = doc { signatures = newSignature : signatures doc }
  where
    newSignature = Signature {
        signature    = sign (privateKey key) . fst . renderJSON $ unsign doc
      , signatureKey = Some $ publicKey key
      }

verifySignature :: BS.L.ByteString -> Signature -> Bool
verifySignature inp Signature{signature = sig, signatureKey = Some pub} =
  verify pub inp sig

instance ToJSON a => ToJSON (Signed a) where
  toJSON Signed{..} = do
     unsign'     <- toJSON unsign
     signatures' <- toJSON signatures
     return $ JSObject [
         ("signed"     , unsign')
       , ("signatures" , signatures')
       ]

instance ToJSON Signature where
  toJSON Signature{..} = do
     keyid  <- writeKeyAsId signatureKey
     method <- toJSON (someKeyType signatureKey)
     sig    <- toJSON (B64.fromByteString signature)
     return $ JSObject [
         ("keyid"  , keyid)
       , ("method" , method)
       , ("sig"    , sig)
       ]

instance FromJSON Signature where
  fromJSON enc = do
      key    <- readKeyAsId =<< fromJSField enc "keyid"
      method <- fromJSField enc "method"
      sig    <- fromJSField enc "sig"
      validate "key type" $ someKeyType key == method
      return Signature {
          signature    = B64.toByteString sig
        , signatureKey = key
        }

instance FromJSON a => FromJSON (Signed a) where
  fromJSON enc = do
      unsign'    <- fromJSField enc "signed"
      -- Important that we fully decode signed' first in the case that it
      -- contains a key dictionary (which we might need to resolve signatures)
      unsign     <- fromJSON unsign'
      signatures <- fromJSField enc "signatures"

      -- Signature verification
      --
      -- NOTES:
      -- 1. Technically we are verifying the signatures against the JSON as
      --    parsed and then pretty-printed, as opposed to the original JSON.
      --    However, since this round-trip should be an identity this is OK
      --    (provided the JSON is well-formed. If it's not we'll get a syntax
      --    error instead of a key validation error, but that's also OK.)
      --    However, since we check the signature against the raw JSValue
      --    (as opposed to the translation from that JSValue to type @a@),
      --    we do not rely on any roundtripping properties of the translation
      --    in ToJSON/FromJSON.
      --
      -- 2. We verify that all signatures are valid, but we cannot verify (here)
      --    that these signatures are signed with the right key, or that we
      --    have a sufficient number of signatures. This will be the
      --    responsibility of the calling code.
      validate "signatures" $
        all (verifySignature (renderCanonicalJSON unsign')) signatures

      return Signed{..}
