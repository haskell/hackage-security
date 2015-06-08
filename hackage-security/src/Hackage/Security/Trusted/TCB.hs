{-# LANGUAGE CPP #-}
module Hackage.Security.Trusted.TCB (
    -- * Trusted values
    Trusted(DeclareTrusted)
  , trusted
  , trustStatic
  , trustVerified
  , trustApply
  , trustSeq
    -- * Role verification
  , SignaturesVerified -- opaque
  , signaturesVerified
  , VerificationError(..)
  , verifyRole
  , verifyFingerprints
#if __GLASGOW_HASKELL__ >= 710
    -- * Re-exports
  , StaticPtr
#else
    -- * Fake static pointers
  , StaticPtr
  , static
#endif
  ) where

import Control.Exception
import Control.Monad.Except
import Data.Typeable
import Data.Time
import Hackage.Security.TUF
import Hackage.Security.Key
import qualified Hackage.Security.Util.Lens as Lens

#if __GLASGOW_HASKELL__ >= 710
import GHC.StaticPtr
#else
-- Fake static pointers for ghc < 7.10. This means Trusted offers no
-- additional type safety, but that's okay: we can still verify the code
-- with ghc 7.10 and get the additional checks.
newtype StaticPtr a = StaticPtr { deRefStaticPtr :: a }

static :: a -> StaticPtr a
static = StaticPtr
#endif

-- | Trusted values
--
-- Trusted values originate in only two ways:
--
-- * Anything that is statically known is trusted ('trustStatic')
-- * If we have "dynamic" data we can trust it once we have verified the
--   the signatures (trustSigned).
--
-- NOTE: Trusted is NOT a functor. If it was we could define
--
-- > trustAnything :: a -> Trusted a
-- > trustAnything a = fmap (const a) (trustStatic (static ()))
--
-- Consequently, it is neither a monad nor a comonad. However, we _can_ apply
-- trusted functions to trusted arguments ('trustApply').
--
-- The 'DeclareTrusted' constructor is exported, but any use of it should be
-- verified.
newtype Trusted a = DeclareTrusted { trusted :: a }
  deriving (Eq, Show)

trustStatic :: StaticPtr a -> Trusted a
trustStatic = DeclareTrusted . deRefStaticPtr

trustVerified :: SignaturesVerified a -> Trusted a
trustVerified = DeclareTrusted . signaturesVerified

-- | Equivalent of '<*>'
--
-- Trusted isn't quite applicative (no pure, not a functor), but it is
-- somehow Applicative-like: we have the equivalent of '<*>'
trustApply :: Trusted (a -> b) -> Trusted a -> Trusted b
trustApply (DeclareTrusted f) (DeclareTrusted x) = DeclareTrusted (f x)

-- | Equivalent of 'sequenceA'
--
-- Trusted isn't quite Traversable (no Functor instance), but it is
-- somehow Traversable-like: we have the equivalent of 'sequenceA'
trustSeq :: Functor f => Trusted (f a) -> f (Trusted a)
trustSeq (DeclareTrusted fa) = DeclareTrusted `fmap` fa

{-------------------------------------------------------------------------------
  Role verification
-------------------------------------------------------------------------------}

newtype SignaturesVerified a = SignaturesVerified { signaturesVerified :: a }

-- | Errors thrown during role validation
--
-- The string arguments to the various constructors are just here to give a
-- hint about which file caused the error.
data VerificationError =
     -- | Not enough signatures signed with the appropriate keys
     VerificationErrorSignatures

     -- | The file is expired
   | VerificationErrorExpired String

     -- | The file version is less than the previous version
   | VerificationErrorVersion String

     -- | File information mismatch
   | VerificationErrorFileInfo String

     -- | We tried to lookup file information about a particular target file,
     -- but the information wasn't in the corresponding @targets.json@ file.
   | VerificationErrorUnknownTarget String

     -- | The file we requested from the server was larger than expected
     -- (potential endless data attack)
   | VerificationErrorFileTooLarge String

     -- | The spec stipulates that if a verification error occurs during
     -- the check for updates, we must download new root information and
     -- start over. However, we limit how often we attempt this.
   | VerificationErrorLoop
   deriving (Show, Typeable)

instance Exception VerificationError

-- | Role verification
--
-- NOTE: We throw an error when the version number _decreases_, but allow it
-- to be the same. This is sufficient: the file number is there so that
-- attackers cannot replay old files. It cannot protect against freeze attacks
-- (that's what the expiry date is for), so "replaying" the same file is not
-- a problem. If an attacker changes the contents of the file but not the
-- version number we have an inconsistent situation, but this is not something
-- we need to worry about: in this case the attacker will need to resign the
-- file or otherwise the signature won't match, and if the attacker has
-- compromised the key then he might just as well increase the version number
-- and resign.
--
-- NOTE 2: We are not actually verifying the signatures _themselves_ here
-- (we did that when we parsed the JSON). We are merely verifying the provenance
-- of the keys.
verifyRole :: forall a. (HasHeader a, DescribeFile a)
           => Trusted (RoleSpec a)     -- ^ For signature validation
           -> Maybe FileVersion        -- ^ Previous version (if available)
           -> Maybe UTCTime            -- ^ Time now (if checking expiry)
           -> Signed a -> Either VerificationError (SignaturesVerified a)
verifyRole (trusted -> RoleSpec{roleSpecThreshold = KeyThreshold threshold, ..})
           mPrev
           mNow
           Signed{signatures = Signatures sigs, ..} =
    runExcept go
  where
    go :: Except VerificationError (SignaturesVerified a)
    go = do
      -- Verify expiry date
      case mNow of
        Just now ->
          when (isExpired now (Lens.get fileExpires signed)) $
            throwError $ VerificationErrorExpired (describeFile signed)
        _otherwise ->
          return ()

      -- Verify timestamp
      case mPrev of
        Nothing   -> return ()
        Just prev ->
          when (Lens.get fileVersion signed < prev) $
            throwError $ VerificationErrorVersion (describeFile signed)

      -- Verify signatures
      -- NOTE: We only need to verify the keys that were used; if the signature
      -- was invalid we would already have thrown an error constructing Signed.
      -- (Similarly, if two signatures were made by the same key, the FromJSON
      -- instance for Signatures would have thrown an error.)
      unless (length (filter isRoleSpecKey sigs) >= threshold) $
        throwError VerificationErrorSignatures

      -- Everything is A-OK!
      return $ SignaturesVerified signed

    isRoleSpecKey :: Signature -> Bool
    isRoleSpecKey Signature{..} = signatureKey `elem` roleSpecKeys

-- | Variation on 'verifyRole' that uses key IDs rather than keys
--
-- This is used during the bootstrap process.
--
-- See <http://en.wikipedia.org/wiki/Public_key_fingerprint>.
verifyFingerprints :: [KeyId]
                   -> KeyThreshold
                   -> Signed Root
                   -> Either VerificationError (SignaturesVerified Root)
verifyFingerprints fingerprints
                   (KeyThreshold threshold)
                   Signed{signatures = Signatures sigs, ..} =
    if length (filter isTrustedKey sigs) >= threshold
      then Right $ SignaturesVerified signed
      else Left $ VerificationErrorSignatures
  where
    isTrustedKey :: Signature -> Bool
    isTrustedKey Signature{..} = someKeyId signatureKey `elem` fingerprints
