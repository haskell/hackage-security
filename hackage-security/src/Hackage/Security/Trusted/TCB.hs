{-# LANGUAGE CPP #-}
module Hackage.Security.Trusted.TCB (
    -- * Trusted values
    Trusted(DeclareTrusted)
  , trusted
  , trustStatic
  , trustVerified
  , trustApply
  , trustElems
    -- * Verification errors
  , VerificationError(..)
  , RootUpdated(..)
  , VerificationHistory
    -- * Role verification
  , SignaturesVerified -- opaque
  , signaturesVerified
  , verifyRole'
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
import Hackage.Security.JSON
import Hackage.Security.Key
import Hackage.Security.Util.Pretty
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

-- | Trust all elements of some trusted (traversable) container
--
-- If we have, say, a trusted list of values, we should be able to get a list
-- of trusted values out of it.
--
-- > trustElems :: Trusted [a] -> [Trusted a]
--
-- NOTE. It might appear that the more natural primitive to offer is a
-- 'sequenceA'-like operator such as
--
-- > trustSeq :: Applicative f => Trusted (f a) -> f (Trusted a)
--
-- However, this is unsound. To see this, consider that @((->) a)@ is
-- 'Applicative' (it's the reader monad); hence, we can instantiate 'trustSeq'
-- at
--
-- > trustSeq :: Trusted (a -> a) -> a -> Trusted a
--
-- and by passing @trustStatic (static id)@ make 'Trusted' a functor, which we
-- certainly don't want to do (see comments for 'Trusted').
--
-- So why is it okay when we insist on 'Traversable' rather than 'Applicative'?
-- To see this, it's instructive to consider how we might make a @((->) a)@ an
-- instance of 'Traversable'. If we define the domain of enumerable types as
--
-- > class Eq a => Enumerable a where
-- >   enumerate :: [a]
--
-- then we can make @((->) r)@ traversable by
--
-- > instance Enumerable r => Traversable ((->) r) where
-- >   sequenceA f = rebuild <$> sequenceA ((\r -> (r,) <$> f r) <$> enumerate)
-- >     where
-- >       rebuild :: [(r, a)] -> r -> a
-- >       rebuild fun arg = fromJust (lookup arg fun)
--
-- The idea is that if the domain of a function is enumerable, we can apply the
-- function to each possible input, collect the outputs, and construct a new
-- function by pairing the inputs with the outputs. I.e., if we had something of
-- type
--
-- > a -> IO b
--
-- and @a@ is enumerable, we just run the @IO@ action on each possible @a@ and
-- collect all @b@s to get a pure function @a -> b@. Of course, you probably
-- don't want to be doing that, but the point is that as far as the type system
-- is concerned you could.
--
-- In the context of 'Trusted', this means that we can derive
--
-- > enumPure :: Enumerable a => a -> Trusted a
--
-- but in a way this this makes sense anyway. If a domain is enumerable, it
-- would not be unreasonable to change @Enumerable@ to
--
-- > class Eq a => Enumerable a where
-- >   enumerate :: [StaticPtr a]
--
-- so we could define @enumPure@ as
--
-- > enumPure :: Enumerable a => a -> Trusted a
-- > enumPure x = trustStatic
-- >            $ fromJust (find ((== x) . deRefStaticPtr) enumerate)
--
-- In other words, we just enumerate the entire domain as trusted values
-- (because we defined them locally) and then return the one that matched the
-- untrusted value.
--
-- The conclusion from all of this is that the types of untrusted input  (like
-- the types of the TUF files we download from the server) should probably not
-- be considered enumerable.
trustElems :: Traversable f => Trusted (f a) -> f (Trusted a)
trustElems (DeclareTrusted fa) = DeclareTrusted `fmap` fa

{-------------------------------------------------------------------------------
  Role verification
-------------------------------------------------------------------------------}

newtype SignaturesVerified a = SignaturesVerified { signaturesVerified :: a }

-- | Errors thrown during role validation
data VerificationError =
     -- | Not enough signatures signed with the appropriate keys
     VerificationErrorSignatures TargetPath

     -- | The file is expired
   | VerificationErrorExpired TargetPath

     -- | The file version is less than the previous version
   | VerificationErrorVersion TargetPath

     -- | File information mismatch
   | VerificationErrorFileInfo TargetPath

     -- | We tried to lookup file information about a particular target file,
     -- but the information wasn't in the corresponding @targets.json@ file.
   | VerificationErrorUnknownTarget TargetPath

     -- | The metadata for the specified target is missing a SHA256
   | VerificationErrorMissingSHA256 TargetPath

     -- | Some verification errors materialize as deserialization errors
     --
     -- For example: if we try to deserialize a timestamp file but the timestamp
     -- key has been rolled over, deserialization of the file will fail with
     -- 'DeserializationErrorUnknownKey'.
   | VerificationErrorDeserialization TargetPath DeserializationError

     -- | The spec stipulates that if a verification error occurs during
     -- the check for updates, we must download new root information and
     -- start over. However, we limit how often we attempt this.
     --
     -- We record all verification errors that occurred before we gave up.
   | VerificationErrorLoop VerificationHistory
   deriving (Typeable)

-- | Root metadata updated (as part of the normal update process)
data RootUpdated = RootUpdated
  deriving (Typeable)

type VerificationHistory = [Either RootUpdated VerificationError]

#if MIN_VERSION_base(4,8,0)
deriving instance Show VerificationError
deriving instance Show RootUpdated
instance Exception VerificationError where displayException = pretty
instance Exception RootUpdated where displayException = pretty
#else
instance Exception VerificationError
instance Show VerificationError where show = pretty
instance Show RootUpdated where show = pretty
instance Exception RootUpdated
#endif

instance Pretty VerificationError where
  pretty (VerificationErrorSignatures file) =
      pretty file ++ " does not have enough signatures signed with the appropriate keys"
  pretty (VerificationErrorExpired file) =
      pretty file ++ " is expired"
  pretty (VerificationErrorVersion file) =
      "Version of " ++ pretty file ++ " is less than the previous version"
  pretty (VerificationErrorFileInfo file) =
      "Invalid hash for " ++ pretty file
  pretty (VerificationErrorUnknownTarget file) =
      pretty file ++ " not found in corresponding target metadata"
  pretty (VerificationErrorMissingSHA256 file) =
      "Missing SHA256 hash for " ++ pretty file
  pretty (VerificationErrorDeserialization file err) =
      "Could not deserialize " ++ pretty file ++ ": " ++ pretty err
  pretty (VerificationErrorLoop es) =
      "Verification loop. Errors in order:\n"
   ++ unlines (map (("  " ++) . either pretty pretty) es)

instance Pretty RootUpdated where
  pretty RootUpdated = "Root information updated"

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
verifyRole' :: forall a. HasHeader a
            => Trusted (RoleSpec a)     -- ^ For signature validation
            -> TargetPath               -- ^ File source (for error messages)
            -> Maybe FileVersion        -- ^ Previous version (if available)
            -> Maybe UTCTime            -- ^ Time now (if checking expiry)
            -> Signed a -> Either VerificationError (SignaturesVerified a)
verifyRole' (trusted -> RoleSpec{roleSpecThreshold = KeyThreshold threshold, ..})
            targetPath
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
            throwError $ VerificationErrorExpired targetPath
        _otherwise ->
          return ()

      -- Verify timestamp
      case mPrev of
        Nothing   -> return ()
        Just prev ->
          when (Lens.get fileVersion signed < prev) $
            throwError $ VerificationErrorVersion targetPath

      -- Verify signatures
      -- NOTE: We only need to verify the keys that were used; if the signature
      -- was invalid we would already have thrown an error constructing Signed.
      -- (Similarly, if two signatures were made by the same key, the FromJSON
      -- instance for Signatures would have thrown an error.)
      unless (length (filter isRoleSpecKey sigs) >= fromIntegral threshold) $
        throwError $ VerificationErrorSignatures targetPath

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
                   -> TargetPath      -- ^ For error messages
                   -> Signed Root
                   -> Either VerificationError (SignaturesVerified Root)
verifyFingerprints fingerprints
                   (KeyThreshold threshold)
                   targetPath
                   Signed{signatures = Signatures sigs, ..} =
    if length (filter isTrustedKey sigs) >= fromIntegral threshold
      then Right $ SignaturesVerified signed
      else Left $ VerificationErrorSignatures targetPath
  where
    isTrustedKey :: Signature -> Bool
    isTrustedKey Signature{..} = someKeyId signatureKey `elem` fingerprints
