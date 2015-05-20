-- | The root filetype
module Hackage.Security.TUF.Root (
    -- * Datatypes
    Root(..)
  , RootRoles(..)
  , RoleSpec(..)
    -- * Accessing trusted information
  , rootRoleRoot
  , rootRoleSnapshot
  , rootRoleTargets
  , rootRoleTimestamp
    -- * Role verification
  , VerificationError(..)
  , verifyRoot
  , verifyTimestamp
  , verifySnapshot
    -- * Utility
  , formatVerificationError
  ) where

import Control.Exception
import Control.Monad.Except
import Data.Time
import Data.Typeable (Typeable)

import Hackage.Security.JSON
import Hackage.Security.Key
import Hackage.Security.Key.Env (KeyEnv)
import Hackage.Security.Key.ExplicitSharing
import Hackage.Security.Trusted.Unsafe
import Hackage.Security.TUF.Common
import Hackage.Security.TUF.Header
import Hackage.Security.TUF.Signed
import Hackage.Security.TUF.Snapshot
import Hackage.Security.TUF.Targets
import Hackage.Security.TUF.Timestamp
import Hackage.Security.Util.Some

{-------------------------------------------------------------------------------
  Datatypes
-------------------------------------------------------------------------------}

-- | The root metadata
--
-- NOTE: We must have the invariant that ALL keys (apart from delegation keys)
-- must be listed in 'rootKeys'. (Delegation keys satisfy a similar invariant,
-- see Targets.)
data Root = Root {
    rootVersion :: FileVersion
  , rootExpires :: FileExpires
  , rootKeys    :: KeyEnv
  , rootRoles   :: RootRoles
  }

data RootRoles = RootRoles {
    rootRolesRoot      :: RoleSpec Root
  , rootRolesSnapshot  :: RoleSpec Snapshot
  , rootRolesTargets   :: RoleSpec Targets
  , rootRolesTimestamp :: RoleSpec Timestamp
--, rootRolesMirrors   :: RoleSpec Mirrors    -- TODO
  }

-- | Role specification
--
-- The phantom type indicates what kind of type this role is meant to verify.
data RoleSpec a = RoleSpec {
    roleSpecKeys      :: [Some PublicKey]
  , roleSpecThreshold :: KeyThreshold
  }
  deriving (Show)

instance TUFHeader Root where
  fileVersion = rootVersion
  fileExpires = Just . rootExpires
  describeFile _ = "root"

{-------------------------------------------------------------------------------
  Accessing trusted information
-------------------------------------------------------------------------------}

rootRoleRoot :: Trusted Root -> Trusted (RoleSpec Root)
rootRoleRoot = DeclareTrusted . rootRolesRoot . rootRoles . trusted

rootRoleSnapshot :: Trusted Root -> Trusted (RoleSpec Snapshot)
rootRoleSnapshot = DeclareTrusted . rootRolesSnapshot . rootRoles . trusted

rootRoleTargets :: Trusted Root -> Trusted (RoleSpec Targets)
rootRoleTargets = DeclareTrusted . rootRolesTargets . rootRoles . trusted

rootRoleTimestamp :: Trusted Root -> Trusted (RoleSpec Timestamp)
rootRoleTimestamp = DeclareTrusted . rootRolesTimestamp . rootRoles . trusted

{-------------------------------------------------------------------------------
  Role verification
-------------------------------------------------------------------------------}

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

     -- | The spec stipulates that if a verification error occurs during
     -- the check for updates, we must download new root information and
     -- start over. However, we limit how often we attempt this.
   | VerificationErrorLoop
   deriving (Show, Typeable)

instance Exception VerificationError

-- | Verify (new) root info based on (old) root info
verifyRoot :: Trusted Root             -- ^ Trusted (old) root data
           -> Maybe UTCTime            -- ^ Time now (if checking expiry)
           -> Signed Root              -- ^ New root data to verify
           -> Either VerificationError (Trusted Root)
verifyRoot old = verifyRole (rootRoleRoot old) (Just (fileVersion old))

-- | Verify a timestamp
verifyTimestamp :: Trusted Root      -- ^ Trusted root data
                -> Maybe FileVersion -- ^ Previous version (if available)
                -> Maybe UTCTime     -- ^ Time now (if checking expiry)
                -> Signed Timestamp  -- ^ Timestamp to verify
                -> Either VerificationError (Trusted Timestamp)
verifyTimestamp root = verifyRole (rootRoleTimestamp root)

-- | Verify snapshot
verifySnapshot :: Trusted Root       -- ^ Root data
               -> Maybe FileVersion  -- ^ Previous version (if available)
               -> Maybe UTCTime      -- ^ Time now (if checking expiry)
               -> Signed Snapshot    -- ^ Snapshot to verify
               -> Either VerificationError (Trusted Snapshot)
verifySnapshot root = verifyRole (rootRoleSnapshot root)

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
verifyRole :: forall a. TUFHeader a
           => Trusted (RoleSpec a)     -- ^ For signature validation
           -> Maybe FileVersion        -- ^ Previous version (if available)
           -> Maybe UTCTime            -- ^ Time now (if checking expiry)
           -> Signed a -> Either VerificationError (Trusted a)
verifyRole (trusted -> RoleSpec{roleSpecThreshold = KeyThreshold threshold, ..})
           mPrev
           mNow
           Signed{..} =
    runExcept go
  where
    go :: Except VerificationError (Trusted a)
    go = do
      -- Verify expiry date
      case (mNow, fileExpires signed) of
        (Just now, Just expiry) ->
          when (isExpired now expiry) $
            throwError $ VerificationErrorExpired (describeFile signed)
        _otherwise ->
          return ()

      -- Verify timestamp
      case mPrev of
        Nothing   -> return ()
        Just prev ->
          when (fileVersion signed < prev) $
            throwError $ VerificationErrorVersion (describeFile signed)

      -- Verify signatures
      -- NOTE: We only need to verify the keys that were used; if the signature
      -- was invalid we would already have thrown an error constructing Signed.
      unless (length (filter isRoleSpecKey signatures) >= threshold) $
        throwError VerificationErrorSignatures

      -- Everything is A-OK!
      return $ DeclareTrusted signed

    isRoleSpecKey :: Signature -> Bool
    isRoleSpecKey Signature{..} = signatureKey `elem` roleSpecKeys

{-------------------------------------------------------------------------------
  Utility
-------------------------------------------------------------------------------}

formatVerificationError :: VerificationError -> String
formatVerificationError VerificationErrorSignatures =
    "Not enough signatures signed with the appropriate keys"
formatVerificationError (VerificationErrorExpired file) =
    file ++ " is expired"
formatVerificationError (VerificationErrorVersion file) =
    "Version of " ++ file ++ " is less than the previous version"
formatVerificationError (VerificationErrorFileInfo file) =
    "Invalid hash for " ++ file
formatVerificationError (VerificationErrorUnknownTarget file) =
    file ++ " not found in corresponding target metadata"
formatVerificationError VerificationErrorLoop =
    "Verification loop"

{-------------------------------------------------------------------------------
  JSON encoding
-------------------------------------------------------------------------------}

instance ToJSON RootRoles where
  toJSON RootRoles{..} = JSObject [
      ("root"      , toJSON rootRolesRoot)
    , ("snapshot"  , toJSON rootRolesSnapshot)
    , ("targets"   , toJSON rootRolesTargets)
    , ("timestamp" , toJSON rootRolesTimestamp)
    ]

instance FromJSON ReadJSON RootRoles where
  fromJSON enc = do
    rootRolesRoot      <- fromJSField enc "root"
    rootRolesSnapshot  <- fromJSField enc "snapshot"
    rootRolesTargets   <- fromJSField enc "targets"
    rootRolesTimestamp <- fromJSField enc "timestamp"
    return RootRoles{..}

instance ToJSON Root where
  toJSON Root{..} = JSObject [
         ("_type"   , JSString "Root")
       , ("version" , toJSON rootVersion)
       , ("expires" , toJSON rootExpires)
       , ("keys"    , toJSON rootKeys)
       , ("roles"   , toJSON rootRoles)
       ]

instance ToJSON (RoleSpec a) where
  toJSON RoleSpec{..} = JSObject [
        ("keyids"    , JSArray $ map writeKeyAsId roleSpecKeys)
      , ("threshold" , toJSON roleSpecThreshold)
      ]

-- | We give an instance for Signed Root rather than Root because the key
-- environment from the root data is necessary to resolve the explicit sharing
-- in the signatures.
instance FromJSON ReadJSON (Signed Root) where
  fromJSON envelope = do
    enc      <- fromJSField envelope "signed"
    rootKeys <- fromJSField enc      "keys"
    withKeys rootKeys $ do
      -- TODO: verify _type
      rootVersion <- fromJSField enc "version"
      rootExpires <- fromJSField enc "expires"
      rootRoles   <- fromJSField enc "roles"
      let signed = Root{..}

      signatures <- fromJSField envelope "signatures"
      validate "signatures" $ verifySignatures enc signatures
      return Signed{..}

instance FromJSON ReadJSON (RoleSpec a) where
  fromJSON enc = do
    roleSpecKeys      <- mapM readKeyAsId =<< fromJSField enc "keyids"
    roleSpecThreshold <- fromJSField enc "threshold"
    return RoleSpec{..}
