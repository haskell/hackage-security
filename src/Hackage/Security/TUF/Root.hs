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
  ) where

import Control.Exception
import Control.Monad.Except
import Data.Time
import Data.Typeable (Typeable)

import Hackage.Security.JSON
import Hackage.Security.Key
import Hackage.Security.Key.Env (KeyEnv)
import Hackage.Security.Key.ExplicitSharing
import Hackage.Security.Some
import Hackage.Security.Trusted.Unsafe
import Hackage.Security.TUF.Common
import Hackage.Security.TUF.FileInfo
import Hackage.Security.TUF.Signed
import Hackage.Security.TUF.Snapshot
import Hackage.Security.TUF.Targets
import Hackage.Security.TUF.Timestamp

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
  fileExpires = rootExpires

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
data VerificationError =
     -- | Not enough signatures signed with the appropriate keys
     VerificationErrorSignatures

     -- | The file is expired
   | VerificationErrorExpired

     -- | The file version is less than the previous version
   | VerificationErrorVersion

     -- | File information mismatch
   | VerificationErrorFileInfo

     -- | A file that we did not expect to be deleted got deleted
   | VerificationErrorFileDeleted
   deriving (Show, Typeable)

instance Exception VerificationError

-- | Verify (new) root info based on (old) root info
verifyRoot :: Trusted Root             -- ^ Trusted (old) root data
           -> Maybe (Trusted FileInfo) -- ^ Info for new root (if available)
           -> Maybe UTCTime            -- ^ Time now (if checking expiry)
           -> Signed Root              -- ^ New root data to verify
           -> Either VerificationError (Trusted Root)
verifyRoot oldRoot mInfo =
    verifyRole (rootRoleRoot oldRoot) mInfo (Just (fileVersion oldRoot))

-- | Verify a timestamp
verifyTimestamp :: Trusted Root      -- ^ Trusted root data
                -> Maybe FileVersion -- ^ Previous version (if available)
                -> Maybe UTCTime     -- ^ Time now (if checking expiry)
                -> Signed Timestamp  -- ^ Timestamp to verify
                -> Either VerificationError (Trusted Timestamp)
verifyTimestamp root =
    verifyRole (rootRoleTimestamp root) Nothing

-- | Verify snapshot
verifySnapshot :: Trusted Root       -- ^ Root data
               -> Trusted FileInfo   -- ^ File info (from the timestamp file)
               -> Maybe FileVersion  -- ^ Previous version (if available)
               -> Maybe UTCTime      -- ^ Time now (if checking expiry)
               -> Signed Snapshot    -- ^ Snapshot to verify
               -> Either VerificationError (Trusted Snapshot)
verifySnapshot root info =
    verifyRole (rootRoleSnapshot root) (Just info)

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
verifyRole :: forall a. (TUFHeader a, ToJSON a)
           => Trusted (RoleSpec a)     -- ^ For signature validation
           -> Maybe (Trusted FileInfo) -- ^ File info (if known)
           -> Maybe FileVersion        -- ^ Previous version (if available)
           -> Maybe UTCTime            -- ^ Time now (if checking expiry)
           -> Signed a -> Either VerificationError (Trusted a)
verifyRole (trusted -> RoleSpec{roleSpecThreshold = KeyThreshold threshold, ..})
           mFileInfo
           mPrev
           mNow
           Signed{..} =
    runExcept go
  where
    go :: Except VerificationError (Trusted a)
    go = do
      -- Verify file info
      case mFileInfo of
        Nothing   -> return ()
        Just info ->
          unless (verifyFileInfo info (fileInfoJSON signed)) $
            throwError VerificationErrorFileInfo

      -- Verify expiry date
      case mNow of
        Nothing  -> return ()
        Just now ->
          when (fileExpires signed < FileExpires now) $
            throwError VerificationErrorExpired

      -- Verify timestamp
      case mPrev of
        Nothing   -> return ()
        Just prev ->
          when (fileVersion signed < prev) $
            throwError VerificationErrorVersion

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
