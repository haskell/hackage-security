-- | The root filetype
module Hackage.Security.TUF.Root (
    -- * Datatypes
    Role(..)
  , Root(..)
  , RoleSpec(..)
    -- * Utility
  , roleTimestamp
  , roleSnapshot
  , verifyThreshold
  ) where

import Data.Time
import Data.Map (Map)
import qualified Data.Map as Map

import Hackage.Security.JSON
import Hackage.Security.Key
import Hackage.Security.Key.Env (KeyEnv)
import Hackage.Security.Key.ExplicitSharing
import Hackage.Security.Some
import Hackage.Security.TUF.Ints
import Hackage.Security.TUF.Signed

{-------------------------------------------------------------------------------
  Datatypes
-------------------------------------------------------------------------------}

data Role =
    RoleRoot
  | RoleSnapshot
  | RoleTargets
  | RoleTimestamp
  | RoleMirrors
  deriving (Eq, Ord)

-- | The root metadata
--
-- NOTE: We must have the invariant that ALL keys (apart from delegation keys)
-- must be listed in rootKeys. (Delegation keys satisfy a similar invariant,
-- see Targets.)
data Root = Root {
    rootVersion :: Version
  , rootExpires :: UTCTime
  , rootKeys    :: KeyEnv
  , rootRoles   :: Map Role RoleSpec
  }

data RoleSpec = RoleSpec {
    roleSpecKeys      :: [Some PublicKey]
  , roleSpecThreshold :: KeyThreshold
  }

{-------------------------------------------------------------------------------
  Utility
-------------------------------------------------------------------------------}

-- | Get the specification for the timestamp role
--
-- TODO: Perhaps we should change the representation of roles so that we
-- guarantee at the type level that this role specification exists.
roleTimestamp :: Root -> RoleSpec
roleTimestamp Root{..} = rootRoles Map.! RoleTimestamp

-- | Get the specification for the snapshot role
roleSnapshot :: Root -> RoleSpec
roleSnapshot Root{..} = rootRoles Map.! RoleSnapshot

-- | Verify that we have at least 'roleSpecThreshold' signatures signed by
-- 'roleSpecKeys'.
--
-- This does NOT verify the signatures themselves.
verifyThreshold :: RoleSpec -> [Signature] -> Bool
verifyThreshold RoleSpec{roleSpecThreshold = KeyThreshold threshold, ..} sigs =
    length (filter isRoleSpecKey sigs) >= threshold
  where
    isRoleSpecKey :: Signature -> Bool
    isRoleSpecKey Signature{..} = signatureKey `elem` roleSpecKeys

{-------------------------------------------------------------------------------
  JSON encoding
-------------------------------------------------------------------------------}

instance ToObjectKey Role where
  toObjectKey RoleRoot      = "root"
  toObjectKey RoleSnapshot  = "snapshot"
  toObjectKey RoleTargets   = "targets"
  toObjectKey RoleTimestamp = "timestamp"
  toObjectKey RoleMirrors   = "mirrors"

instance ReportSchemaErrors m => FromObjectKey m Role where
  fromObjectKey "root"      = return RoleRoot
  fromObjectKey "snapshot"  = return RoleSnapshot
  fromObjectKey "targets"   = return RoleTargets
  fromObjectKey "timestamp" = return RoleTimestamp
  fromObjectKey "mirrors"   = return RoleMirrors
  fromObjectKey _otherwise  = expected "valid role"

instance ToJSON Root where
  toJSON Root{..} = JSObject [
         ("_type"   , JSString "Root")
       , ("version" , toJSON rootVersion)
       , ("expires" , toJSON rootExpires)
       , ("keys"    , toJSON rootKeys)
       , ("roles"   , toJSON rootRoles)
       ]

instance ToJSON RoleSpec where
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

instance FromJSON ReadJSON RoleSpec where
  fromJSON enc = do
    roleSpecKeys      <- mapM readKeyAsId =<< fromJSField enc "keyids"
    roleSpecThreshold <- fromJSField enc "threshold"
    return RoleSpec{..}
