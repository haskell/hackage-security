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
    -- * Bootstrapping
  , readRootFile
  ) where

import Data.Time
import Data.Map (Map)
import qualified Data.Map             as Map
import qualified Data.ByteString.Lazy as BS.L

import Hackage.Security.JSON
import Hackage.Security.Key
import Hackage.Security.Key.Env (KeyEnv)
import Hackage.Security.Key.ExplicitSharing
import Hackage.Security.Some
import Hackage.Security.TUF.Ints
import Hackage.Security.TUF.Signed
import Text.JSON.Canonical
import qualified Hackage.Security.Key.Env as KeyEnv

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

data Root = Root {
    rootVersion :: Version
  , rootExpires :: UTCTime
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

instance Monad m => ToObjectKey m Role where
  toObjectKey RoleRoot      = return "root"
  toObjectKey RoleSnapshot  = return "snapshot"
  toObjectKey RoleTargets   = return "targets"
  toObjectKey RoleTimestamp = return "timestamp"
  toObjectKey RoleMirrors   = return "mirrors"

instance ReportSchemaErrors m => FromObjectKey m Role where
  fromObjectKey "root"      = return RoleRoot
  fromObjectKey "snapshot"  = return RoleSnapshot
  fromObjectKey "targets"   = return RoleTargets
  fromObjectKey "timestamp" = return RoleTimestamp
  fromObjectKey "mirrors"   = return RoleMirrors
  fromObjectKey _otherwise  = expected "valid role"

instance ToJSON WriteJSON Root where
  toJSON Root{..} = do
     rootVersion'   <- toJSON rootVersion
     rootExpires'   <- toJSON rootExpires
     rootRoles'     <- toJSON rootRoles -- mapM roleSpecPair (Map.toList rootRoles)
     keyDict        <- toJSON =<< getAccumulatedKeys
     return $ JSObject [
         ("_type"   , JSString "Root")
       , ("version" , rootVersion')
       , ("expires" , rootExpires')
       , ("keys"    , keyDict)
       , ("roles"   , rootRoles')
       ]

instance ToJSON WriteJSON RoleSpec where
  toJSON RoleSpec{..} = do
    roleSpecKeys'      <- mapM writeKeyAsId roleSpecKeys
    roleSpecThreshold' <- toJSON roleSpecThreshold
    return $ JSObject [
        ("keyids"    , JSArray roleSpecKeys')
      , ("threshold" , roleSpecThreshold')
      ]

instance FromJSON ReadJSON Root where
  fromJSON enc = do
    -- TODO: verify _type
    rootVersion <- fromJSField enc "version"
    rootExpires <- fromJSField enc "expires"
    rootRoles   <- fromJSField enc "roles"
    return Root{..}

instance FromJSON ReadJSON RoleSpec where
  fromJSON enc = do
    roleSpecKeys      <- mapM readKeyAsId =<< fromJSField enc "keyids"
    roleSpecThreshold <- fromJSField enc "threshold"
    return RoleSpec{..}

{-------------------------------------------------------------------------------
  Bootstrapping
-------------------------------------------------------------------------------}

-- | Read a root JSON value
--
-- The root JSON file is a bit different because it contains its own key
-- environment, so we need to extract this separately. We cannot extract it
-- locally in the ReadJSON instance for Root because although this environment
-- is defined inside the Root datatype, it is needed outside of it: both in the
-- Signed envelope around the root data (for the signatures), but also for
-- reading any of the other json files.
readRootFile :: FilePath -> IO (Either DeserializationError (Signed Root, KeyEnv))
readRootFile fp = go <$> BS.L.readFile fp
  where
    go :: BS.L.ByteString -> Either DeserializationError (Signed Root, KeyEnv)
    go bs =
      case parseCanonicalJSON bs of
        Left  err -> Left $ DeserializationErrorMalformed err
        Right enc -> runReadJSON KeyEnv.empty $ do
          signed  <- fromJSField enc    "signed"
          keyDict <- fromJSField signed "keys"
          root    <- addKeys keyDict $ fromJSON enc
          return (root, keyDict)
