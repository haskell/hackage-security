module Hackage.Security.TUF.Targets (
    -- * TUF types
    Targets(..)
  , Delegations(..)
  , DelegationSpec(..)
  , Delegation(..)
    -- ** Util
  , targetsLookup
  ) where

import Hackage.Security.JSON
import Hackage.Security.Key
import Hackage.Security.Key.Env (KeyEnv)
import Hackage.Security.TUF.Common
import Hackage.Security.TUF.FileInfo
import Hackage.Security.TUF.FileMap (FileMap, TargetPath)
import Hackage.Security.TUF.Header
import Hackage.Security.TUF.Patterns
import Hackage.Security.TUF.Signed
import Hackage.Security.Util.Some
import qualified Hackage.Security.TUF.FileMap as FileMap

{-------------------------------------------------------------------------------
  TUF types
-------------------------------------------------------------------------------}

-- | Target metadata
--
-- Most target files do not need expiry dates because they are not subject to
-- change (and hence attacks like freeze attacks are not a concern).
data Targets = Targets {
    targetsVersion     :: FileVersion
  , targetsExpires     :: FileExpires
  , targetsTargets     :: FileMap
  , targetsDelegations :: Maybe Delegations
  }
  deriving (Show)

-- | Delegations
--
-- Much like the Root datatype, this must have an invariant that ALL used keys
-- (apart from the global keys, which are in the root key environment) must
-- be listed in 'delegationsKeys'.
data Delegations = Delegations {
    delegationsKeys  :: KeyEnv
  , delegationsRoles :: [DelegationSpec]
  }
  deriving (Show)

-- | Delegation specification
--
-- NOTE: This is a close analogue of 'RoleSpec'.
data DelegationSpec = DelegationSpec {
    delegationSpecKeys      :: [Some PublicKey]
  , delegationSpecThreshold :: KeyThreshold
  , delegation              :: Delegation
  }
  deriving (Show)

instance HasHeader Targets where
  fileVersion f x = (\y -> x { targetsVersion = y }) <$> f (targetsVersion x)
  fileExpires f x = (\y -> x { targetsExpires = y }) <$> f (targetsExpires x)

{-------------------------------------------------------------------------------
  Utility
-------------------------------------------------------------------------------}

targetsLookup :: TargetPath -> Targets -> Maybe FileInfo
targetsLookup fp Targets{..} = FileMap.lookup fp targetsTargets

{-------------------------------------------------------------------------------
  JSON
-------------------------------------------------------------------------------}

instance Monad m => ToJSON m DelegationSpec where
  toJSON DelegationSpec{delegation = Delegation fp name, ..} = mkObject [
        ("name"      , toJSON name)
      , ("keyids"    , return . JSArray . map writeKeyAsId $ delegationSpecKeys)
      , ("threshold" , toJSON delegationSpecThreshold)
      , ("path"      , toJSON fp)
      ]

instance MonadKeys m => FromJSON m DelegationSpec where
  fromJSON enc = do
    delegationName          <- fromJSField enc "name"
    delegationSpecKeys      <- mapM readKeyAsId =<< fromJSField enc "keyids"
    delegationSpecThreshold <- fromJSField enc "threshold"
    delegationPath          <- fromJSField enc "path"
    case parseDelegation delegationName delegationPath of
      Left  err        -> expected ("valid name/path combination: " ++ err) Nothing
      Right delegation -> return DelegationSpec{..}

-- NOTE: Unlike the Root object, the keys that are used to sign the delegations
-- are NOT listed inside the delegations, so the same "bootstrapping" problems
-- do not arise here.
instance Monad m => ToJSON m Delegations where
  toJSON Delegations{..} = mkObject [
        ("keys"  , toJSON delegationsKeys)
      , ("roles" , toJSON delegationsRoles)
      ]

instance MonadKeys m => FromJSON m Delegations where
  fromJSON enc = do
    delegationsKeys  <- fromJSField enc "keys"
    delegationsRoles <- fromJSField enc "roles"
    return Delegations{..}

instance Monad m => ToJSON m Targets where
  toJSON Targets{..} = mkObject $ mconcat [
      [ ("_type"       , return $ JSString "Targets")
      , ("version"     , toJSON targetsVersion)
      , ("expires"     , toJSON targetsExpires)
      , ("targets"     , toJSON targetsTargets)
      ]
    , [ ("delegations" , toJSON d) | Just d <- [ targetsDelegations ] ]
    ]

instance MonadKeys m => FromJSON m Targets where
  fromJSON enc = do
    verifyType enc "Targets"
    targetsVersion     <- fromJSField    enc "version"
    targetsExpires     <- fromJSField    enc "expires"
    targetsTargets     <- fromJSField    enc "targets"
    targetsDelegations <- fromJSOptField enc "delegations"
    return Targets{..}

-- TODO: This is okay right now because targets do not introduce additional
-- keys, but will no longer be okay once we have author keys.
instance MonadKeys m => FromJSON m (Signed Targets) where
  fromJSON = signedFromJSON
