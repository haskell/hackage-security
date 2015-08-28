module TestSuite.PrivateKeys (
    PrivateKeys(..)
  , createPrivateKeys
  , privateKeysEnv
  , privateKeysRoles
  ) where

-- stdlib
import Control.Monad

-- hackage-security
import Hackage.Security.Client
import Hackage.Security.Key.Env (KeyEnv)
import Hackage.Security.Util.Some
import qualified Hackage.Security.Key.Env as KeyEnv

{-------------------------------------------------------------------------------
  All private keys
-------------------------------------------------------------------------------}

data PrivateKeys = PrivateKeys {
      privateRoot      :: [Some Key]
    , privateTarget    :: [Some Key]
    , privateSnapshot  :: Some Key
    , privateTimestamp :: Some Key
    , privateMirrors   :: Some Key
    }

createPrivateKeys :: IO PrivateKeys
createPrivateKeys = do
    privateRoot      <- replicateM 3 $ createKey' KeyTypeEd25519
    privateTarget    <- replicateM 3 $ createKey' KeyTypeEd25519
    privateSnapshot  <- createKey' KeyTypeEd25519
    privateTimestamp <- createKey' KeyTypeEd25519
    privateMirrors   <- createKey' KeyTypeEd25519
    return PrivateKeys{..}

privateKeysEnv :: PrivateKeys -> KeyEnv
privateKeysEnv PrivateKeys{..} = KeyEnv.fromKeys $ concat [
      privateRoot
    , privateTarget
    , [privateSnapshot]
    , [privateTimestamp]
    , [privateMirrors]
    ]

privateKeysRoles :: PrivateKeys -> RootRoles
privateKeysRoles PrivateKeys{..} = RootRoles {
      rootRolesRoot      = RoleSpec {
          roleSpecKeys      = map somePublicKey privateRoot
        , roleSpecThreshold = KeyThreshold 2
        }
    , rootRolesSnapshot  = RoleSpec {
          roleSpecKeys      = [somePublicKey privateSnapshot]
        , roleSpecThreshold = KeyThreshold 1
        }
    , rootRolesTargets   = RoleSpec {
          roleSpecKeys      = map somePublicKey privateTarget
        , roleSpecThreshold = KeyThreshold 2
        }
    , rootRolesTimestamp = RoleSpec {
          roleSpecKeys      = [somePublicKey privateTimestamp]
        , roleSpecThreshold = KeyThreshold 1
        }
    , rootRolesMirrors   = RoleSpec {
          roleSpecKeys      = [somePublicKey privateMirrors]
        , roleSpecThreshold = KeyThreshold 1
        }
    }
