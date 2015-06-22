module Hackage.Security.Key.Env (
    KeyEnv -- opaque
  , keyEnvMap
    -- * Convenience constructors
  , fromPublicKeys
  , fromKeys
    -- * The usual accessors
  , empty
  , null
  , insert
  , lookup
  , union
  ) where

import Prelude hiding (lookup, null)
import Data.Map (Map)
import qualified Data.Map as Map

import Hackage.Security.JSON
import Hackage.Security.Key
import Hackage.Security.Util.Some

newtype KeyEnv = KeyEnv {
    keyEnvMap :: Map KeyId (Some PublicKey)
  }

{-------------------------------------------------------------------------------
  Convenience constructors
-------------------------------------------------------------------------------}

fromPublicKeys :: [Some PublicKey] -> KeyEnv
fromPublicKeys = KeyEnv . Map.fromList . map aux
  where
    aux :: Some PublicKey -> (KeyId, Some PublicKey)
    aux pub = (someKeyId pub, pub)

fromKeys :: [Some Key] -> KeyEnv
fromKeys = fromPublicKeys . map somePublicKey

{-------------------------------------------------------------------------------
  The usual accessors
-------------------------------------------------------------------------------}

empty :: KeyEnv
empty = KeyEnv Map.empty

null :: KeyEnv -> Bool
null (KeyEnv env) = Map.null env

insert :: Some PublicKey -> KeyEnv -> KeyEnv
insert key (KeyEnv env) = KeyEnv $ Map.insert (someKeyId key) key env

lookup :: KeyId -> KeyEnv -> Maybe (Some PublicKey)
lookup kId (KeyEnv env) = Map.lookup kId env

union :: KeyEnv -> KeyEnv -> KeyEnv
union (KeyEnv env) (KeyEnv env') = KeyEnv (env `Map.union` env')

{-------------------------------------------------------------------------------
  JSON
-------------------------------------------------------------------------------}

instance Monad m => ToJSON m KeyEnv where
  toJSON (KeyEnv keyEnv) = toJSON keyEnv

-- TODO: verify key ID matches
instance ReportSchemaErrors m => FromJSON m KeyEnv where
  fromJSON enc = KeyEnv <$> fromJSON enc
