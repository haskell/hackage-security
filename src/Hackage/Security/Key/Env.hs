module Hackage.Security.Key.Env (
    KeyEnv -- opaque
  , keyEnvMap
  , empty
  , insert
  , lookup
  ) where

import Prelude hiding (lookup)
import Data.Map (Map)
import qualified Data.Map as Map

import Hackage.Security.JSON
import Hackage.Security.Key
import Hackage.Security.Some

newtype KeyEnv = KeyEnv {
    keyEnvMap :: Map KeyId (Some PublicKey)
  }

{-------------------------------------------------------------------------------
  The usual accessors
-------------------------------------------------------------------------------}

empty :: KeyEnv
empty = KeyEnv Map.empty

insert :: Some PublicKey -> KeyEnv -> KeyEnv
insert key (KeyEnv env) = KeyEnv $ Map.insert (someKeyId key) key env

lookup :: KeyId -> KeyEnv -> Maybe (Some PublicKey)
lookup kId (KeyEnv env) = Map.lookup kId env

{-------------------------------------------------------------------------------
  JSON
-------------------------------------------------------------------------------}

instance Monad m => ToJSON m KeyEnv where
  toJSON (KeyEnv keyEnv) = toJSON keyEnv

-- TODO: verify key ID matches
instance ReportSchemaErrors m => FromJSON m KeyEnv where
  fromJSON enc = KeyEnv <$> fromJSON enc
