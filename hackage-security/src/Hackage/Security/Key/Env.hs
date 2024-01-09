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
import Control.Monad
import Data.Map (Map)
import qualified Data.Map as Map

import Hackage.Security.Key
import Hackage.Security.Util.JSON
import Hackage.Security.Util.Some

{-------------------------------------------------------------------------------
  Main datatype
-------------------------------------------------------------------------------}

-- | A key environment is a mapping from key IDs to the corresponding keys.
--
-- It should satisfy the invariant that these key IDs actually match the keys;
-- see 'checkKeyEnvInvariant'.
newtype KeyEnv = KeyEnv {
    keyEnvMap :: Map KeyId (Some PublicKey)
  }
  deriving (Show)

-- | Verify that each key ID is mapped to a key with that ID
checkKeyEnvInvariant :: KeyEnv -> Bool
checkKeyEnvInvariant = all (uncurry go) . Map.toList . keyEnvMap
  where
    go :: KeyId -> Some PublicKey -> Bool
    go kId key = kId == someKeyId key

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

instance ReportSchemaErrors m => FromJSON m KeyEnv where
  fromJSON enc = do
    keyEnv <- KeyEnv <$> fromJSON enc
    -- We should really use 'validate', but that causes module import cycles.
    -- Sigh.
    unless (checkKeyEnvInvariant keyEnv) $
      expected "valid key environment" Nothing
    return keyEnv
