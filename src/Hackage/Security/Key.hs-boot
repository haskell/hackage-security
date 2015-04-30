{-# LANGUAGE CPP #-}
module Hackage.Security.Key where

data KeyId
data PublicKey (typ :: *)
data Some (key :: * -> *)
data KeyEnv

instance Ord  KeyId
instance Show KeyId

class HasKeyId key where
  keyId :: key typ -> KeyId

instance HasKeyId PublicKey

someKeyId    :: HasKeyId key => Some key -> KeyId
keyEnvEmpty  :: KeyEnv
keyEnvInsert :: Some PublicKey -> KeyEnv -> KeyEnv
keyEnvLookup :: KeyId -> KeyEnv -> Maybe (Some PublicKey)

#if __GLASGOW_HASKELL__ >= 708
type role PublicKey nominal
type role Some nominal
#endif
