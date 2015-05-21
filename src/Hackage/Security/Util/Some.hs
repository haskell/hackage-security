-- | Hiding existentials
module Hackage.Security.Util.Some (
    Some(..)
  , typecheckSome
  ) where

import Hackage.Security.Util.TypedEmbedded

data Some f where
    Some :: (Eq (f a), Show (f a)) => f a -> Some f

deriving instance Show (Some f)

instance Typed f => Eq (Some f) where
    Some a == Some b =
      case unify (typeOf a) (typeOf b) of
        Just Refl -> a == b
        Nothing   -> False

typecheckSome :: Typed f => Some f -> Some (TypeOf f) -> Bool
typecheckSome (Some x) (Some typ) =
    case unify (typeOf x) typ of
      Just Refl -> True
      Nothing   -> False
