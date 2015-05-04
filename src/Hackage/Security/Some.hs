module Hackage.Security.Some (
    -- * Typed embedded languages
    (:=:)(Refl)
  , TypeOf
  , Unify(..)
  , Typed(..)
    -- * Hiding existentials
  , Some(..)
  , typecheckSome
  ) where

import Hackage.Security.JSON

{-------------------------------------------------------------------------------
  Embedded languages with meta level types
-------------------------------------------------------------------------------}

-- | Type equality proofs
--
-- This is a direct copy of "type-equality:Data.Type.Equality"; if we don't
-- mind the dependency we can use that package directly.
data a :=: b where
  Refl :: a :=: a

type family TypeOf (f :: * -> *) :: * -> *

class Unify f where
  unify :: f typ -> f typ' -> Maybe (typ :=: typ')

class Unify (TypeOf f) => Typed f where
  typeOf :: f typ -> TypeOf f typ

{-
class TypeCheck f where
  typecheck ::
-}

{-------------------------------------------------------------------------------
  Hiding existentials
-------------------------------------------------------------------------------}

data Some key where
    Some :: ( Eq     (key typ)
            , Ord    (key typ)
            , ToJSON (key typ)
            ) => key typ -> Some key

instance ToJSON (Some key) where
    toJSON (Some a) = toJSON a

instance Typed f => Eq (Some f) where
    Some a == Some b =
      case unify (typeOf a) (typeOf b) of
        Just Refl -> a == b
        Nothing   -> False

instance Typed f => Ord (Some f) where
    Some a <= Some b =
      case unify (typeOf a) (typeOf b) of
        Just Refl -> a <= b
        Nothing   -> False

typecheckSome :: Typed f => Some f -> Some (TypeOf f) -> Bool
typecheckSome (Some x) (Some typ) =
    case unify (typeOf x) typ of
      Just Refl -> True
      Nothing   -> False
