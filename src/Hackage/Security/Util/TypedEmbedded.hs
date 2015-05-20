-- | Embedded languages with meta level types
module Hackage.Security.Util.TypedEmbedded (
    (:=:)(Refl)
  , TypeOf
  , Unify(..)
  , Typed(..)
  , AsType(..)
  ) where

-- | Type equality proofs
--
-- This is a direct copy of "type-equality:Data.Type.Equality"; if we don't
-- mind the dependency we can use that package directly.
data a :=: b where
  Refl :: a :=: a

type family TypeOf (f :: * -> *) :: * -> *

-- | Equality check that gives us a type-level equality proof.
class Unify f where
  unify :: f typ -> f typ' -> Maybe (typ :=: typ')

-- | Embedded languages with type inference
class Unify (TypeOf f) => Typed f where
  typeOf :: f typ -> TypeOf f typ

-- | Cast from one type to another
--
-- By default (for language with type inference) we just compare the types
-- returned by 'typeOf'; however, in languages in which terms can have more
-- than one type this may not be the correct definition (indeed, for such
-- languages we cannot give an instance of 'Typed').
class AsType f where
  asType :: f typ -> TypeOf f typ' -> Maybe (f typ')
  default asType :: Typed f => f typ -> TypeOf f typ' -> Maybe (f typ')
  asType x typ = case unify (typeOf x) typ of
                   Just Refl -> Just x
                   Nothing   -> Nothing
