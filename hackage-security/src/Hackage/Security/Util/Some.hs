{-# LANGUAGE CPP #-}
-- | Hiding existentials
module Hackage.Security.Util.Some (
    Some(..)
    -- ** Equality
  , DictEq(..)
  , SomeEq(..)
    -- ** Serialization
  , DictShow(..)
  , SomeShow(..)
    -- ** Pretty-printing
  , DictPretty(..)
  , SomePretty(..)
    -- ** Type checking
  , typecheckSome
#if !MIN_VERSION_base(4,7,0)
    -- ** Compatibility with base < 4.7
  , tyConSome
#endif
  ) where

#if MIN_VERSION_base(4,7,0)
import Data.Typeable (Typeable)
#else
import qualified Data.Typeable as Typeable
#endif

import Hackage.Security.Util.TypedEmbedded
import Hackage.Security.Util.Pretty

data Some f = forall a. Some (f a)

#if MIN_VERSION_base(4,7,0)
deriving instance Typeable Some
#else
tyConSome :: Typeable.TyCon
tyConSome = Typeable.mkTyCon3 "hackage-security" "Hackage.Security.Util.Some" "Some"
#endif

{-------------------------------------------------------------------------------
  Equality on Some types

  Note that we cannot really do something similar for ordering; what value
  should we return for

  > Some (f x) `compare` Some (f x')

  where @x :: a@, @x' :: a'@ and @a /= a'@? These are incomparable.
-------------------------------------------------------------------------------}

data DictEq a where
  DictEq :: Eq a => DictEq a

-- | Type @f@ satisfies @SomeEq f@ if @f a@ satisfies @Eq@ independent of @a@
class SomeEq f where
  someEq :: DictEq (f a)

instance (Typed f, SomeEq f) => Eq (Some f) where
  Some (x :: f a) == Some (y :: f a') =
    case unify (typeOf x) (typeOf y) of
      Nothing   -> False
      Just Refl -> case someEq :: DictEq (f a) of DictEq -> x == y

{-------------------------------------------------------------------------------
  Showing Some types
-------------------------------------------------------------------------------}

data DictShow a where
  DictShow :: Show a => DictShow a

-- | Type @f@ satisfies @SomeShow f@ if @f a@ satisfies @Show@ independent of @a@
class SomeShow f where
  someShow :: DictShow (f a)

instance SomeShow f => Show (Some f) where
  show (Some (x :: f a)) =
    case someShow :: DictShow (f a) of DictShow -> show x

{-------------------------------------------------------------------------------
  Pretty-printing Some types
-------------------------------------------------------------------------------}

data DictPretty a where
  DictPretty :: Pretty a => DictPretty a

-- | Type @f@ satisfies @SomeShow f@ if @f a@ satisfies @Show@ independent of @a@
class SomePretty f where
  somePretty :: DictPretty (f a)

instance SomePretty f => Pretty (Some f) where
  pretty (Some (x :: f a)) =
    case somePretty :: DictPretty (f a) of DictPretty -> pretty x

{-------------------------------------------------------------------------------
  Typechecking Some types
-------------------------------------------------------------------------------}

typecheckSome :: Typed f => Some f -> Some (TypeOf f) -> Bool
typecheckSome (Some x) (Some typ) =
    case unify (typeOf x) typ of
      Just Refl -> True
      Nothing   -> False
