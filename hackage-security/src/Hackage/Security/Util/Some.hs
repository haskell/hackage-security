{-# LANGUAGE CPP #-}
-- | Hiding existentials
module Hackage.Security.Util.Some (
    Some(..)
  , typecheckSome
#if !MIN_VERSION_base(4,7,0)
  , tyConSome
#endif
  ) where

#if MIN_VERSION_base(4,7,0)
import Data.Typeable (Typeable)
#else
import qualified Data.Typeable as Typeable
#endif

import Hackage.Security.Util.TypedEmbedded

data Some f where
    Some :: (Eq (f a), Show (f a)) => f a -> Some f

deriving instance Show (Some f)

#if MIN_VERSION_base(4,7,0)
deriving instance Typeable Some
#else
tyConSome :: Typeable.TyCon
tyConSome = Typeable.mkTyCon3 "hackage-security" "Hackage.Security.Util.Some" "Some"
#endif

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
