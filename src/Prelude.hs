-- | Smooth over differences between various ghc versions by making older
-- preludes look like 4.6.0
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE CPP #-}
module Prelude (
    module P
#if !MIN_VERSION_base(4,6,0)
  , Applicative(..)
  , Monoid(..)
  , (<$>)
  , (<$)
#endif
  ) where

#if MIN_VERSION_base(4,6,0)
import "base" Prelude as P
#else
import "base" Prelude as P
import Control.Applicative
import Data.Monoid
#endif
