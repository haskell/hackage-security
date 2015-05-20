module Hackage.Security.Client.Formats (
    -- * Formats
    -- ** Type level
    FormatUncompressed
  , FormatCompressedGz
    -- ** Term level
  , Format(..)
    -- * Products
  , FormatProd(..)
    -- ** Utility
  , formatProdZip
  , formatProdMap
  , formatProdPrefer
    -- * Sums
  , FormatSum(..)
    -- ** Utility
  , formatSumSome
  ) where

import Hackage.Security.Util.Some
import Hackage.Security.Util.Stack
import Hackage.Security.Util.TypedEmbedded

{-------------------------------------------------------------------------------
  Formats
-------------------------------------------------------------------------------}

data FormatUncompressed
data FormatCompressedGz

-- | Format is a singleton type (reflection between type and term level)
--
-- NOTE: In the future we might add further compression formats.
data Format :: * -> * where
    FormatUncompressed :: Format FormatUncompressed
    FormatCompressedGz :: Format FormatCompressedGz

deriving instance Eq   (Format f)
deriving instance Ord  (Format f)
deriving instance Show (Format f)

instance Unify Format where
    unify FormatUncompressed FormatUncompressed = Just Refl
    unify FormatCompressedGz FormatCompressedGz = Just Refl
    unify _                  _                  = Nothing

{-------------------------------------------------------------------------------
  Products
-------------------------------------------------------------------------------}

data FormatProd :: * -> * -> * where
    FN :: FormatProd () a
    FC :: Format f -> a -> FormatProd fs a -> FormatProd (f :- fs) a

deriving instance Eq   a => Eq   (FormatProd fs a)
deriving instance Ord  a => Ord  (FormatProd fs a)
deriving instance Show a => Show (FormatProd fs a)

instance Functor (FormatProd fs) where
  fmap g = formatProdMap (\_format -> g)

{-------------------------------------------------------------------------------
  Products: Utility
-------------------------------------------------------------------------------}

formatProdZip :: FormatProd fs a -> FormatProd fs b -> FormatProd fs (a, b)
formatProdZip FN          FN           = FN
formatProdZip (FC f a as) (FC _f b bs) = FC f (a, b) (formatProdZip as bs)
formatProdZip _           _            = error "inaccessible"

formatProdMap :: forall a b fs.
                 (forall f. Format f -> a -> b)
              -> FormatProd fs a -> FormatProd fs b
formatProdMap g = go
  where
    -- Type annotation required: polymorphic recursion
    go :: forall fs'. FormatProd fs' a -> FormatProd fs' b
    go FN          = FN
    go (FC f a as) = FC f (g f a) (go as)

-- | Select a preferred format from a list if available, or default to any
-- other format otherwise.
formatProdPrefer :: NonEmpty fs -> Format f -> FormatProd fs a -> (FormatSum fs, a)
formatProdPrefer NonEmpty f = go
  where
    go :: forall f' fs a. FormatProd (f' :- fs) a -> (FormatSum (f' :- fs), a)
    go (FC f' a pd) =
      case pd of
        FN       -> (FZ f', a) -- default
        FC _ _ _ -> case unify f f' of
                      Just Refl -> (FZ f, a)
                      Nothing   -> let (sm, a') = go pd in (FS sm, a')

{-------------------------------------------------------------------------------
  Sums
-------------------------------------------------------------------------------}

-- | Dual to FormatSum
--
-- The idea is that if we request, say, @FormatProd fs Foo@ the server will
-- pick one of the formats and respond with @FormatSum fs@, indicating which
-- format it picked.
--
-- NOTE: Unlike `FormatProd`, `FormatSum` does not carry a payload; there is
-- little point, since this is just a single format, and the type the payload
-- does not vary with the format chosen (for instance, see type of
-- 'formatProdPrefer').
data FormatSum :: * -> * where
    FZ :: Format f     -> FormatSum (f :- fs)
    FS :: FormatSum fs -> FormatSum (f :- fs)

formatSumSome :: FormatSum fs -> Some Format
formatSumSome (FZ f)  = Some f
formatSumSome (FS fs) = formatSumSome fs
