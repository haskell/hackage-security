module Hackage.Security.Client.Formats (
    -- * Formats
    -- ** Type level
    FormatUncompressed
  , FormatCompressedGz
    -- ** Term level
  , Format(..)
    -- * Products
  , Formats(..)
    -- ** Utility
  , formatsZip
  , formatsMap
  , formatsList
  , formatsLookup
  , formatsHead
  , formatsPrefer
  , formatsCompressed
  , formatsUncompressed
    -- * Sums
  , SelectedFormat(..)
    -- ** Utility
  , selectedFormatSome
  ) where

import Data.Maybe (fromMaybe)

import Hackage.Security.Util.Some
import Hackage.Security.Util.Stack
import Hackage.Security.Util.TypedEmbedded

{-------------------------------------------------------------------------------
  Formats
-------------------------------------------------------------------------------}

data FormatUncompressed
data FormatCompressedGz

-- | Format is a singleton type (reflection type to term level)
--
-- NOTE: In the future we might add further compression formats.
data Format :: * -> * where
    FUn :: Format FormatUncompressed
    FGz :: Format FormatCompressedGz

deriving instance Show (Format f)
deriving instance Eq   (Format f)

instance Unify Format where
    unify FUn FUn = Just Refl
    unify FGz FGz = Just Refl
    unify _   _   = Nothing

{-------------------------------------------------------------------------------
  Products
-------------------------------------------------------------------------------}

-- | Available formats
--
-- Rather than having a general list here, we enumerate all possibilities.
-- This means we are very precise about what we expect, and we avoid any runtime
-- errors about unexpect format definitions.
--
-- NOTE: If we add additional cases here (for dealing with additional formats)
-- all calls to @error "inaccessible"@ need to be reevaluated.
data Formats :: * -> * -> * where
  FsNone :: Formats () a
  FsUn   :: a -> Formats (FormatUncompressed :- ()) a
  FsGz   :: a -> Formats (FormatCompressedGz :- ()) a
  FsUnGz :: a -> a -> Formats (FormatUncompressed :- FormatCompressedGz :- ()) a

deriving instance Eq   a => Eq   (Formats fs a)
deriving instance Show a => Show (Formats fs a)

instance Functor (Formats fs) where
  fmap g = formatsMap (\_format -> g)

{-------------------------------------------------------------------------------
  Utility
-------------------------------------------------------------------------------}

formatsZip :: Formats fs a -> Formats fs b -> Formats fs (a, b)
formatsZip FsNone        FsNone        = FsNone
formatsZip (FsUn   a)    (FsUn   b)    = FsUn (a, b)
formatsZip (FsGz   a)    (FsGz   b)    = FsGz (a, b)
formatsZip (FsUnGz a a') (FsUnGz b b') = FsUnGz (a, b) (a', b')
formatsZip _            _              = error "inaccessible"

formatsMap :: (forall f. Format f -> a -> b) -> Formats fs a -> Formats fs b
formatsMap _ FsNone        = FsNone
formatsMap f (FsUn   a)    = FsUn   (f FUn a)
formatsMap f (FsGz   a)    = FsGz   (f FGz a)
formatsMap f (FsUnGz a a') = FsUnGz (f FUn a) (f FGz a')

formatsList :: Formats fs a -> [(SelectedFormat fs, a)]
formatsList FsNone        = []
formatsList (FsUn   a)    = [(SZ FUn, a)]
formatsList (FsGz   a)    = [(SZ FGz, a)]
formatsList (FsUnGz a a') = [(SZ FUn, a), (SS (SZ FGz), a')]

formatsLookup :: Format f -> Formats fs a -> Maybe (SelectedFormat fs, a)
formatsLookup f = go . formatsList
  where
    go :: [(SelectedFormat fs, a)] -> Maybe (SelectedFormat fs, a)
    go []           = Nothing
    go ((sf, a):as) = case selectedFormatSome sf of
                        Some f' -> case unify f f' of
                                     Just Refl -> Just (sf, a)
                                     Nothing   -> go as

formatsHead :: NonEmpty fs -> Formats fs a -> (SelectedFormat fs, a)
formatsHead NonEmpty (FsUn   a)   = (SZ FUn, a)
formatsHead NonEmpty (FsGz   a)   = (SZ FGz, a)
formatsHead NonEmpty (FsUnGz a _) = (SZ FUn, a)
formatsHead _ _ = error "inaccessible"

formatsPrefer :: NonEmpty fs -> Format f -> Formats fs a -> (SelectedFormat fs, a)
formatsPrefer pne f fs = fromMaybe (formatsHead pne fs) (formatsLookup f fs)

-- | Find (any) compressed format
formatsCompressed :: Formats fs a -> Maybe (SelectedFormat fs, a)
formatsCompressed = formatsLookup FGz

-- | Find uncompressed format
formatsUncompressed :: Formats fs a -> Maybe a
formatsUncompressed = fmap snd . formatsLookup FUn

{-------------------------------------------------------------------------------
  Sums
-------------------------------------------------------------------------------}

data SelectedFormat :: * -> * where
    SZ :: Format f -> SelectedFormat (f :- fs)
    SS :: SelectedFormat fs -> SelectedFormat (f :- fs)

{-------------------------------------------------------------------------------
  Sums: Utility
-------------------------------------------------------------------------------}

selectedFormatSome :: SelectedFormat fs -> Some Format
selectedFormatSome (SZ f)  = Some f
selectedFormatSome (SS fs) = selectedFormatSome fs
