module Hackage.Security.Client.Formats (
    -- * Formats
    -- ** Type level
    FormatUn
  , FormatGz
    -- ** Term level
  , Format(..)
  , Formats(..)
    -- * Key membership
  , HasFormat(..)
    -- ** Utility
  , hasFormatAbsurd
  , hasFormatGet
    -- * Map-like operations
  , formatsMap
  , formatsMember
  , formatsLookup
  ) where

import Hackage.Security.Util.Stack
import Hackage.Security.Util.TypedEmbedded

{-------------------------------------------------------------------------------
  Formats
-------------------------------------------------------------------------------}

data FormatUn
data FormatGz

-- | Format is a singleton type (reflection type to term level)
--
-- NOTE: In the future we might add further compression formats.
data Format :: * -> * where
  FUn :: Format FormatUn
  FGz :: Format FormatGz

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
  FsUn   :: a -> Formats (FormatUn :- ()) a
  FsGz   :: a -> Formats (FormatGz :- ()) a
  FsUnGz :: a -> a -> Formats (FormatUn :- FormatGz :- ()) a

deriving instance Eq   a => Eq   (Formats fs a)
deriving instance Show a => Show (Formats fs a)

instance Functor (Formats fs) where
  fmap g = formatsMap (\_format -> g)

{-------------------------------------------------------------------------------
  Key membership
-------------------------------------------------------------------------------}

-- | @HasFormat fs f@ is a proof that @f@ is a key in @fs@.
--
-- See 'formatsMember' and 'formatsLookup' for typical usage.
data HasFormat :: * -> * -> * where
  HFZ :: Format f       -> HasFormat (f  :- fs) f
  HFS :: HasFormat fs f -> HasFormat (f' :- fs) f

deriving instance Eq   (HasFormat fs f)
deriving instance Show (HasFormat fs f)

hasFormatAbsurd :: HasFormat () f -> a
hasFormatAbsurd _ = error "inaccessible"

hasFormatGet :: HasFormat fs f -> Format f
hasFormatGet (HFZ f)  = f
hasFormatGet (HFS hf) = hasFormatGet hf

{-------------------------------------------------------------------------------
  Map-like functionality
-------------------------------------------------------------------------------}

formatsMap :: (forall f. Format f -> a -> b) -> Formats fs a -> Formats fs b
formatsMap _ FsNone        = FsNone
formatsMap f (FsUn   a)    = FsUn   (f FUn a)
formatsMap f (FsGz   a)    = FsGz   (f FGz a)
formatsMap f (FsUnGz a a') = FsUnGz (f FUn a) (f FGz a')

formatsMember :: Format f -> Formats fs a -> Maybe (HasFormat fs f)
formatsMember _   FsNone       = Nothing
formatsMember FUn (FsUn   _  ) = Just $ HFZ FUn
formatsMember FUn (FsGz     _) = Nothing
formatsMember FUn (FsUnGz _ _) = Just $ HFZ FUn
formatsMember FGz (FsUn   _  ) = Nothing
formatsMember FGz (FsGz     _) = Just $ HFZ FGz
formatsMember FGz (FsUnGz _ _) = Just $ HFS (HFZ FGz)

formatsLookup :: HasFormat fs f -> Formats fs a -> a
formatsLookup (HFZ FUn) (FsUn   a  ) = a
formatsLookup (HFZ FUn) (FsUnGz a _) = a
formatsLookup (HFZ FGz) (FsGz     a) = a
formatsLookup (HFS hf)  (FsUn   _  ) = hasFormatAbsurd hf
formatsLookup (HFS hf)  (FsGz     _) = hasFormatAbsurd hf
formatsLookup (HFS hf)  (FsUnGz _ a) = formatsLookup hf (FsGz a)
