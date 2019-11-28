-- | Some very simple lens definitions (to avoid further dependencies)
--
-- Intended to be double-imported
-- > import Hackage.Security.Util.Lens (Lens)
-- > import qualified Hackage.Security.Util.Lens as Lens
module Hackage.Security.Util.Lens (
    -- * Generic definitions
    Lens
  , Lens'
  , Traversal
  , Traversal'
  , get
  , over
  , set
  ) where

import Control.Applicative
import Data.Functor.Identity

{-------------------------------------------------------------------------------
  General definitions
-------------------------------------------------------------------------------}

-- | Polymorphic lens
type Lens s t a b = forall f. Functor f => LensLike f s t a b

-- | Monomorphic lens
type Lens' s a = Lens s s a a

-- | Polymorphic traversal
type Traversal s t a b = forall f. Applicative f => LensLike f s t a b

-- | Monomorphic traversal
type Traversal' s a = Traversal s s a a

type LensLike f s t a b = (a -> f b) -> s -> f t
type LensLike' f s a = LensLike f s s a a

get :: LensLike' (Const a) s a -> s -> a
get l = getConst . l Const

over :: LensLike Identity s t a b -> (a -> b) -> s -> t
over l f = runIdentity . l (Identity . f)

set :: LensLike Identity s t a b -> b -> s -> t
set l = over l . const
