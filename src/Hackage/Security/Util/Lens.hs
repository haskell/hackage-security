-- | Some very simple lens definitions (to avoid further dependencies)
--
-- Intended to be double-imported
-- > import Hackage.Security.Util.Lens (Lens)
-- > import qualified Hackage.Security.Util.Lens as Lens
module Hackage.Security.Util.Lens (
    Lens
  , Lens'
  , get
  , modify
  , set
  ) where

import Control.Applicative
import Data.Functor.Identity

-- | Polymorphic lens
type Lens s t a b = forall f. Functor f => (a -> f b) -> s -> f t

-- | Monomorphic lens
type Lens' s a = Lens s s a a

get :: Lens' s a -> s -> a
get l = getConst . l Const

modify :: Lens s t a b -> (a -> b) -> s -> t
modify l f = runIdentity . l (Identity . f)

set :: Lens s t a b -> b -> s -> t
set l = modify l . const
