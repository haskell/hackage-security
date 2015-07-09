-- | Some very simple lens definitions (to avoid further dependencies)
--
-- Intended to be double-imported
-- > import Hackage.Security.Util.Lens (Lens)
-- > import qualified Hackage.Security.Util.Lens as Lens
module Hackage.Security.Util.Lens (
    -- * Generic definitions
    Lens
  , Lens'
  , get
  , modify
  , set
    -- * Specific lenses
  , lookupM
  ) where

import Control.Applicative
import Data.Functor.Identity

{-------------------------------------------------------------------------------
  General definitions
-------------------------------------------------------------------------------}

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

{-------------------------------------------------------------------------------
  Specific lenses
-------------------------------------------------------------------------------}

lookupM :: forall a b. (Eq a, Monoid b) => a -> Lens' [(a, b)] b
lookupM a f = go
  where
    go []                       = (\b'  -> [(a, b')]  ) <$> f mempty
    go ((a', b):xs) | a == a'   = (\b'  -> (a, b'):xs ) <$> f b
                    | otherwise = (\xs' -> (a', b):xs') <$> go xs
