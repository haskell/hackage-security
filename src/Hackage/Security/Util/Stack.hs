-- | Heterogenous lists
module Hackage.Security.Util.Stack (
    (:-)(..)
  , NonEmpty(..)
  ) where

data h :- t = h :- t
  deriving (Eq, Show)
infixr 5 :-

-- | Proof that a stack is non-empty
data NonEmpty :: * -> * where
  NonEmpty :: NonEmpty (f :- fs)

deriving instance Eq   (NonEmpty fs)
deriving instance Show (NonEmpty fs)
