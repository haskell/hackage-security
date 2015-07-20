-- | Heterogenous lists
module Hackage.Security.Util.Stack (
    (:-)(..)
  ) where

data h :- t = h :- t
  deriving (Eq, Show)
infixr 5 :-
