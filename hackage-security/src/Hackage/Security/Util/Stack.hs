-- | Heterogenous lists
module Hackage.Security.Util.Stack (
    (:-)(..)
  ) where

import MyPrelude

data h :- t = h :- t
  deriving (Eq, Show)
infixr 5 :-
