-- | Producing human-reaadable strings
module Hackage.Security.Util.Pretty (
    Pretty(..)
  ) where

import MyPrelude

-- | Produce a human-readable string
class Pretty a where
  pretty :: a -> String
