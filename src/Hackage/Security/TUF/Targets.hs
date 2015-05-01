module Hackage.Security.TUF.Targets (
    Targets(..)
  ) where

import Data.Time

import Hackage.Security.TUF.Ints
import qualified Hackage.Security.TUF.FileMap (FileMap)

data Targets = Targets {
    targetsVersion :: Version
  , targetsExpires :: UTCTime
  , targets        :: FileMap
  }
