-- | An archive of multiple JSON encoded files
--
-- This is intended to be double-imported:
-- > import Hackage.Security.JSON.Archive (Archive)
-- > import qualified Hackage.Security.JSON.Archive as Archive
module Hackage.Security.JSON.Archive (
    Archive -- opaque
    -- * Map-like accessors
  , empty
  , insert
  , lookup
    -- * I/O
  , writeEntries
  ) where

import Prelude hiding (lookup)
import Data.Map (Map)
import System.FilePath
import qualified Data.ByteString.Lazy as BS.L
import qualified Data.Map             as Map

import Hackage.Security.JSON
import Text.JSON.Canonical

newtype Archive = A (Map FilePath JSValue)

{-------------------------------------------------------------------------------
  Map-like accessors
-------------------------------------------------------------------------------}

empty :: Archive
empty = A Map.empty

insert :: ToJSON a => FilePath -> a -> Archive -> Archive
insert fp a (A ar) = A $ Map.insert fp (toJSON a) ar

lookup :: FromJSON m a => FilePath -> Archive -> Maybe (m a)
lookup fp (A ar) = fromJSON <$> Map.lookup fp ar

{-------------------------------------------------------------------------------
  I/O
-------------------------------------------------------------------------------}

-- | Write each entry in the archive to its corresponding path
writeEntries :: FilePath  -- ^ Base directory
             -> Archive -> IO ()
writeEntries baseDir (A ar) = mapM_ go $ Map.toList ar
  where
    go :: (FilePath, JSValue) -> IO ()
    go (fp, val) = BS.L.writeFile (baseDir </> fp) (renderCanonicalJSON val)

{-------------------------------------------------------------------------------
  JSON
-------------------------------------------------------------------------------}

instance ToJSON Archive where
  toJSON (A ar) = toJSON ar

instance ReportSchemaErrors m => FromJSON m Archive where
  fromJSON = fmap A . fromJSON
