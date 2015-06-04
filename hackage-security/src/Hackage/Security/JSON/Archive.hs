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
  , fromEntries
  ) where

import Prelude hiding (lookup)
import Control.Monad.Except
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

-- | Construct an archive from a set of JSON files
--
-- This verifies that the entries are valid JSON.
fromEntries :: FilePath   -- ^ Base directory
            -> [FilePath] -- ^ Files to add (relative to basedir)
            -> IO (Either String Archive)
fromEntries baseDir = runExceptT . fmap (A . Map.fromList) . mapM go
  where
    go :: FilePath -> ExceptT String IO (FilePath, JSValue)
    go fp = do
      bs <- lift $ BS.L.readFile (baseDir </> fp)
      case parseCanonicalJSON bs of
        Left  err -> throwError err
        Right val -> return (fp, val)

{-------------------------------------------------------------------------------
  JSON
-------------------------------------------------------------------------------}

instance ToJSON Archive where
  toJSON (A ar) = toJSON ar

instance ReportSchemaErrors m => FromJSON m Archive where
  fromJSON = fmap A . fromJSON
