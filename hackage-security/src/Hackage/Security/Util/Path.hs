-- | A more type-safe version of file paths
--
-- This module is intended to replace imports of System.FilePath, and
-- additionally exports thin wrappers around common IO functions.  To facilitate
-- importing this module unqualified we also re-export some  definitions from
-- System.IO (importing both would likely lead to name clashes).
--
-- Note that his module does not import any other modules from Hackage.Security;
-- everywhere else we use Path instead of FilePath directly.
module Hackage.Security.Util.Path (
    Path -- Opaque
  , filePath
  , path
  , (</>)
  , (<.>)
  , joinPath
  , takeDirectory
  , takeFileName
    -- * Wrappers around standard functions
    -- ** from System.IO
  , withFile
  , withBinaryFile
  , openTempFile
    -- ** from Data.ByteString.*
  , writeLazyByteString
  , readLazyByteString
  , readStrictByteString
    -- ** from System.Directory
  , createDirectoryIfMissing
  , copyFile
  , doesFileExist
  , removeFile
  , getTemporaryDirectory
    -- ** from Codec.Archive.Tar.*
  , tarPack
  , tarIndexLookup
    -- ** from Network.URI
  , uriPath
  , modifyUriPath
    -- * Re-exports
  , IO.IOMode(..)
  , IO.BufferMode(..)
  , IO.Handle
  , IO.hSetBuffering
  , IO.hClose
  , IO.hFileSize
  ) where

import qualified Data.ByteString         as BS
import qualified Data.ByteString.Lazy    as BS.L
import qualified System.FilePath         as FilePath
import qualified System.IO               as IO
import qualified System.Directory        as Dir
import qualified Codec.Archive.Tar       as Tar
import qualified Codec.Archive.Tar.Index as TarIndex
import qualified Network.URI             as URI

newtype Path = Path { filePath :: FilePath }
  deriving (Eq, Ord)

instance Show Path where
  show = filePath

path :: FilePath -> Path
path = Path

(</>) :: Path -> Path -> Path
Path p </> Path q = Path (p FilePath.</> q)

(<.>) :: Path -> String -> Path
Path p <.> ext = Path (p FilePath.<.> ext)

joinPath :: [Path] -> Path
joinPath = Path . FilePath.joinPath . map filePath

takeDirectory :: Path -> Path
takeDirectory (Path p) = Path $ FilePath.takeDirectory p

takeFileName :: Path -> Path
takeFileName (Path p) = Path $ FilePath.takeFileName p

{-------------------------------------------------------------------------------
  Wrappers around System.IO
-------------------------------------------------------------------------------}

withFile :: Path -> IO.IOMode -> (IO.Handle -> IO r) -> IO r
withFile = IO.withFile . filePath

withBinaryFile :: Path -> IO.IOMode -> (IO.Handle -> IO r) -> IO r
withBinaryFile = IO.withBinaryFile . filePath

openTempFile :: Path -> Path -> IO (Path, IO.Handle)
openTempFile (Path dir) (Path template) = aux <$> IO.openTempFile dir template
  where
    aux :: (FilePath, IO.Handle) -> (Path, IO.Handle)
    aux (fp, h) = (Path fp, h)

{-------------------------------------------------------------------------------
  Wrappers around Data.ByteString.*
-------------------------------------------------------------------------------}

writeLazyByteString :: Path -> BS.L.ByteString -> IO ()
writeLazyByteString = BS.L.writeFile . filePath

readLazyByteString :: Path -> IO BS.L.ByteString
readLazyByteString (Path p) = BS.L.readFile p

readStrictByteString :: Path -> IO BS.ByteString
readStrictByteString (Path p) = BS.readFile p

{-------------------------------------------------------------------------------
  Wrappers around System.Directory
-------------------------------------------------------------------------------}

createDirectoryIfMissing :: Bool -> Path -> IO ()
createDirectoryIfMissing createParents (Path p) =
    Dir.createDirectoryIfMissing createParents p

copyFile :: Path -> Path -> IO ()
copyFile (Path p) (Path q) = Dir.copyFile p q

doesFileExist :: Path -> IO Bool
doesFileExist (Path p) = Dir.doesFileExist p

removeFile :: Path -> IO ()
removeFile (Path p) = Dir.removeFile p

getTemporaryDirectory :: IO Path
getTemporaryDirectory = path <$> Dir.getTemporaryDirectory

{-------------------------------------------------------------------------------
  Wrappers around Codec.Archive.Tar.*
-------------------------------------------------------------------------------}

tarPack :: Path -> [Path] -> IO [Tar.Entry]
tarPack baseDir paths = Tar.pack (filePath baseDir) (map filePath paths)

tarIndexLookup :: TarIndex.TarIndex -> Path -> Maybe TarIndex.TarIndexEntry
tarIndexLookup index (Path p) = TarIndex.lookup index p

{-------------------------------------------------------------------------------
  Wrappers around Network.URI
-------------------------------------------------------------------------------}

uriPath :: URI.URI -> Path
uriPath uri = Path $ URI.uriPath uri

modifyUriPath :: URI.URI -> (Path -> Path) -> URI.URI
modifyUriPath uri f = uri { URI.uriPath = f' (URI.uriPath uri) }
  where
    f' :: FilePath -> FilePath
    f' = filePath . f . path
