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
    Path              -- opaque
  , Rooted            -- opaque
  , IsRoot            -- opaque
  , IsFileSystemRoot  -- opaque
  , Unrooted          -- empty type
  , LocalDir          -- empty type
  , Absolute          -- empty type
  , WebRoot           -- empty type
  , Fragment
    -- ** Synonyms for convenience
  , AbsolutePath
  , UnrootedPath
    -- * Constructing and deconstructing Paths
  , fragment
  , rootPath
  , (</>)
  , (<.>)
    -- * Conversion between Path and FilePath
  , toFilePath
  , fromFilePath
  , toUnrootedFilePath
  , fromUnrootedFilePath
    -- * FilePath-like operations
  , splitFragments
  , joinFragments
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

import Data.Function (on)
import qualified Data.ByteString         as BS
import qualified Data.ByteString.Lazy    as BS.L
import qualified System.FilePath         as FilePath
import qualified System.IO               as IO
import qualified System.Directory        as Dir
import qualified Codec.Archive.Tar       as Tar
import qualified Codec.Archive.Tar.Index as TarIndex
import qualified Network.URI             as URI

{-------------------------------------------------------------------------------
  Types
-------------------------------------------------------------------------------}

data Unrooted
data LocalDir
data Absolute
data WebRoot

data Rooted a where
    RootLocalDir :: Rooted LocalDir
    RootAbsolute :: Rooted Absolute
    RootWebRoot  :: Rooted WebRoot

deriving instance Show (Rooted root)

class IsRoot root where
  singRoot :: Rooted root

instance IsRoot LocalDir where singRoot = RootLocalDir
instance IsRoot Absolute where singRoot = RootAbsolute
instance IsRoot WebRoot  where singRoot = RootWebRoot

class IsRoot root => IsFileSystemRoot root where
  rootFilePath :: Rooted root -> FilePath -> FilePath

instance IsFileSystemRoot LocalDir where rootFilePath _ = ("." FilePath.</>)
instance IsFileSystemRoot Absolute where rootFilePath _ = ("/" FilePath.</>)

type Fragment = String

-- | Paths
--
-- A path consists of an optional root and a list of fragments.
-- Alternatively, think of it as a list with two kinds of nil-constructors.
data Path a where
    PathRoot :: IsRoot root => Path (Rooted root)
    PathNil  :: Path Unrooted
    PathSnoc :: Path a -> Fragment -> Path a

deriving instance Show (Path a)

instance Eq UnrootedPath where
  (==) = (==) `on` splitFragments

instance Ord UnrootedPath where
  (<=) = (<=) `on` splitFragments

type AbsolutePath = Path (Rooted Absolute)
type UnrootedPath = Path Unrooted

{-------------------------------------------------------------------------------
  Constructing and deconstructing Paths
-------------------------------------------------------------------------------}

fragment :: Fragment -> UnrootedPath
fragment = PathSnoc PathNil

(</>) :: Path a -> UnrootedPath -> Path a
ps </> PathNil       = ps
ps </> PathSnoc qs q = PathSnoc (ps </> qs) q

rootPath :: IsRoot root => UnrootedPath -> Path (Rooted root)
rootPath PathNil         = PathRoot
rootPath (PathSnoc qs q) = PathSnoc (rootPath qs) q

unrootPath :: Path (Rooted root) -> UnrootedPath
unrootPath PathRoot        = PathNil
unrootPath (PathSnoc ps p) = PathSnoc (unrootPath ps) p

(<.>) :: Path a -> String -> Path a
PathRoot      <.> _   = error "(<.>): empty path"
PathNil       <.> _   = error "(<.>): empty path"
PathSnoc ps p <.> ext = PathSnoc ps (p FilePath.<.> ext)

{-------------------------------------------------------------------------------
  FilePath-like operations
-------------------------------------------------------------------------------}

joinFragments :: [Fragment] -> UnrootedPath
joinFragments = go PathNil
  where
    go :: UnrootedPath -> [Fragment] -> UnrootedPath
    go acc []     = acc
    go acc (p:ps) = go (PathSnoc acc p) ps

splitFragments :: UnrootedPath -> [Fragment]
splitFragments = go []
  where
    go :: [Fragment] -> UnrootedPath -> [Fragment]
    go acc PathNil         = acc
    go acc (PathSnoc ps p) = go (p:acc) ps

takeDirectory :: Path a -> Path a
takeDirectory PathRoot        = PathRoot
takeDirectory PathNil         = PathNil
takeDirectory (PathSnoc ps _) = ps

takeFileName :: Path a -> Fragment
takeFileName PathRoot       = error "takeFileName: empty path"
takeFileName PathNil        = error "takeFileName: empty path"
takeFileName (PathSnoc _ p) = p

{-------------------------------------------------------------------------------
  Converting between Paths and FilePaths
-------------------------------------------------------------------------------}

toUnrootedFilePath :: UnrootedPath -> FilePath
toUnrootedFilePath = FilePath.joinPath . splitFragments

fromUnrootedFilePath :: FilePath -> UnrootedPath
fromUnrootedFilePath = joinFragments . FilePath.splitPath

-- | Translate to a raw FilePath
--
-- This only makes sense for rooted paths
toFilePath :: forall root. IsFileSystemRoot root
           => Path (Rooted root) -> FilePath
toFilePath = rootFilePath (singRoot :: Rooted root)
           . toUnrootedFilePath
           . unrootPath

-- | Translate from a raw FilePath
--
-- Invariant: @fromFilePath . toFilePath == id@
--
-- TODO: We should do some error checking here
-- TODO: If we introduce trickier file systme roots (like home directory)
-- then we need to do more manipulation of the FilePath here
fromFilePath :: IsRoot root => FilePath -> Path (Rooted root)
fromFilePath = rootPath . fromUnrootedFilePath

{-------------------------------------------------------------------------------
  Wrappers around System.IO
-------------------------------------------------------------------------------}

withFile :: IsFileSystemRoot root
         => Path (Rooted root) -> IO.IOMode -> (IO.Handle -> IO r) -> IO r
withFile = IO.withFile . toFilePath

withBinaryFile :: IsFileSystemRoot root
               => Path (Rooted root) -> IO.IOMode -> (IO.Handle -> IO r) -> IO r
withBinaryFile = IO.withBinaryFile . toFilePath

openTempFile :: forall root. IsFileSystemRoot root
             => Path (Rooted root) -> Fragment -> IO (Path (Rooted root), IO.Handle)
openTempFile dir template = aux <$> IO.openTempFile (toFilePath dir) template
  where
    aux :: (FilePath, IO.Handle) -> (Path (Rooted root), IO.Handle)
    aux (fp, h) = (fromFilePath fp, h)

{-------------------------------------------------------------------------------
  Wrappers around Data.ByteString.*
-------------------------------------------------------------------------------}

writeLazyByteString :: IsFileSystemRoot root
                    => Path (Rooted root) -> BS.L.ByteString -> IO ()
writeLazyByteString = BS.L.writeFile . toFilePath

readLazyByteString :: IsFileSystemRoot root
                   => Path (Rooted root) -> IO BS.L.ByteString
readLazyByteString = BS.L.readFile . toFilePath

readStrictByteString :: IsFileSystemRoot root
                     => Path (Rooted root) -> IO BS.ByteString
readStrictByteString = BS.readFile . toFilePath

{-------------------------------------------------------------------------------
  Wrappers around System.Directory
-------------------------------------------------------------------------------}

createDirectoryIfMissing :: IsFileSystemRoot root
                         => Bool -> Path (Rooted root) -> IO ()
createDirectoryIfMissing createParents =
    Dir.createDirectoryIfMissing createParents . toFilePath

copyFile :: (IsFileSystemRoot root, IsFileSystemRoot root')
         => Path (Rooted root) -> Path (Rooted root') -> IO ()
copyFile p q = Dir.copyFile (toFilePath p) (toFilePath q)

doesFileExist :: IsFileSystemRoot root => Path (Rooted root) -> IO Bool
doesFileExist = Dir.doesFileExist . toFilePath

removeFile :: IsFileSystemRoot root => Path (Rooted root) -> IO ()
removeFile = Dir.removeFile . toFilePath

getTemporaryDirectory :: IO AbsolutePath
getTemporaryDirectory = fromFilePath <$> Dir.getTemporaryDirectory

{-------------------------------------------------------------------------------
  Wrappers around Codec.Archive.Tar.*
-------------------------------------------------------------------------------}

tarPack :: IsFileSystemRoot root
        => Path (Rooted root) -> [UnrootedPath] -> IO [Tar.Entry]
tarPack baseDir paths =
    Tar.pack (toFilePath baseDir) (map toUnrootedFilePath paths)

tarIndexLookup :: TarIndex.TarIndex -> UnrootedPath -> Maybe TarIndex.TarIndexEntry
tarIndexLookup index = TarIndex.lookup index . toUnrootedFilePath

{-------------------------------------------------------------------------------
  Wrappers around Network.URI
-------------------------------------------------------------------------------}

uriPath :: URI.URI -> Path (Rooted WebRoot)
uriPath = fromFilePath . URI.uriPath

modifyUriPath :: URI.URI -> (Path (Rooted WebRoot) -> Path (Rooted WebRoot)) -> URI.URI
modifyUriPath uri f = uri { URI.uriPath = f' (URI.uriPath uri) }
  where
    f' :: FilePath -> FilePath
    f' = toUnrootedFilePath . unrootPath . f . fromFilePath
