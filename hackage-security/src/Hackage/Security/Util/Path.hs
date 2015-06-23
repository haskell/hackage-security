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
  -- * Paths
    Path
  , Fragment
  , Unrooted
  , Rooted(..)
  , UnrootedPath
  -- ** Construcion and destruction
  , fragment
  , (</>)
  , rootPath
  , unrootPath
  , unrootPath'
  , castRoot
  -- ** Unrooted paths
  , joinFragments
  , splitFragments
  , toUnrootedFilePath
  , fromUnrootedFilePath
  -- ** FilePath-like operations
  , takeDirectory
  , takeFileName
  , (<.>)
  , splitExtension
  -- * File-system paths
  , IsFileSystemRoot
  , Relative
  , Absolute
  , HomeDir
  , AbsolutePath
  , RelativePath
  , FileSystemPath(..)
  -- ** Conversions
  , toFilePath
  , fromFilePath
  , makeAbsolute
  , toAbsoluteFilePath
  , fromAbsoluteFilePath
  -- ** Wrappers around System.IO
  , openTempFile
  , withBinaryFile
  , withFile
  -- ** Wrappers around Data.ByteString.*
  , readLazyByteString
  , readStrictByteString
  , writeLazyByteString
  -- ** Wrappers around System.Directory
  , copyFile
  , createDirectoryIfMissing
  , doesDirectoryExist
  , doesFileExist
  , getDirectoryContents
  , getTemporaryDirectory
  , removeFile
  -- ** Wrappers around Codec.Archive.Tar.*
  , TarballRoot
  , TarballPath
  , tarPack
  , tarIndexLookup
  -- * Paths in URIs
  , WebRoot
  , URIPath
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
  Paths
-------------------------------------------------------------------------------}

-- | Unrooted paths
--
-- Unrooted paths need a root before they can be interpreted.
data Unrooted

-- | Rooted paths
--
-- The 'a' parameter is a phantom argument; 'Rooted' is effectively a proxy.
data Rooted a = Rooted

-- | Path fragments
type Fragment = String

-- | Paths
--
-- A path consists of an optional root and a list of fragments.
-- Alternatively, think of it as a list with two kinds of nil-constructors.
data Path a where
    PathRoot :: Rooted root -> Path (Rooted root)
    PathNil  :: Path Unrooted
    PathSnoc :: Path a -> Fragment -> Path a

instance Show (Path Unrooted) where
   show = toUnrootedFilePath

instance Show (Rooted root) => Show (Path (Rooted root)) where
   show path = let (root, unrooted) = unrootPath path
               in show root FilePath.</> show unrooted

type UnrootedPath = Path Unrooted

instance Eq (Path a) where
  (==) = (==) `on` (splitFragments . unrootPath')

instance Ord (Path a) where
  (<=) = (<=) `on` (splitFragments . unrootPath')

{-------------------------------------------------------------------------------
  Constructing and destructing paths
-------------------------------------------------------------------------------}

fragment :: Fragment -> UnrootedPath
fragment = PathSnoc PathNil

(</>) :: Path a -> UnrootedPath -> Path a
ps </> PathNil       = ps
ps </> PathSnoc qs q = PathSnoc (ps </> qs) q

rootPath :: forall root. Rooted root -> UnrootedPath -> Path (Rooted root)
rootPath root = go
  where
    go :: UnrootedPath -> Path (Rooted root)
    go PathNil         = PathRoot root
    go (PathSnoc qs q) = PathSnoc (go qs) q

unrootPath :: Path (Rooted root) -> (Rooted root, UnrootedPath)
unrootPath (PathRoot root) = (root, PathNil)
unrootPath (PathSnoc qs q) = let (root, unrooted) = unrootPath qs
                             in (root, PathSnoc unrooted q)

unrootPath' :: Path a -> UnrootedPath
unrootPath' (PathRoot _)    = PathNil
unrootPath' PathNil         = PathNil
unrootPath' (PathSnoc qs q) = PathSnoc (unrootPath' qs) q

-- | Reinterpret the root of a path
castRoot :: Path (Rooted root) -> Path (Rooted root')
castRoot (PathRoot _)    = PathRoot Rooted
castRoot (PathSnoc qs q) = PathSnoc (castRoot qs) q

{-------------------------------------------------------------------------------
  Unrooted paths
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

toUnrootedFilePath :: UnrootedPath -> FilePath
toUnrootedFilePath = FilePath.joinPath . splitFragments

fromUnrootedFilePath :: FilePath -> UnrootedPath
fromUnrootedFilePath = joinFragments . FilePath.splitPath

{-------------------------------------------------------------------------------
  FilePath-like operations
-------------------------------------------------------------------------------}

takeDirectory :: Path a -> Path a
takeDirectory (PathRoot root) = PathRoot root
takeDirectory PathNil         = PathNil
takeDirectory (PathSnoc ps _) = ps

takeFileName :: Path a -> Fragment
takeFileName (PathRoot _)   = ""
takeFileName PathNil        = ""
takeFileName (PathSnoc _ p) = p

(<.>) :: Path a -> String -> Path a
PathRoot root <.> ext = PathSnoc (PathRoot root) ext
PathNil       <.> ext = PathSnoc PathNil ext
PathSnoc ps p <.> ext = PathSnoc ps (p FilePath.<.> ext)

splitExtension :: Path a -> (Path a, String)
splitExtension (PathRoot root) = (PathRoot root, "")
splitExtension PathNil         = (PathNil, "")
splitExtension (PathSnoc ps p) = let (p', ext) = FilePath.splitExtension p
                                 in (PathSnoc ps p', ext)

{-------------------------------------------------------------------------------
  File-system paths
-------------------------------------------------------------------------------}

-- | A file system root can be interpreted as an (absolute) FilePath
class Show (Rooted root) => IsFileSystemRoot root where
    interpretRoot :: Rooted root -> IO FilePath

data Relative
data Absolute
data HomeDir

type AbsolutePath = Path (Rooted Absolute)
type RelativePath = Path (Rooted Relative)

instance Show (Rooted Relative) where show _ = "."
instance Show (Rooted Absolute) where show _ = "/"
instance Show (Rooted HomeDir)  where show _ = "~"

instance IsFileSystemRoot Relative where
    interpretRoot _ = Dir.getCurrentDirectory

instance IsFileSystemRoot Absolute where
    interpretRoot _ = return "/"

instance IsFileSystemRoot HomeDir where
    interpretRoot _ = Dir.getHomeDirectory

-- | Abstract over a file system root
--
-- see 'fromFilePath'
data FileSystemPath where
    FileSystemPath :: IsFileSystemRoot root => Path (Rooted root) -> FileSystemPath

{-------------------------------------------------------------------------------
  Conversions
-------------------------------------------------------------------------------}

toFilePath :: AbsolutePath -> FilePath
toFilePath = toUnrootedFilePath . unrootPath'

fromFilePath :: FilePath -> FileSystemPath
fromFilePath ('/':path) = FileSystemPath $
    rootPath (Rooted :: Rooted Absolute) (fromUnrootedFilePath path)
fromFilePath ('~':'/':path) = FileSystemPath $
    rootPath (Rooted :: Rooted HomeDir)  (fromUnrootedFilePath path)
fromFilePath path = FileSystemPath $
    rootPath (Rooted :: Rooted Relative) (fromUnrootedFilePath path)

makeAbsolute :: FileSystemPath -> IO AbsolutePath
makeAbsolute (FileSystemPath path) = do
    let (root, unrooted) = unrootPath path
    rootFilePath <- fromUnrootedFilePath <$> interpretRoot root
    return $ rootPath Rooted (rootFilePath </> unrooted)

toAbsoluteFilePath :: IsFileSystemRoot root => Path (Rooted root) -> IO FilePath
toAbsoluteFilePath = fmap toFilePath . makeAbsolute . FileSystemPath

fromAbsoluteFilePath :: FilePath -> AbsolutePath
fromAbsoluteFilePath ('/':path) = rootPath Rooted (fromUnrootedFilePath path)
fromAbsoluteFilePath _ = error "fromAbsoluteFilePath: not an absolute path"

{-------------------------------------------------------------------------------
  Wrappers around System.IO
-------------------------------------------------------------------------------}

withFile :: IsFileSystemRoot root
         => Path (Rooted root) -> IO.IOMode -> (IO.Handle -> IO r) -> IO r
withFile path mode callback = do
    filePath <- toAbsoluteFilePath path
    IO.withFile filePath mode callback

withBinaryFile :: IsFileSystemRoot root
               => Path (Rooted root) -> IO.IOMode -> (IO.Handle -> IO r) -> IO r
withBinaryFile path mode callback = do
    filePath <- toAbsoluteFilePath path
    IO.withBinaryFile filePath mode callback

openTempFile :: forall root. IsFileSystemRoot root
             => Path (Rooted root) -> Fragment -> IO (AbsolutePath, IO.Handle)
openTempFile path template = do
    filePath <- toAbsoluteFilePath path
    (tempFilePath, h) <- IO.openTempFile filePath template
    return (fromAbsoluteFilePath tempFilePath, h)

{-------------------------------------------------------------------------------
  Wrappers around Data.ByteString.*
-------------------------------------------------------------------------------}

writeLazyByteString :: IsFileSystemRoot root
                    => Path (Rooted root) -> BS.L.ByteString -> IO ()
writeLazyByteString path bs = do
    filePath <- toAbsoluteFilePath path
    BS.L.writeFile filePath bs

readLazyByteString :: IsFileSystemRoot root
                   => Path (Rooted root) -> IO BS.L.ByteString
readLazyByteString path = do
    filePath <- toAbsoluteFilePath path
    BS.L.readFile filePath

readStrictByteString :: IsFileSystemRoot root
                     => Path (Rooted root) -> IO BS.ByteString
readStrictByteString path = do
    filePath <- toAbsoluteFilePath path
    BS.readFile filePath

{-------------------------------------------------------------------------------
  Wrappers around System.Directory
-------------------------------------------------------------------------------}

createDirectoryIfMissing :: IsFileSystemRoot root
                         => Bool -> Path (Rooted root) -> IO ()
createDirectoryIfMissing createParents path = do
    filePath <- toAbsoluteFilePath path
    Dir.createDirectoryIfMissing createParents filePath

copyFile :: (IsFileSystemRoot root, IsFileSystemRoot root')
         => Path (Rooted root) -> Path (Rooted root') -> IO ()
copyFile srcPath dstPath = do
    srcFilePath <- toAbsoluteFilePath srcPath
    dstFilePath <- toAbsoluteFilePath dstPath
    Dir.copyFile srcFilePath dstFilePath

doesFileExist :: IsFileSystemRoot root => Path (Rooted root) -> IO Bool
doesFileExist path = do
    filePath <- toAbsoluteFilePath path
    Dir.doesFileExist filePath

doesDirectoryExist :: IsFileSystemRoot root => Path (Rooted root) -> IO Bool
doesDirectoryExist path = do
    filePath <- toAbsoluteFilePath path
    Dir.doesDirectoryExist filePath

removeFile :: IsFileSystemRoot root => Path (Rooted root) -> IO ()
removeFile path = do
    filePath <- toAbsoluteFilePath path
    Dir.removeFile filePath

getTemporaryDirectory :: IO AbsolutePath
getTemporaryDirectory = fromAbsoluteFilePath <$> Dir.getTemporaryDirectory

getDirectoryContents :: IsFileSystemRoot root
                     => Path (Rooted root) -> IO [Fragment]
getDirectoryContents path = do
    filePath <- toAbsoluteFilePath path
    Dir.getDirectoryContents filePath

{-------------------------------------------------------------------------------
  Wrappers around Codec.Archive.Tar.*
-------------------------------------------------------------------------------}

data TarballRoot
type TarballPath = Path (Rooted TarballRoot)

instance Show (Rooted TarballRoot) where show _ = "<tarball>"

tarPack :: IsFileSystemRoot root
        => Path (Rooted root) -> [TarballPath] -> IO [Tar.Entry]
tarPack basePath contents = do
    baseFilePath <- toAbsoluteFilePath basePath
    Tar.pack baseFilePath contents'
  where
    contents' :: [FilePath]
    contents' = map (toUnrootedFilePath . unrootPath') contents

tarIndexLookup :: TarIndex.TarIndex -> TarballPath -> Maybe TarIndex.TarIndexEntry
tarIndexLookup index path = TarIndex.lookup index path'
  where
    path' :: FilePath
    path' = toUnrootedFilePath $ unrootPath' path

{-------------------------------------------------------------------------------
  Wrappers around Network.URI
-------------------------------------------------------------------------------}

data WebRoot

type URIPath = Path (Rooted WebRoot)

toURIPath :: FilePath -> URIPath
toURIPath = rootPath Rooted . fromUnrootedFilePath

fromURIPath :: URIPath -> FilePath
fromURIPath = toUnrootedFilePath . unrootPath'

uriPath :: URI.URI -> URIPath
uriPath = toURIPath . URI.uriPath

modifyUriPath :: URI.URI -> (URIPath -> URIPath) -> URI.URI
modifyUriPath uri f = uri { URI.uriPath = f' (URI.uriPath uri) }
  where
    f' :: FilePath -> FilePath
    f' = fromURIPath . f . toURIPath
