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
    -- * Path fragments
    Fragment  -- opaque
  , mkFragment
  , unFragment
    -- * Paths
  , Path
  , Unrooted
  , Rooted(..)
  , UnrootedPath
  , IsRoot(..)
  -- ** Construcion and destruction
  , fragment
  , fragment'
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
  , isPathPrefixOf
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
  , withFile
  -- ** Wrappers around Data.ByteString.*
  , readLazyByteString
  , readStrictByteString
  -- ** Wrappers around System.Directory
  , createDirectoryIfMissing
  , doesDirectoryExist
  , doesFileExist
  , getCurrentDirectory
  , getDirectoryContents
  , getRecursiveContents
  , getTemporaryDirectory
  , removeFile
  , renameFile
  -- ** Wrappers around Codec.Archive.Tar.*
  , TarballRoot
  , TarballPath
  , tarIndexLookup
  , tarAppend
  -- * Paths in URIs
  , WebRoot
  , URIPath
  , uriPath
  , modifyUriPath
    -- * Re-exports
  , IO.IOMode(..)
  , IO.BufferMode(..)
  , IO.Handle
  , IO.SeekMode(..)
  , IO.hSetBuffering
  , IO.hClose
  , IO.hFileSize
  , IO.hSeek
  ) where

import Control.Monad
import Data.Function (on)
import qualified Data.ByteString         as BS
import qualified Data.ByteString.Lazy    as BS.L
import qualified System.FilePath         as FilePath hiding (splitPath)
import qualified System.IO               as IO
import qualified System.Directory        as Dir
import qualified Codec.Archive.Tar       as Tar
import qualified Codec.Archive.Tar.Index as TarIndex
import qualified Network.URI             as URI

import Hackage.Security.Util.Pretty

{-------------------------------------------------------------------------------
  Fragments
-------------------------------------------------------------------------------}

-- | Path fragments
--
-- Path fragments must be non-empty and not contain any path delimiters.
newtype Fragment = Fragment { unFragment :: String }
  deriving (Show, Eq, Ord)

instance Pretty Fragment where
  pretty = unFragment

mkFragment :: String -> Fragment
mkFragment str
    | hasSep str = invalid "fragment contains path separators"
    | null str   = invalid "empty fragment"
    | otherwise  = Fragment str
  where
    invalid :: String -> a
    invalid msg = error $ "mkFragment: " ++ show str ++ ": " ++ msg

    hasSep :: String -> Bool
    hasSep = any FilePath.isPathSeparator

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
  deriving (Show)

-- | Paths
--
-- A path consists of an optional root and a list of fragments.
-- Alternatively, think of it as a list with two kinds of nil-constructors.
data Path a where
    PathRoot :: Rooted root -> Path (Rooted root)
    PathNil  :: Path Unrooted
    PathSnoc :: Path a -> Fragment -> Path a

deriving instance Show (Path a)

class IsRoot root where
  showRoot :: Rooted root -> String

type UnrootedPath = Path Unrooted

instance Eq (Path a) where
  (==) = (==) `on` (splitFragments . unrootPath')

instance Ord (Path a) where
  (<=) = (<=) `on` (splitFragments . unrootPath')

-- | Turn a path into a human-readable string
instance IsRoot root => Pretty (Path (Rooted root)) where
  pretty path = showRoot root FilePath.</> toUnrootedFilePath unrooted
    where
      (root, unrooted) = unrootPath path

{-------------------------------------------------------------------------------
  Constructing and destructing paths
-------------------------------------------------------------------------------}

fragment :: Fragment -> UnrootedPath
fragment = PathSnoc PathNil

-- | For convenience: combine `fragment` and `mkFragment`
--
-- This can therefore throw the same runtime errors as `mkFragment`.
fragment' :: String -> UnrootedPath
fragment' = fragment . mkFragment

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
toUnrootedFilePath = FilePath.joinPath . map unFragment . splitFragments

fromUnrootedFilePath :: FilePath -> UnrootedPath
fromUnrootedFilePath = joinFragments . map mkFragment . splitPath

isPathPrefixOf :: UnrootedPath -> UnrootedPath -> Bool
isPathPrefixOf = go `on` splitFragments
  where
    go :: [Fragment] -> [Fragment] -> Bool
    go []     _      = True
    go _      []     = False
    go (p:ps) (q:qs) = p == q && go ps qs

{-------------------------------------------------------------------------------
  FilePath-like operations
-------------------------------------------------------------------------------}

takeDirectory :: Path a -> Path a
takeDirectory (PathRoot root) = PathRoot root
takeDirectory PathNil         = PathNil
takeDirectory (PathSnoc ps _) = ps

takeFileName :: Path a -> Fragment
takeFileName (PathRoot _)   = error "takeFileName: empty path"
takeFileName PathNil        = error "takeFileName: empty path"
takeFileName (PathSnoc _ p) = p

(<.>) :: Path a -> String -> Path a
PathRoot _    <.> _   = error "(<.>): empty path"
PathNil       <.> _   = error "(<.>): empty path"
PathSnoc ps p <.> ext = PathSnoc ps p'
  where
    p' = mkFragment $ unFragment p FilePath.<.> ext

splitExtension :: Path a -> (Path a, String)
splitExtension (PathRoot _)    = error "splitExtension: empty path"
splitExtension PathNil         = error "splitExtension: empty path"
splitExtension (PathSnoc ps p) =
    let (p', ext) = FilePath.splitExtension (unFragment p)
    in (PathSnoc ps (mkFragment p'), ext)

{-------------------------------------------------------------------------------
  File-system paths
-------------------------------------------------------------------------------}

-- | A file system root can be interpreted as an (absolute) FilePath
class IsRoot root => IsFileSystemRoot root where
    interpretRoot :: Rooted root -> IO FilePath

data Relative
data Absolute
data HomeDir

type AbsolutePath = Path (Rooted Absolute)
type RelativePath = Path (Rooted Relative)

instance IsRoot Relative where showRoot _ = "."
instance IsRoot Absolute where showRoot _ = "/"
instance IsRoot HomeDir  where showRoot _ = "~"

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
toFilePath path = "/" FilePath.</> toUnrootedFilePath (unrootPath' path)

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

-- | Wrapper around 'withFile'
withFile :: IsFileSystemRoot root
         => Path (Rooted root) -> IO.IOMode -> (IO.Handle -> IO r) -> IO r
withFile path mode callback = do
    filePath <- toAbsoluteFilePath path
    IO.withFile filePath mode callback

-- | Wrapper around 'openBinaryTempFileWithDefaultPermissions'
openTempFile :: forall root. IsFileSystemRoot root
             => Path (Rooted root) -> String -> IO (AbsolutePath, IO.Handle)
openTempFile path template = do
    filePath <- toAbsoluteFilePath path
    (tempFilePath, h) <- IO.openBinaryTempFileWithDefaultPermissions filePath template
    return (fromAbsoluteFilePath tempFilePath, h)

{-------------------------------------------------------------------------------
  Wrappers around Data.ByteString.*
-------------------------------------------------------------------------------}

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

-- | Return the immediate children of a directory
--
-- Filters out @"."@ and @".."@.
getDirectoryContents :: IsFileSystemRoot root
                     => Path (Rooted root) -> IO [UnrootedPath]
getDirectoryContents path = do
    filePath <- toAbsoluteFilePath path
    fragments <$> Dir.getDirectoryContents filePath
  where
    fragments :: [String] -> [UnrootedPath]
    fragments = map fragment' . filter (not . skip)

    skip :: String -> Bool
    skip "."  = True
    skip ".." = True
    skip _    = False

-- | Recursive traverse a directory structure
--
-- Returns a set of paths relative to the directory specified.
-- TODO: Not sure about the memory behaviour with large file systems.
getRecursiveContents :: IsFileSystemRoot root
                     => Path (Rooted root)
                     -> IO [UnrootedPath]
getRecursiveContents root = go PathNil
  where
    go :: UnrootedPath -> IO [UnrootedPath]
    go subdir = do
      entries <- getDirectoryContents (root </> subdir)
      liftM concat $ forM entries $ \entry -> do
        let path = subdir </> entry
        isDirectory <- doesDirectoryExist (root </> path)
        if isDirectory then go path
                       else return [path]

renameFile :: (IsFileSystemRoot root, IsFileSystemRoot root1)
           => Path (Rooted root)  -- ^ Old
           -> Path (Rooted root1) -- ^ New
           -> IO ()
renameFile old new = do
    old' <- toAbsoluteFilePath old
    new' <- toAbsoluteFilePath new
    Dir.renameFile old' new'

getCurrentDirectory :: IO AbsolutePath
getCurrentDirectory = do
    cwd <- Dir.getCurrentDirectory
    makeAbsolute $ fromFilePath cwd

{-------------------------------------------------------------------------------
  Wrappers around Codec.Archive.Tar.*
-------------------------------------------------------------------------------}

data TarballRoot
type TarballPath = Path (Rooted TarballRoot)

instance Show (Rooted TarballRoot) where show _ = "<tarball>"

tarIndexLookup :: TarIndex.TarIndex -> TarballPath -> Maybe TarIndex.TarIndexEntry
tarIndexLookup index path = TarIndex.lookup index path'
  where
    path' :: FilePath
    path' = toUnrootedFilePath $ unrootPath' path

tarAppend :: (IsFileSystemRoot root, IsFileSystemRoot root')
          => Path (Rooted root)  -- ^ Path of the @.tar@ file
          -> Path (Rooted root') -- ^ Base directory
          -> [TarballPath]       -- ^ Files to add, relative to the base dir
          -> IO ()
tarAppend tarFile baseDir contents = do
    tarFile' <- toAbsoluteFilePath tarFile
    baseDir' <- toAbsoluteFilePath baseDir
    Tar.append tarFile' baseDir' contents'
  where
    contents' :: [FilePath]
    contents' = map (toUnrootedFilePath . unrootPath') contents

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

{-------------------------------------------------------------------------------
  Auxiliary: operations on raw FilePaths
-------------------------------------------------------------------------------}

-- | Split a path into its components
--
-- Unlike 'FilePath.splitPath' this satisfies the invariants required by
-- 'mkFragment'. That is, the fragments do NOT contain any path separators.
--
-- Multiple consecutive path separators are considered to be the same as a
-- single path separator, and leading and trailing separators are ignored.
splitPath :: FilePath -> [FilePath]
splitPath = go []
  where
    go :: [FilePath] -> FilePath -> [FilePath]
    go acc fp = case break FilePath.isPathSeparator fp of
                  ("", [])    -> reverse acc
                  (fr, [])    -> reverse (fr:acc)
                  ("", _:fp') -> go acc      fp'
                  (fr, _:fp') -> go (fr:acc) fp'
