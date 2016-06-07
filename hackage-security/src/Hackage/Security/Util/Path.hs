-- | A more type-safe version of file paths
--
-- This module is intended to replace imports of System.FilePath, and
-- additionally exports thin wrappers around common IO functions.  To facilitate
-- importing this module unqualified we also re-export some  definitions from
-- System.IO (importing both would likely lead to name clashes).
--
-- Note that his module does not import any other modules from Hackage.Security;
-- everywhere else we use Path instead of FilePath directly.
{-# LANGUAGE CPP #-}
module Hackage.Security.Util.Path (
    -- * Paths
    Path(..)
  , castRoot
    -- * FilePath-like operations on paths with arbitrary roots
  , takeDirectory
  , takeFileName
  , (<.>)
  , splitExtension
  , takeExtension
    -- * Unrooted paths
  , Unrooted
  , (</>)
  , rootPath
  , unrootPath
  , toUnrootedFilePath
  , fromUnrootedFilePath
  , fragment
  , joinFragments
  , splitFragments
  , isPathPrefixOf
    -- * File-system paths
  , Relative
  , Absolute
  , HomeDir
  , FsRoot(..)
  , FsPath(..)
    -- ** Conversions
  , toFilePath
  , fromFilePath
  , makeAbsolute
  , fromAbsoluteFilePath
    -- ** Wrappers around System.IO
  , withFile
  , openTempFile'
    -- ** Wrappers around Data.ByteString
  , readLazyByteString
  , readStrictByteString
  , writeLazyByteString
  , writeStrictByteString
    -- ** Wrappers around System.Directory
  , copyFile
  , createDirectory
  , createDirectoryIfMissing
  , removeDirectory
  , doesFileExist
  , doesDirectoryExist
  , getModificationTime
  , removeFile
  , getTemporaryDirectory
  , getDirectoryContents
  , getRecursiveContents
  , renameFile
  , getCurrentDirectory
    -- * Wrappers around Codec.Archive.Tar
  , Tar
  , tarIndexLookup
  , tarAppend
    -- * Wrappers around Network.URI
  , Web
  , toURIPath
  , fromURIPath
  , uriPath
  , modifyUriPath
    -- * Re-exports
  , IOMode(..)
  , BufferMode(..)
  , Handle
  , SeekMode(..)
  , IO.hSetBuffering
  , IO.hClose
  , IO.hFileSize
  , IO.hSeek
  ) where

import Control.Monad
import Data.List (isPrefixOf)
import System.IO (IOMode(..), BufferMode(..), Handle, SeekMode(..))
import System.IO.Unsafe (unsafeInterleaveIO)
#if MIN_VERSION_directory(1,2,0)
import Data.Time (UTCTime)
#else
import System.Time (ClockTime)
#endif
import qualified Data.ByteString         as BS
import qualified Data.ByteString.Lazy    as BS.L
import qualified System.FilePath         as FP.Native
import qualified System.FilePath.Posix   as FP.Posix
import qualified System.IO               as IO
import qualified System.Directory        as Dir
import qualified Codec.Archive.Tar       as Tar
import qualified Codec.Archive.Tar.Index as TarIndex
import qualified Network.URI             as URI

import Hackage.Security.Util.Pretty

{-------------------------------------------------------------------------------
  Paths
-------------------------------------------------------------------------------}

-- | Paths
--
-- A 'Path' is simply a 'FilePath' with a type-level tag indicating where this
-- path is rooted (relative to the current directory, absolute path, relative to
-- a web domain, whatever). Most operations on 'Path' are just lifted versions
-- of the operations on the underlying 'FilePath'. The tag however allows us to
-- give a lot of operations a more meaningful type. For instance, it does not
-- make sense to append two absolute paths together; instead, we can only append
-- an unrooted path to another path. It also means we avoid bugs where we use
-- one kind of path where we expect another.
newtype Path a = Path FilePath -- always a Posix style path internally
  deriving (Show, Eq, Ord)

mkPathNative :: FilePath -> Path a
mkPathNative = Path . FP.Posix.joinPath . FP.Native.splitDirectories

unPathNative :: Path a -> FilePath
unPathNative (Path fp) = FP.Native.joinPath . FP.Posix.splitDirectories $ fp

mkPathPosix :: FilePath -> Path a
mkPathPosix = Path

unPathPosix :: Path a -> FilePath
unPathPosix (Path fp) = fp

-- | Reinterpret the root of a path
--
-- This literally just changes the type-level tag; use with caution!
castRoot :: Path root -> Path root'
castRoot (Path fp) = Path fp

{-------------------------------------------------------------------------------
  FilePath-like operations on paths with an arbitrary root
-------------------------------------------------------------------------------}

takeDirectory :: Path a -> Path a
takeDirectory = liftFP FP.Posix.takeDirectory

takeFileName :: Path a -> String
takeFileName = liftFromFP FP.Posix.takeFileName

(<.>) :: Path a -> String -> Path a
fp <.> ext = liftFP (FP.Posix.<.> ext) fp

splitExtension :: Path a -> (Path a, String)
splitExtension (Path fp) = (Path fp', ext)
  where
    (fp', ext) = FP.Posix.splitExtension fp

takeExtension :: Path a -> String
takeExtension (Path fp) = FP.Posix.takeExtension fp

{-------------------------------------------------------------------------------
  Unrooted paths
-------------------------------------------------------------------------------}

-- | Type-level tag for unrooted paths
--
-- Unrooted paths need a root before they can be interpreted.
data Unrooted

instance Pretty (Path Unrooted) where
  pretty (Path fp) = fp

(</>) :: Path a -> Path Unrooted -> Path a
(</>) = liftFP2 (FP.Posix.</>)

-- | Reinterpret an unrooted path
--
-- This is an alias for 'castRoot'; see comments there.
rootPath :: Path Unrooted -> Path root
rootPath (Path fp) = Path fp

-- | Forget a path's root
--
-- This is an alias for 'castRoot'; see comments there.
unrootPath :: Path root -> Path Unrooted
unrootPath (Path fp) = Path fp

-- | Convert a relative\/unrooted Path to a FilePath (using POSIX style
-- directory separators).
--
-- See also 'toAbsoluteFilePath'
--
toUnrootedFilePath :: Path Unrooted -> FilePath
toUnrootedFilePath = unPathPosix

-- | Convert from a relative\/unrooted FilePath (using POSIX style directory
-- separators).
--
fromUnrootedFilePath :: FilePath -> Path Unrooted
fromUnrootedFilePath = mkPathPosix

-- | A path fragment (like a single directory or filename)
fragment :: String -> Path Unrooted
fragment = Path

joinFragments :: [String] -> Path Unrooted
joinFragments = liftToFP FP.Posix.joinPath

splitFragments :: Path Unrooted -> [String]
splitFragments (Path fp) = FP.Posix.splitDirectories fp

isPathPrefixOf :: Path Unrooted -> Path Unrooted -> Bool
isPathPrefixOf = liftFromFP2 isPrefixOf

{-------------------------------------------------------------------------------
  File-system paths
-------------------------------------------------------------------------------}

data Relative
data Absolute
data HomeDir

instance Pretty (Path Absolute) where
  pretty (Path fp) = fp

instance Pretty (Path Relative) where
  pretty (Path fp) = "./" ++ fp

instance Pretty (Path HomeDir) where
  pretty (Path fp) = "~/" ++ fp

-- | A file system root can be interpreted as an (absolute) FilePath
class FsRoot root where
  -- | Convert a Path to an absolute FilePath (using native style directory separators).
  --
  toAbsoluteFilePath :: Path root -> IO FilePath

instance FsRoot Relative where
    toAbsoluteFilePath p = go (unPathNative p)
      where
        go :: FilePath -> IO FilePath
#if MIN_VERSION_directory(1,2,2)
        go = Dir.makeAbsolute
#else
        -- copied implementation from the directory package
        go = (FP.Native.normalise <$>) . absolutize
        absolutize path -- avoid the call to `getCurrentDirectory` if we can
          | FP.Native.isRelative path
                      = (FP.Native.</> path)
                      . FP.Native.addTrailingPathSeparator <$>
                        Dir.getCurrentDirectory
          | otherwise = return path
#endif

instance FsRoot Absolute where
    toAbsoluteFilePath = return . unPathNative

instance FsRoot HomeDir where
    toAbsoluteFilePath p = do
      home <- Dir.getHomeDirectory
      return $ home FP.Native.</> unPathNative p

-- | Abstract over a file system root
--
-- see 'fromFilePath'
data FsPath = forall root. FsRoot root => FsPath (Path root)

{-------------------------------------------------------------------------------
  Conversions
-------------------------------------------------------------------------------}

toFilePath :: Path Absolute -> FilePath
toFilePath = unPathNative

fromFilePath :: FilePath -> FsPath
fromFilePath fp
    | FP.Native.isAbsolute fp = FsPath (mkPathNative fp  :: Path Absolute)
    | Just fp' <- atHome fp   = FsPath (mkPathNative fp' :: Path HomeDir)
    | otherwise               = FsPath (mkPathNative fp  :: Path Relative)
  where
    -- TODO: I don't know if there a standard way that Windows users refer to
    -- their home directory. For now, we'll only interpret '~'. Everybody else
    -- can specify an absolute path if this doesn't work.
    atHome :: FilePath -> Maybe FilePath
    atHome "~" = Just ""
    atHome ('~':sep:fp') | FP.Native.isPathSeparator sep = Just fp'
    atHome _otherwise = Nothing

makeAbsolute :: FsPath -> IO (Path Absolute)
makeAbsolute (FsPath p) = mkPathNative <$> toAbsoluteFilePath p

fromAbsoluteFilePath :: FilePath -> Path Absolute
fromAbsoluteFilePath fp
  | FP.Native.isAbsolute fp = mkPathNative fp
  | otherwise               = error "fromAbsoluteFilePath: not an absolute path"

{-------------------------------------------------------------------------------
  Wrappers around System.IO
-------------------------------------------------------------------------------}

-- | Wrapper around 'withFile'
withFile :: FsRoot root => Path root -> IOMode -> (Handle -> IO r) -> IO r
withFile path mode callback = do
    filePath <- toAbsoluteFilePath path
    IO.withFile filePath mode callback

-- | Wrapper around 'openBinaryTempFileWithDefaultPermissions'
--
-- NOTE: The caller is responsible for cleaning up the temporary file.
openTempFile' :: FsRoot root => Path root -> String -> IO (Path Absolute, Handle)
openTempFile' path template = do
    filePath <- toAbsoluteFilePath path
    (tempFilePath, h) <- IO.openBinaryTempFileWithDefaultPermissions filePath template
    return (fromAbsoluteFilePath tempFilePath, h)

{-------------------------------------------------------------------------------
  Wrappers around Data.ByteString.*
-------------------------------------------------------------------------------}

readLazyByteString :: FsRoot root => Path root -> IO BS.L.ByteString
readLazyByteString path = do
    filePath <- toAbsoluteFilePath path
    BS.L.readFile filePath

readStrictByteString :: FsRoot root => Path root -> IO BS.ByteString
readStrictByteString path = do
    filePath <- toAbsoluteFilePath path
    BS.readFile filePath

writeLazyByteString :: FsRoot root => Path root -> BS.L.ByteString -> IO ()
writeLazyByteString path bs = do
    filePath <- toAbsoluteFilePath path
    BS.L.writeFile filePath bs

writeStrictByteString :: FsRoot root => Path root -> BS.ByteString -> IO ()
writeStrictByteString path bs = do
    filePath <- toAbsoluteFilePath path
    BS.writeFile filePath bs

{-------------------------------------------------------------------------------
  Wrappers around System.Directory
-------------------------------------------------------------------------------}

copyFile :: (FsRoot root, FsRoot root') => Path root -> Path root' -> IO ()
copyFile src dst = do
    src' <- toAbsoluteFilePath src
    dst' <- toAbsoluteFilePath dst
    Dir.copyFile src' dst'

createDirectory :: FsRoot root => Path root -> IO ()
createDirectory path = Dir.createDirectory =<< toAbsoluteFilePath path

createDirectoryIfMissing :: FsRoot root => Bool -> Path root -> IO ()
createDirectoryIfMissing createParents path = do
    filePath <- toAbsoluteFilePath path
    Dir.createDirectoryIfMissing createParents filePath

removeDirectory :: FsRoot root => Path root -> IO ()
removeDirectory path = Dir.removeDirectory =<< toAbsoluteFilePath path

doesFileExist :: FsRoot root => Path root -> IO Bool
doesFileExist path = do
    filePath <- toAbsoluteFilePath path
    Dir.doesFileExist filePath

doesDirectoryExist :: FsRoot root => Path root -> IO Bool
doesDirectoryExist path = do
    filePath <- toAbsoluteFilePath path
    Dir.doesDirectoryExist filePath

#if MIN_VERSION_directory(1,2,0)
getModificationTime :: FsRoot root => Path root -> IO UTCTime
#else
getModificationTime :: FsRoot root => Path root -> IO ClockTime
#endif
getModificationTime path = do
    filePath <- toAbsoluteFilePath path
    Dir.getModificationTime filePath

removeFile :: FsRoot root => Path root -> IO ()
removeFile path = do
    filePath <- toAbsoluteFilePath path
    Dir.removeFile filePath

getTemporaryDirectory :: IO (Path Absolute)
getTemporaryDirectory = fromAbsoluteFilePath <$> Dir.getTemporaryDirectory

-- | Return the immediate children of a directory
--
-- Filters out @"."@ and @".."@.
getDirectoryContents :: FsRoot root => Path root -> IO [Path Unrooted]
getDirectoryContents path = do
    filePath <- toAbsoluteFilePath path
    fragments <$> Dir.getDirectoryContents filePath
  where
    fragments :: [String] -> [Path Unrooted]
    fragments = map fragment . filter (not . skip)

    skip :: String -> Bool
    skip "."  = True
    skip ".." = True
    skip _    = False

-- | Recursive traverse a directory structure
--
-- Returns a set of paths relative to the directory specified. The list is
-- lazily constructed, so that directories are only read when required.
-- (This is also essential to ensure that this function does not build the
-- entire result in memory before returning, potentially running out of heap.)
getRecursiveContents :: FsRoot root => Path root -> IO [Path Unrooted]
getRecursiveContents root = go emptyPath
  where
    go :: Path Unrooted -> IO [Path Unrooted]
    go subdir = unsafeInterleaveIO $ do
      entries <- getDirectoryContents (root </> subdir)
      liftM concat $ forM entries $ \entry -> do
        let path = subdir </> entry
        isDirectory <- doesDirectoryExist (root </> path)
        if isDirectory then go path
                       else return [path]

    emptyPath :: Path Unrooted
    emptyPath = joinFragments []

renameFile :: (FsRoot root, FsRoot root')
           => Path root  -- ^ Old
           -> Path root' -- ^ New
           -> IO ()
renameFile old new = do
    old' <- toAbsoluteFilePath old
    new' <- toAbsoluteFilePath new
    Dir.renameFile old' new'

getCurrentDirectory :: IO (Path Absolute)
getCurrentDirectory = do
    cwd <- Dir.getCurrentDirectory
    makeAbsolute $ fromFilePath cwd

{-------------------------------------------------------------------------------
  Wrappers around Codec.Archive.Tar.*
-------------------------------------------------------------------------------}

data Tar

instance Pretty (Path Tar) where
  pretty (Path fp) = "<tarball>/" ++ fp

tarIndexLookup :: TarIndex.TarIndex -> Path Tar -> Maybe TarIndex.TarIndexEntry
tarIndexLookup index path = TarIndex.lookup index path'
  where
    path' :: FilePath
    path' = toUnrootedFilePath $ unrootPath path

tarAppend :: (FsRoot root, FsRoot root')
          => Path root   -- ^ Path of the @.tar@ file
          -> Path root'  -- ^ Base directory
          -> [Path Tar]  -- ^ Files to add, relative to the base dir
          -> IO ()
tarAppend tarFile baseDir contents = do
    tarFile' <- toAbsoluteFilePath tarFile
    baseDir' <- toAbsoluteFilePath baseDir
    Tar.append tarFile' baseDir' contents'
  where
    contents' :: [FilePath]
    contents' = map (unPathNative . unrootPath) contents

{-------------------------------------------------------------------------------
  Wrappers around Network.URI
-------------------------------------------------------------------------------}

data Web

toURIPath :: FilePath -> Path Web
toURIPath = rootPath . fromUnrootedFilePath

fromURIPath :: Path Web -> FilePath
fromURIPath = toUnrootedFilePath . unrootPath

uriPath :: URI.URI -> Path Web
uriPath = toURIPath . URI.uriPath

modifyUriPath :: URI.URI -> (Path Web -> Path Web) -> URI.URI
modifyUriPath uri f = uri { URI.uriPath = f' (URI.uriPath uri) }
  where
    f' :: FilePath -> FilePath
    f' = fromURIPath . f . toURIPath

{-------------------------------------------------------------------------------
  Auxiliary
-------------------------------------------------------------------------------}

liftFP :: (FilePath -> FilePath) -> Path a -> Path b
liftFP f (Path fp) = Path (f fp)

liftFP2 :: (FilePath -> FilePath -> FilePath) -> Path a -> Path b -> Path c
liftFP2 f (Path fp) (Path fp') = Path (f fp fp')

liftFromFP :: (FilePath -> x) -> Path a -> x
liftFromFP f (Path fp) = f fp

liftFromFP2 :: (FilePath -> FilePath -> x) -> Path a -> Path b -> x
liftFromFP2 f (Path fp) (Path fp') = f fp fp'

liftToFP :: (x -> FilePath) -> x -> Path a
liftToFP f x = Path (f x)
