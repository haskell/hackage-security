module Hackage.Security.Client.Repository (
    -- * File formats
    MultipleFormats -- opaque
  , Format(..)
  , multipleFormats
  , multipleFormatsList
  , preferFormat
  , mergeMultipleFormats
    -- * Files
  , RemoteFile(..)
  , CachedFile(..)
  , IndexFile(..)
    -- * Repository proper
  , Repository(..)
  , TempPath
  , LogMessage(..)
    -- * Paths
  , remoteFilePath
  , cachedFilePath
  , indexFilePath
    -- * Names of package files
  , pkgTarGz
    -- * Utility
  , IsCached(..)
  , mustCache
  , formatLogMessage
  ) where

import Data.List (sortBy)
import Data.Ord (comparing)
import System.FilePath
import qualified Data.ByteString as BS

import Distribution.Package
import Distribution.Text

import Hackage.Security.Trusted
import Hackage.Security.TUF

{-------------------------------------------------------------------------------
  Multiple formats
-------------------------------------------------------------------------------}

-- | Some files might be available in mutual inter-derivable formats
--
-- INVARIANT: This list must be non-empty.
newtype MultipleFormats a = MultipleFormats {
    multipleFormatsList :: [(Format, a)]
  }
  deriving (Functor, Show)

-- | Contruct 'MultipleFormats'
--
-- Enforces the invariant that the list is non-empty.
multipleFormats :: [(Format, a)] -> MultipleFormats a
multipleFormats [] = error "MultipleFormats must be non-empty"
multipleFormats fs = MultipleFormats fs

-- | Used to index 'MultipleFormats'
data Format =
    FormatUncompressed
  | FormatCompressedGz
  deriving (Eq, Ord, Show)

preferFormat :: Format -> MultipleFormats a -> (Format, a)
preferFormat preferred (MultipleFormats fs) =
    case lookup preferred fs of
      Just a  -> (preferred, a)
      Nothing -> head fs

-- | Merge two 'MultipleFormats'
--
-- This should only be used when we are sure that the two 'MultipleFormats'
-- record the _same_ formats.
--
-- TODO: Ideally we'd express this in the types, but it gets a bit messy.
-- See also note for 'remoteFilePath'.
mergeMultipleFormats :: MultipleFormats a
                     -> MultipleFormats b
                     -> MultipleFormats (a, b)
mergeMultipleFormats (MultipleFormats xs) (MultipleFormats ys) =
    MultipleFormats $ zipWith aux (sortBy (comparing fst) xs)
                                  (sortBy (comparing fst) ys)
  where
    aux :: (Format, a) -> (Format, b) -> (Format, (a, b))
    aux (format, a) (_format, b) = (format, (a, b))

{-------------------------------------------------------------------------------
  Files
-------------------------------------------------------------------------------}

-- | Abstract definition of files we might have to download
data RemoteFile =
    -- | Timestamp metadata (@timestamp.json@)
    --
    -- We never have (explicit) file length available for timestamps.
    RemoteTimestamp

    -- | Root metadata (@root.json@)
    --
    -- For root information we may or may not have the file length available:
    --
    -- * If during the normal update process the new snapshot tells us the root
    --   information has changed, we can use the file length from the snapshot.
    -- * If however we need to update the root metadata due to a verification
    --   exception we do not know the file length.
  | RemoteRoot (Maybe (Trusted FileLength))

    -- | Snapshot metadata (@snapshot.json@)
    --
    -- We get file length of the snapshot from the timestamp.
  | RemoteSnapshot (Trusted FileLength)

    -- | Index
    --
    -- The index file length comes from the snapshot.
    --
    -- When we request that the index is downloaded, it is up to the repository
    -- to decide whether to download @00-index.tar@ or @00-index.tar.gz@.
    -- The callback is told which format was requested.
    --
    -- It is a bug to request a file that the repository does not provide
    -- (the snapshot should make it clear which files are available).
  | RemoteIndex (MultipleFormats (Trusted FileLength))

    -- | Actual package
    --
    -- Package file length comes from the corresponding @targets.json@.
  | RemotePkgTarGz PackageIdentifier (Trusted FileLength)

-- | Files that we might request from the local cache
data CachedFile =
    -- | Timestamp metadata (@timestamp.json@)
    CachedTimestamp

    -- | Root metadata (@root.json@)
  | CachedRoot

    -- | Snapshot metadata (@snapshot.json@)
  | CachedSnapshot
  deriving Show

-- | Files that we might request from the index
data IndexFile =
    -- | Package-specific metadata (@targets.json@)
    IndexPkgMetadata PackageIdentifier
  deriving Show

-- | Path to temporary file
type TempPath = FilePath

{-------------------------------------------------------------------------------
  Repository proper
-------------------------------------------------------------------------------}

-- | Repository
--
-- This is an abstract representation of a repository. It simply provides a way
-- to download metafiles and target files, without specifying how this is done.
-- For instance, for a local repository this could just be doing a file read,
-- whereas for remote repositories this could be using any kind of HTTP client.
data Repository = Repository {
    -- | Get a file from the server
    --
    -- Responsibilies of 'repWithRemote':
    --
    -- * Download the file from the repository and make it available at a
    --   temporary location
    -- * Use the provided file length to protect against endless data attacks.
    --   (Repositories such as local repositories that are not suspectible to
    --   endless data attacks can safely ignore this argument.)
    -- * Move the file from its temporary location to its permanent location
    --   if the callback returns successfully (where appropriate).
    --
    -- Responsibilities of the callback:
    --
    -- * Verify the file and throw an exception if verification fails.
    -- * Not modify or move the temporary file.
    --   (Thus it is safe for local repositories to directly pass the path
    --   into the local repository.)
    --
    -- TODO: We should make it clear to the Repository that we are downloading
    -- files after a verification error. Remote repositories can use this
    -- information to force proxies to get files upstream.
    repWithRemote :: forall a. RemoteFile -> (Format -> TempPath -> IO a) -> IO a

    -- | Get a cached file (if available)
  , repGetCached :: CachedFile -> IO (Maybe FilePath)

    -- | Get the cached root
    --
    -- This is a separate method only because clients must ALWAYS have root
    -- information available.
  , repGetCachedRoot :: IO FilePath

    -- | Clear all cached data
    --
    -- In particular, this should remove the snapshot and the timestamp.
    -- It would also be okay, but not required, to delete the index.
  , repClearCache :: IO ()

    -- | Get a file from the index
    --
    -- The use of a strict bytestring here is intentional: it means the
    -- Repository is free to keep the index open and just seek the handle
    -- for different files. Since we only extract small files, having the
    -- entire extracted file in memory is not an issue.
  , repGetFromIndex :: IndexFile -> IO (Maybe BS.ByteString)

    -- | Logging
  , repLog :: LogMessage -> IO ()
  }

data LogMessage =
    -- | Root information was updated
    --
    -- This message is issued when the root information is updated as part of
    -- the normal check for updates procedure. If the root information is
    -- updated because of a verification error WarningVerificationError is
    -- issued instead.
    LogRootUpdated

    -- | A verification error
    --
    -- Verification errors can be temporary, and may be resolved later; hence
    -- these are just warnings. (Verification errors that cannot be resolved
    -- are thrown as exceptions.)
  | LogVerificationError VerificationError

{-------------------------------------------------------------------------------
  Paths
-------------------------------------------------------------------------------}

-- TODO: Ideally we'd use a GADT to connect the multiple formats of the result
-- with the particular kind of remote file. However, the details are a bit
-- messy so for now we don't.
remoteFilePath :: RemoteFile -> MultipleFormats FilePath
remoteFilePath RemoteTimestamp = MultipleFormats $
    [ (FormatUncompressed, "timestamp.json") ]
remoteFilePath (RemoteRoot _) = MultipleFormats $
    [ (FormatUncompressed, "root.json") ]
remoteFilePath (RemoteSnapshot _) = MultipleFormats $
    [ (FormatUncompressed, "snapshot.json") ]
remoteFilePath (RemoteIndex (MultipleFormats lens)) = MultipleFormats $
    map aux lens
  where
    aux :: (Format, a) -> (Format, FilePath)
    aux (FormatUncompressed, _) = (FormatUncompressed, "00-index.tar")
    aux (FormatCompressedGz, _) = (FormatCompressedGz, "00-index.tar.gz")
remoteFilePath (RemotePkgTarGz pkgId _) = MultipleFormats $
    [ (FormatCompressedGz, pkgLoc pkgId </> pkgTarGz pkgId) ]

cachedFilePath :: CachedFile -> FilePath
cachedFilePath CachedTimestamp    = "timestamp.json"
cachedFilePath CachedRoot         = "root.json"
cachedFilePath CachedSnapshot     = "snapshot.json"

indexFilePath :: IndexFile -> FilePath
indexFilePath (IndexPkgMetadata pkgId) = pkgLoc pkgId </> "targets.json"

pkgLoc :: PackageIdentifier -> FilePath
pkgLoc pkgId = display (packageName pkgId) </> display (packageVersion pkgId)

-- TODO: Are we hardcoding information here that's available from Cabal somewhere?
pkgTarGz :: PackageIdentifier -> FilePath
pkgTarGz pkgId = concat [
      display (packageName pkgId)
    , "-"
    , display (packageVersion pkgId)
    , ".tar.gz"
    ]

{-------------------------------------------------------------------------------
  Utility
-------------------------------------------------------------------------------}

-- | Is a particular remote file cached?
data IsCached =
    -- | This remote file should be cached, and we ask for it by name
    CacheAs CachedFile

    -- | We don't cache this remote file
    --
    -- This doesn't mean a Repository should not feel free to cache the file
    -- if desired, but it does mean the generic algorithms will never ask for
    -- this file from the cache.
  | DontCache

    -- | The index is somewhat special: it should be cached, but we never
    -- ask for it directly.
    --
    -- Instead, we will ask the Repository for files _from_ the index, which it
    -- can serve however it likes. For instance, some repositories might keep
    -- the index in uncompressed form, others in compressed form; some might
    -- keep an index tarball index for quick access, others may scan the tarball
    -- linearly, etc.
  | CacheIndex

-- | Which remote files should we cache locally?
mustCache :: RemoteFile -> IsCached
mustCache RemoteTimestamp      = CacheAs CachedTimestamp
mustCache (RemoteRoot _)       = CacheAs CachedRoot
mustCache (RemoteSnapshot _)   = CacheAs CachedSnapshot
mustCache (RemoteIndex {})     = CacheIndex
mustCache (RemotePkgTarGz _ _) = DontCache

formatLogMessage :: LogMessage -> String
formatLogMessage LogRootUpdated =
    "Root info updated"
formatLogMessage (LogVerificationError err) =
    "Verification error: " ++ formatVerificationError err
