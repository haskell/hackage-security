-- | Abstract definition of a Repository
--
-- Most clients should only need to import this module if they wish to define
-- their own Repository implementations.
{-# LANGUAGE CPP #-}
module Hackage.Security.Client.Repository (
    -- * Files
    Metadata  -- type index (really a kind)
  , Binary    -- type index (really a kind)
  , RemoteFile(..)
  , CachedFile(..)
  , IndexFile(..)
  , remoteFileDefaultFormat
  , remoteFileDefaultInfo
    -- * Repository proper
  , Repository(..)
  , AttemptNr(..)
  , LogMessage(..)
  , UpdateFailure(..)
  , SomeRemoteError(..)
    -- ** Downloaded files
  , DownloadedFile(..)
    -- ** Helpers
  , mirrorsUnsupported
    -- * Paths
  , remoteRepoPath
  , remoteRepoPath'
    -- * Utility
  , IsCached(..)
  , mustCache
  ) where

import Control.Exception
import Data.Typeable (Typeable)
import qualified Codec.Archive.Tar.Index as Tar
import qualified Data.ByteString.Lazy    as BS.L

import Distribution.Package
import Distribution.Text

import Hackage.Security.Client.Formats
import Hackage.Security.Client.Verify
import Hackage.Security.Trusted
import Hackage.Security.TUF
import Hackage.Security.Util.Checked
import Hackage.Security.Util.Path
import Hackage.Security.Util.Pretty
import Hackage.Security.Util.Some
import Hackage.Security.Util.Stack

{-------------------------------------------------------------------------------
  Files
-------------------------------------------------------------------------------}

data Metadata
data Binary

-- | Abstract definition of files we might have to download
--
-- 'RemoteFile' is parametrized by the type of the formats that we can accept
-- from the remote repository, as well as with information on whether this file
-- is metadata actual binary content.
--
-- NOTE: Haddock lacks GADT support so constructors have only regular comments.
data RemoteFile :: * -> * -> * where
    -- Timestamp metadata (@timestamp.json@)
    --
    -- We never have (explicit) file length available for timestamps.
    RemoteTimestamp :: RemoteFile (FormatUn :- ()) Metadata

    -- Root metadata (@root.json@)
    --
    -- For root information we may or may not have the file info available:
    --
    -- - If during the normal update process the new snapshot tells us the root
    --   information has changed, we can use the file info from the snapshot.
    -- - If however we need to update the root metadata due to a verification
    --   exception we do not know the file info.
    -- - We also do not know the file info during bootstrapping.
    RemoteRoot :: Maybe (Trusted FileInfo) -> RemoteFile (FormatUn :- ()) Metadata

    -- Snapshot metadata (@snapshot.json@)
    --
    -- We get file info of the snapshot from the timestamp.
    RemoteSnapshot :: Trusted FileInfo -> RemoteFile (FormatUn :- ()) Metadata

    -- Mirrors metadata (@mirrors.json@)
    --
    -- We get the file info from the snapshot.
    RemoteMirrors :: Trusted FileInfo -> RemoteFile (FormatUn :- ()) Metadata

    -- Index
    --
    -- The index file length comes from the snapshot.
    --
    -- When we request that the index is downloaded, it is up to the repository
    -- to decide whether to download @00-index.tar@ or @00-index.tar.gz@.
    -- The callback is told which format was requested.
    --
    -- It is a bug to request a file that the repository does not provide
    -- (the snapshot should make it clear which files are available).
    RemoteIndex :: HasFormat fs FormatGz
                -> Formats fs (Trusted FileInfo)
                -> RemoteFile fs Binary

    -- Actual package
    --
    -- Package file length comes from the corresponding @targets.json@.
    RemotePkgTarGz :: PackageIdentifier
                   -> Trusted FileInfo
                   -> RemoteFile (FormatGz :- ()) Binary

deriving instance Show (RemoteFile fs typ)

instance Pretty (RemoteFile fs typ) where
  pretty RemoteTimestamp          = "timestamp"
  pretty (RemoteRoot _)           = "root"
  pretty (RemoteSnapshot _)       = "snapshot"
  pretty (RemoteMirrors _)        = "mirrors"
  pretty (RemoteIndex _ _)        = "index"
  pretty (RemotePkgTarGz pkgId _) = "package " ++ display pkgId

-- | Files that we might request from the local cache
data CachedFile =
    -- | Timestamp metadata (@timestamp.json@)
    CachedTimestamp

    -- | Root metadata (@root.json@)
  | CachedRoot

    -- | Snapshot metadata (@snapshot.json@)
  | CachedSnapshot

    -- | Mirrors list (@mirrors.json@)
  | CachedMirrors
  deriving (Eq, Ord, Show)

instance Pretty CachedFile where
  pretty CachedTimestamp = "timestamp"
  pretty CachedRoot      = "root"
  pretty CachedSnapshot  = "snapshot"
  pretty CachedMirrors   = "mirrors"

-- | Default format for each file type
--
-- For most file types we don't have a choice; for the index the repository
-- is only required to offer the GZip-compressed format so that is the default.
remoteFileDefaultFormat :: RemoteFile fs typ -> Some (HasFormat fs)
remoteFileDefaultFormat RemoteTimestamp      = Some $ HFZ FUn
remoteFileDefaultFormat (RemoteRoot _)       = Some $ HFZ FUn
remoteFileDefaultFormat (RemoteSnapshot _)   = Some $ HFZ FUn
remoteFileDefaultFormat (RemoteMirrors _)    = Some $ HFZ FUn
remoteFileDefaultFormat (RemotePkgTarGz _ _) = Some $ HFZ FGz
remoteFileDefaultFormat (RemoteIndex pf _)   = Some pf

-- | Default file info (see also 'remoteFileDefaultFormat')
remoteFileDefaultInfo :: RemoteFile fs typ -> Maybe (Trusted FileInfo)
remoteFileDefaultInfo RemoteTimestamp         = Nothing
remoteFileDefaultInfo (RemoteRoot info)       = info
remoteFileDefaultInfo (RemoteSnapshot info)   = Just info
remoteFileDefaultInfo (RemoteMirrors info)    = Just info
remoteFileDefaultInfo (RemotePkgTarGz _ info) = Just info
remoteFileDefaultInfo (RemoteIndex pf info)   = Just $ formatsLookup pf info

{-------------------------------------------------------------------------------
  Repository proper
-------------------------------------------------------------------------------}

-- | Repository
--
-- This is an abstract representation of a repository. It simply provides a way
-- to download metafiles and target files, without specifying how this is done.
-- For instance, for a local repository this could just be doing a file read,
-- whereas for remote repositories this could be using any kind of HTTP client.
data Repository down = DownloadedFile down => Repository {
    -- | Get a file from the server
    --
    -- Responsibilies of 'repGetRemote':
    --
    -- * Download the file from the repository and make it available at a
    --   temporary location
    -- * Use the provided file length to protect against endless data attacks.
    --   (Repositories such as local repositories that are not suspectible to
    --   endless data attacks can safely ignore this argument.)
    -- * Move the file from its temporary location to its permanent location
    --   if verification succeeds.
    --
    -- NOTE: Calls to 'repGetRemote' should _always_ be in the scope of
    -- 'repWithMirror'.
    repGetRemote :: forall fs typ. Throws SomeRemoteError
                 => AttemptNr
                 -> RemoteFile fs typ
                 -> Verify (Some (HasFormat fs), down typ)

    -- | Get a cached file (if available)
  , repGetCached :: CachedFile -> IO (Maybe (Path Absolute))

    -- | Get the cached root
    --
    -- This is a separate method only because clients must ALWAYS have root
    -- information available.
  , repGetCachedRoot :: IO (Path Absolute)

    -- | Clear all cached data
    --
    -- In particular, this should remove the snapshot and the timestamp.
    -- It would also be okay, but not required, to delete the index.
  , repClearCache :: IO ()

    -- | Open the tarball for reading
    --
    -- This function has this shape so that:
    --
    -- * We can read multiple files from the tarball without having to open
    --   and close the handle each time
    -- * We can close the handle immediately when done.
  , repWithIndex :: forall a. (Handle -> IO a) -> IO a

    -- | Read the index index
  , repGetIndexIdx :: IO Tar.TarIndex

    -- | Lock the cache (during updates)
  , repLockCache :: IO () -> IO ()

    -- | Mirror selection
    --
    -- The purpose of 'repWithMirror' is to scope mirror selection. The idea
    -- is that if we have
    --
    -- > repWithMirror mirrorList $
    -- >   someCallback
    --
    -- then the repository may pick a mirror before calling @someCallback@,
    -- catch exceptions thrown by @someCallback@, and potentially try the
    -- callback again with a different mirror.
    --
    -- The list of mirrors may be @Nothing@ if we haven't yet downloaded the
    -- list of mirrors from the repository, or when our cached list of mirrors
    -- is invalid. Of course, if we did download it, then the list of mirrors
    -- may still be empty. In this case the repository must fall back to its
    -- primary download mechanism.
    --
    -- Mirrors as currently defined (in terms of a "base URL") are inherently a
    -- HTTP (or related) concept, so in repository implementations such as the
    -- local-repo 'repWithMirrors' is probably just an identity operation  (see
    -- 'ignoreMirrors').  Conversely, HTTP implementations of repositories may
    -- have other, out-of-band information (for example, coming from a cabal
    -- config file) that they may use to influence mirror selection.
  , repWithMirror :: forall a. Maybe [Mirror] -> IO a -> IO a

    -- | Logging
  , repLog :: LogMessage -> IO ()

    -- | Layout of this repository
  , repLayout :: RepoLayout

    -- | Layout of the index
    --
    -- Since the repository hosts the index, the layout of the index is
    -- not independent of the layout of the repository.
  , repIndexLayout :: IndexLayout

    -- | Description of the repository (used in the show instance)
  , repDescription :: String
  }

instance Show (Repository down) where
  show = repDescription

-- | Helper function to implement 'repWithMirrors'.
mirrorsUnsupported :: Maybe [Mirror] -> IO a -> IO a
mirrorsUnsupported _ = id

-- | Are we requesting this information because of a previous validation error?
--
-- Clients can take advantage of this to tell caches to revalidate files.
newtype AttemptNr = AttemptNr Int
  deriving (Eq, Ord, Num)

-- | Log messages
--
-- We use a 'RemoteFile' rather than a 'RepoPath' here because we might not have
-- a 'RepoPath' for the file that we were trying to download (that is, for
-- example if the server does not provide an uncompressed tarball, it doesn't
-- make much sense to list the path to that non-existing uncompressed tarball).
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

    -- | Download a file from a repository
  | forall fs typ. LogDownloading (RemoteFile fs typ)

    -- | Incrementally updating a file from a repository
  | forall fs. LogUpdating (RemoteFile fs Binary)

    -- | Selected a particular mirror
  | LogSelectedMirror MirrorDescription

    -- | Updating a file failed
    -- (we will instead download it whole)
  | forall fs. LogCannotUpdate (RemoteFile fs Binary) UpdateFailure

    -- | We got an exception with a particular mirror
    -- (we will try with a different mirror if any are available)
  | LogMirrorFailed MirrorDescription SomeException

    -- | This log event is triggered before invoking a filesystem lock
    -- operation that may block for a significant amount of time; once
    -- the possibly blocking call completes successfully,
    -- 'LogLockWaitDone' will be emitted.
    --
    -- @since 0.6.0
  | LogLockWait (Path Absolute)

    -- | Denotes completion of the operation that advertised a
    -- 'LogLockWait' event
    --
    -- @since 0.6.0
  | LogLockWaitDone (Path Absolute)

    -- | Denotes the filesystem lock previously acquired (signaled by
    -- 'LogLockWait') has been released.
    --
    -- @since 0.6.0
  | LogUnlock (Path Absolute)


-- | Records why we are downloading a file rather than updating it.
data UpdateFailure =
    -- | Server does not support incremental downloads
    UpdateImpossibleUnsupported

    -- | We don't have a local copy of the file to update
  | UpdateImpossibleNoLocalCopy

    -- | Update failed twice
    --
    -- If we attempt an incremental update the first time, and it fails,  we let
    -- it go round the loop, update local security information, and try again.
    -- But if an incremental update then fails _again_, we  instead attempt a
    -- regular download.
  | UpdateFailedTwice

    -- | Update failed (for example: perhaps the local file got corrupted)
  | UpdateFailed SomeException

{-------------------------------------------------------------------------------
  Downloaded files
-------------------------------------------------------------------------------}

class DownloadedFile (down :: * -> *) where
  -- | Verify a download file
  downloadedVerify :: down a -> Trusted FileInfo -> IO Bool

  -- | Read the file we just downloaded into memory
  --
  -- We never read binary data, only metadata.
  downloadedRead :: down Metadata -> IO BS.L.ByteString

  -- | Copy a downloaded file to its destination
  downloadedCopyTo :: down a -> Path Absolute -> IO ()

{-------------------------------------------------------------------------------
  Exceptions thrown by specific Repository implementations
-------------------------------------------------------------------------------}

-- | Repository-specific exceptions
--
-- For instance, for repositories using HTTP this might correspond to a 404;
-- for local repositories this might correspond to file-not-found, etc.
data SomeRemoteError :: * where
    SomeRemoteError :: Exception e => e -> SomeRemoteError
  deriving (Typeable)

#if MIN_VERSION_base(4,8,0)
deriving instance Show SomeRemoteError
instance Exception SomeRemoteError where displayException = pretty
#else
instance Exception SomeRemoteError
instance Show SomeRemoteError where show = pretty
#endif

instance Pretty SomeRemoteError where
    pretty (SomeRemoteError ex) = displayException ex

{-------------------------------------------------------------------------------
  Paths
-------------------------------------------------------------------------------}

remoteRepoPath :: RepoLayout -> RemoteFile fs typ -> Formats fs RepoPath
remoteRepoPath RepoLayout{..} = go
  where
    go :: RemoteFile fs typ -> Formats fs RepoPath
    go RemoteTimestamp        = FsUn $ repoLayoutTimestamp
    go (RemoteRoot _)         = FsUn $ repoLayoutRoot
    go (RemoteSnapshot _)     = FsUn $ repoLayoutSnapshot
    go (RemoteMirrors _)      = FsUn $ repoLayoutMirrors
    go (RemotePkgTarGz pId _) = FsGz $ repoLayoutPkgTarGz pId
    go (RemoteIndex _ lens)   = formatsMap goIndex lens

    goIndex :: Format f -> a -> RepoPath
    goIndex FUn _ = repoLayoutIndexTar
    goIndex FGz _ = repoLayoutIndexTarGz

remoteRepoPath' :: RepoLayout -> RemoteFile fs typ -> HasFormat fs f -> RepoPath
remoteRepoPath' repoLayout file format =
    formatsLookup format $ remoteRepoPath repoLayout file

{-------------------------------------------------------------------------------
  Utility
-------------------------------------------------------------------------------}

-- | Is a particular remote file cached?
data IsCached :: * -> * where
    -- This remote file should be cached, and we ask for it by name
    CacheAs :: CachedFile -> IsCached Metadata

    -- We don't cache this remote file
    --
    -- This doesn't mean a Repository should not feel free to cache the file
    -- if desired, but it does mean the generic algorithms will never ask for
    -- this file from the cache.
    DontCache :: IsCached Binary

    -- The index is somewhat special: it should be cached, but we never
    -- ask for it directly.
    --
    -- Instead, we will ask the Repository for files _from_ the index, which it
    -- can serve however it likes. For instance, some repositories might keep
    -- the index in uncompressed form, others in compressed form; some might
    -- keep an index tarball index for quick access, others may scan the tarball
    -- linearly, etc.
    CacheIndex :: IsCached Binary
--TODO: ^^ older haddock doesn't support GADT doc comments :-(

deriving instance Eq   (IsCached typ)
deriving instance Show (IsCached typ)

-- | Which remote files should we cache locally?
mustCache :: RemoteFile fs typ -> IsCached typ
mustCache RemoteTimestamp      = CacheAs CachedTimestamp
mustCache (RemoteRoot _)       = CacheAs CachedRoot
mustCache (RemoteSnapshot _)   = CacheAs CachedSnapshot
mustCache (RemoteMirrors _)    = CacheAs CachedMirrors
mustCache (RemoteIndex {})     = CacheIndex
mustCache (RemotePkgTarGz _ _) = DontCache

instance Pretty LogMessage where
  pretty LogRootUpdated =
      "Root info updated"
  pretty (LogVerificationError err) =
      "Verification error: " ++ pretty err
  pretty (LogDownloading file) =
      "Downloading " ++ pretty file
  pretty (LogUpdating file) =
      "Updating " ++ pretty file
  pretty (LogSelectedMirror mirror) =
      "Selected mirror " ++ mirror
  pretty (LogCannotUpdate file ex) =
      "Cannot update " ++ pretty file ++ " (" ++ pretty ex ++ ")"
  pretty (LogMirrorFailed mirror ex) =
      "Exception " ++ displayException ex ++ " when using mirror " ++ mirror
  pretty (LogLockWait file) =
      "Waiting to acquire cache lock on " ++ pretty file
  pretty (LogLockWaitDone file) =
      "Acquired cache lock on " ++ pretty file
  pretty (LogUnlock file) =
      "Released cache lock on " ++ pretty file

instance Pretty UpdateFailure where
  pretty UpdateImpossibleUnsupported =
      "server does not provide incremental downloads"
  pretty UpdateImpossibleNoLocalCopy =
      "no local copy"
  pretty UpdateFailedTwice =
      "update failed twice"
  pretty (UpdateFailed ex) =
      displayException ex
