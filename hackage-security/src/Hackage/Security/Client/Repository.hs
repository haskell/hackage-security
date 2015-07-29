-- | Abstract definition of a Repository
--
-- Most clients should only need to import this module if they wish to define
-- their own Repository implementations.
{-# LANGUAGE CPP #-}
module Hackage.Security.Client.Repository (
    -- * Files
    RemoteFile(..)
  , CachedFile(..)
  , IndexFile(..)
  , remoteFileDefaultFormat
    -- * Repository proper
  , Repository(..)
  , TempPath
  , IsRetry(..)
  , LogMessage(..)
  , UpdateFailure(..)
    -- ** Helpers
  , mirrorsUnsupported
    -- * Paths
  , remoteRepoPath
  , remoteRepoPath'
  , indexFilePath
    -- * Recoverable exceptions
  , SomeRecoverableException(..)
  , recoverableIsVerificationError
  , checkVerificationError
    -- * Utility
  , IsCached(..)
  , mustCache
  ) where

import Control.Exception
import Data.Typeable
import qualified Data.ByteString as BS

import Distribution.Package
import Distribution.Text

import Hackage.Security.Client.Formats
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

-- | Abstract definition of files we might have to download
--
-- 'RemoteFile' is parametrized by the type of the formats that we can accept
-- from the remote repository.
--
-- NOTE: Haddock lacks GADT support so constructors have only regular comments.
data RemoteFile :: * -> * where
    -- Timestamp metadata (@timestamp.json@)
    --
    -- We never have (explicit) file length available for timestamps.
    RemoteTimestamp :: RemoteFile (FormatUn :- ())

    -- Root metadata (@root.json@)
    --
    -- For root information we may or may not have the file length available:
    --
    -- - If during the normal update process the new snapshot tells us the root
    --   information has changed, we can use the file length from the snapshot.
    -- - If however we need to update the root metadata due to a verification
    --   exception we do not know the file length.
    -- - We also do not know the file length during bootstrapping.
    RemoteRoot :: Maybe (Trusted FileLength) -> RemoteFile (FormatUn :- ())

    -- Snapshot metadata (@snapshot.json@)
    --
    -- We get file length of the snapshot from the timestamp.
    RemoteSnapshot :: Trusted FileLength -> RemoteFile (FormatUn :- ())

    -- Mirrors metadata (@mirrors.json@)
    --
    -- We get the file length from the snapshot.
    RemoteMirrors :: Trusted FileLength -> RemoteFile (FormatUn :- ())

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
                -> Formats fs (Trusted FileLength)
                -> RemoteFile fs

    -- Actual package
    --
    -- Package file length comes from the corresponding @targets.json@.
    RemotePkgTarGz :: PackageIdentifier
                   -> Trusted FileLength
                   -> RemoteFile (FormatGz :- ())

deriving instance Eq   (RemoteFile fs)
deriving instance Show (RemoteFile fs)

instance Pretty (RemoteFile fs) where
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

-- | Files that we might request from the index
--
-- TODO: We should also provide a way to extract preferred versions info from
-- the tarball. After all, this is a security sensitive, as it might be used
-- for rollback/freeze attacks. Until we have author signing however this is
-- not a strict necessity, as the preferred versions comes from the index which
-- is itself signed.
data IndexFile =
    -- | Package-specific metadata (@targets.json@)
    IndexPkgMetadata PackageIdentifier
  deriving Show

-- | Path to temporary file
type TempPath = AbsolutePath

-- | Default format for each file type
--
-- For most file types we don't have a choice; for the index the repository
-- is only required to offer the GZip-compressed format so that is the default.
remoteFileDefaultFormat :: RemoteFile fs -> Some (HasFormat fs)
remoteFileDefaultFormat RemoteTimestamp      = Some $ HFZ FUn
remoteFileDefaultFormat (RemoteRoot _)       = Some $ HFZ FUn
remoteFileDefaultFormat (RemoteSnapshot _)   = Some $ HFZ FUn
remoteFileDefaultFormat (RemoteMirrors _)    = Some $ HFZ FUn
remoteFileDefaultFormat (RemotePkgTarGz _ _) = Some $ HFZ FGz
remoteFileDefaultFormat (RemoteIndex pf _)   = Some pf

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
    -- NOTE: Calls to 'repWithRemote' should _always_ be in the scope of
    -- 'repWithMirror'.
    repWithRemote :: forall a fs. Throws SomeRecoverableException
                  => IsRetry
                  -> RemoteFile fs
                  -> (forall f. HasFormat fs f -> TempPath -> IO a)
                  -> IO a

    -- | Get a cached file (if available)
  , repGetCached :: CachedFile -> IO (Maybe AbsolutePath)

    -- | Get the cached root
    --
    -- This is a separate method only because clients must ALWAYS have root
    -- information available.
  , repGetCachedRoot :: IO AbsolutePath

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

    -- | Description of the repository (used in the show instance)
  , repDescription :: String
  }

instance Show Repository where
  show = repDescription

-- | Helper function to implement 'repWithMirrors'.
mirrorsUnsupported :: Maybe [Mirror] -> IO a -> IO a
mirrorsUnsupported _ = id

-- | Are we requesting this information because of a previous validation error?
--
-- Clients can take advantage of this to tell caches to revalidate files.
data IsRetry = FirstAttempt | AfterVerificationError

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
  | LogDownloading (Some RemoteFile)

    -- | Incrementally updating a file from a repository
  | LogUpdating (Some RemoteFile)

    -- | Selected a particular mirror
  | LogSelectedMirror MirrorDescription

    -- | Updating a file failed
    -- (we will try again by downloading it whole)
  | LogUpdateFailed (Some RemoteFile) UpdateFailure

    -- | We got an exception with a particular mirror
    -- (we will try with a different mirror if any are available)
  | LogMirrorFailed MirrorDescription SomeRecoverableException

-- | Records why we are downloading a file rather than updating it.
data UpdateFailure =
    -- | Server only provides compressed form of the file
    UpdateImpossibleOnlyCompressed

    -- | Server does not support incremental downloads
  | UpdateImpossibleUnsupported

    -- | We don't have a local copy of the file to update
  | UpdateImpossibleNoLocalCopy

    -- | Updating the local file would actually mean downloading
    -- MORE data then doing a regular download.
  | UpdateTooLarge

    -- | Update failed
  | UpdateFailed SomeRecoverableException

{-------------------------------------------------------------------------------
  Recoverable exceptions
-------------------------------------------------------------------------------}

-- | An exception that we might be able to recover from
--
-- Example use cases:
--
-- * When we are updating a file incrementally rather than downloading it
-- * When we are using a particular mirror (but might choose another)
--
-- In examples such as these we can catch these 'RecoverableException's,
-- but we don't want to catch just any odd exception. For example, we don't
-- want to catch a ThreadKilled exception while incrementally updating a file
-- and then retry by downloading it.
data SomeRecoverableException :: * where
    SomeRecoverableException :: Exception e => e -> SomeRecoverableException
  deriving (Typeable)

#if MIN_VERSION_base(4,8,0)

deriving instance Show SomeRecoverableException
instance Exception SomeRecoverableException
  displayException (SomeRecoverableException ex) = displayException ex

#else

instance Exception SomeRecoverableException
instance Show SomeRecoverableException where
  show (SomeRecoverableException ex) = show ex

#endif

instance Pretty SomeRecoverableException where
    pretty (SomeRecoverableException ex) = displayException ex

recoverableIsVerificationError :: SomeRecoverableException
                               -> Maybe VerificationError
recoverableIsVerificationError (SomeRecoverableException ex) = cast ex

checkVerificationError :: Throws SomeRecoverableException => IO a -> IO a
checkVerificationError = handle $ \(ex :: VerificationError) ->
    throwChecked $ SomeRecoverableException ex

{-------------------------------------------------------------------------------
  Paths
-------------------------------------------------------------------------------}

remoteRepoPath :: RepoLayout -> RemoteFile fs -> Formats fs RepoPath
remoteRepoPath RepoLayout{..} = go
  where
    go :: RemoteFile fs -> Formats fs RepoPath
    go RemoteTimestamp        = FsUn $ repoLayoutTimestamp
    go (RemoteRoot _)         = FsUn $ repoLayoutRoot
    go (RemoteSnapshot _)     = FsUn $ repoLayoutSnapshot
    go (RemoteMirrors _)      = FsUn $ repoLayoutMirrors
    go (RemotePkgTarGz pId _) = FsGz $ repoLayoutPkgTarGz pId
    go (RemoteIndex _ lens)   = formatsMap goIndex lens

    goIndex :: Format f -> a -> RepoPath
    goIndex FUn _ = repoLayoutIndexTar
    goIndex FGz _ = repoLayoutIndexTarGz

remoteRepoPath' :: RepoLayout -> RemoteFile fs -> HasFormat fs f -> RepoPath
remoteRepoPath' repoLayout file format =
    formatsLookup format $ remoteRepoPath repoLayout file

indexFilePath :: IndexLayout -> IndexFile -> IndexPath
indexFilePath IndexLayout{..} = go
  where
    go :: IndexFile -> IndexPath
    go (IndexPkgMetadata pkgId) = indexLayoutPkgMetadata pkgId

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
  deriving (Eq, Ord, Show)

-- | Which remote files should we cache locally?
mustCache :: RemoteFile fs -> IsCached
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
  pretty (LogDownloading (Some file)) =
      "Downloading " ++ pretty file
  pretty (LogUpdating (Some file)) =
      "Updating " ++ pretty file
  pretty (LogSelectedMirror mirror) =
      "Selected mirror " ++ mirror
  pretty (LogUpdateFailed (Some file) ex) =
      "Updating " ++ pretty file ++ " failed (" ++ pretty ex ++ ")"
  pretty (LogMirrorFailed mirror ex) =
      "Exception " ++ pretty ex ++ " when using mirror " ++ mirror

instance Pretty UpdateFailure where
  pretty UpdateImpossibleOnlyCompressed =
      "server only provides file in compressed pretty"
  pretty UpdateImpossibleUnsupported =
      "server does not provide incremental downloads"
  pretty UpdateImpossibleNoLocalCopy =
      "no local copy"
  pretty UpdateTooLarge =
      "update too large"
  pretty (UpdateFailed ex) =
      pretty ex
