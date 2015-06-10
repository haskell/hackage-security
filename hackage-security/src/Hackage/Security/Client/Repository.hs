module Hackage.Security.Client.Repository (
    -- * Files
    RemoteFile(..)
  , CachedFile(..)
  , IndexFile(..)
  , remoteFileNonEmpty
    -- * Repository proper
  , Repository(..)
  , TempPath
  , LogMessage(..)
  , UpdateFailure(..)
    -- ** Helpers
  , mirrorsUnsupported
    -- * Paths
  , remoteFilePath
  , cachedFilePath
  , indexFilePath
    -- * Names of package files
  , pkgTarGz
    -- * Recoverable exceptions
  , RecoverableException(..)
  , CustomException(..)
  , catchRecoverable
    -- * Utility
  , IsCached(..)
  , mustCache
  , formatLogMessage
  , formatUpdateFailure
  , describeRemoteFile
  ) where

import Control.Exception
import Data.Typeable
import System.FilePath
import qualified Data.ByteString as BS

import Distribution.Package
import Distribution.Text

import Hackage.Security.Client.Formats
import Hackage.Security.Trusted
import Hackage.Security.TUF
import Hackage.Security.Util.Stack

{-------------------------------------------------------------------------------
  Files
-------------------------------------------------------------------------------}

-- | Abstract definition of files we might have to download
--
-- 'RemoteFile' is parametrized by the type of the formats that we can accept
-- from the remote repository.
data RemoteFile :: * -> * where
    -- | Timestamp metadata (@timestamp.json@)
    --
    -- We never have (explicit) file length available for timestamps.
    RemoteTimestamp :: RemoteFile (FormatUncompressed :- ())

    -- | Root metadata (@root.json@)
    --
    -- For root information we may or may not have the file length available:
    --
    -- * If during the normal update process the new snapshot tells us the root
    --   information has changed, we can use the file length from the snapshot.
    -- * If however we need to update the root metadata due to a verification
    --   exception we do not know the file length.
    -- * We also do not know the file length during bootstrapping.
    RemoteRoot :: Maybe (Trusted FileLength)
               -> RemoteFile (FormatUncompressed :- ())

    -- | Snapshot metadata (@snapshot.json@)
    --
    -- We get file length of the snapshot from the timestamp.
    RemoteSnapshot :: Trusted FileLength
                   -> RemoteFile (FormatUncompressed :- ())

    -- | Mirrors metadata (@mirrors.json@)
    --
    -- We get the file length from the snapshot.
    RemoteMirrors :: Trusted FileLength
                  -> RemoteFile (FormatUncompressed :- ())

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
    RemoteIndex :: NonEmpty fs
                -> Formats fs (Trusted FileLength)
                -> RemoteFile fs

    -- | Actual package
    --
    -- Package file length comes from the corresponding @targets.json@.
    RemotePkgTarGz :: PackageIdentifier
                   -> Trusted FileLength
                   -> RemoteFile (FormatCompressedGz :- ())

deriving instance Eq   (RemoteFile fs)
deriving instance Show (RemoteFile fs)

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
type TempPath = FilePath

-- | Proof that remote files must always have at least one format
remoteFileNonEmpty :: RemoteFile fs -> NonEmpty fs
remoteFileNonEmpty RemoteTimestamp      = NonEmpty
remoteFileNonEmpty (RemoteRoot _)       = NonEmpty
remoteFileNonEmpty (RemoteSnapshot _)   = NonEmpty
remoteFileNonEmpty (RemoteMirrors _)    = NonEmpty
remoteFileNonEmpty (RemotePkgTarGz _ _) = NonEmpty
remoteFileNonEmpty (RemoteIndex pf _)   = pf

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
    --
    -- NOTE: Calls to 'repWithRemote' should _always_ be in the scope of
    -- 'repWithMirror'.
    repWithRemote :: forall a fs. RemoteFile fs
                  -> (SelectedFormat fs -> TempPath -> IO a)
                  -> IO a

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

    -- | Description of the repository (used in the show instance)
  , repDescription :: String
  }

instance Show Repository where
  show = repDescription

-- | Helper function to implement 'repWithMirrors'.
mirrorsUnsupported :: Maybe [Mirror] -> IO a -> IO a
mirrorsUnsupported _ = id

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
  | LogDownloading String

    -- | Incrementally updating a file from a repository
  | LogUpdating String

    -- | Selected a particular mirror
  | LogSelectedMirror MirrorDescription

    -- | Updating a file failed
    -- (we will try again by downloading it whole)
  | LogUpdateFailed FileDescription UpdateFailure

    -- | We got an exception with a particular mirror
    -- (we will try with a different mirror if any are available)
  | LogMirrorFailed MirrorDescription RecoverableException

-- | Records why we are downloading a file rather than updating it.
data UpdateFailure =
    -- | Server only provides compressed form of the file
    UpdateImpossibleOnlyCompressed

    -- | Server does not support incremental downloads
  | UpdateImpossibleUnsupported

    -- | We don't have a local copy of the file to update
  | UpdateImpossibleNoLocalCopy

    -- | Update failed
  | UpdateFailed RecoverableException

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
-- want to catch a ThreadKilled exception while updating a file and then
-- retry by downloading it.
data RecoverableException =
    RecoverIOException IOException
  | RecoverVerificationError VerificationError
  | RecoverCustom CustomException

-- | Wrapper for custom exceptions (for example, those defined in HTTP clients)
data CustomException where
    CustomException :: Exception e => e -> CustomException
  deriving (Typeable)

deriving instance Show CustomException
instance Exception CustomException

formatRecoverableException :: RecoverableException -> String
formatRecoverableException = go
  where
    -- TODO: Can we do better than @show@ for IO and custom exceptions?
    go (RecoverIOException       e) = show e
    go (RecoverVerificationError e) = formatVerificationError e
    go (RecoverCustom            e) = show e

catchRecoverable :: (IO a -> IO a)                  -- ^ Wrap custom exceptions
                 -> IO a                            -- ^ Action to execute
                 -> (RecoverableException -> IO a)  -- ^ Exception handler
                 -> IO a
catchRecoverable wrapCustom act handler = catches (wrapCustom act) [
      Handler $ handler . RecoverIOException
    , Handler $ handler . RecoverVerificationError
    , Handler $ handler . RecoverCustom
    ]

{-------------------------------------------------------------------------------
  Paths
-------------------------------------------------------------------------------}

remoteFilePath :: RemoteFile fs -> Formats fs FilePath
remoteFilePath RemoteTimestamp        = FsUn "timestamp.json"
remoteFilePath (RemoteRoot _)         = FsUn "root.json"
remoteFilePath (RemoteSnapshot _)     = FsUn "snapshot.json"
remoteFilePath (RemoteMirrors _)      = FsUn "mirrors.json"
remoteFilePath (RemotePkgTarGz pId _) = FsGz (pkgLoc pId </> pkgTarGz pId)
remoteFilePath (RemoteIndex _ lens)   = formatsMap aux lens
  where
    aux :: Format f -> a -> FilePath
    aux FUn _ = "00-index.tar"
    aux FGz _ = "00-index.tar.gz"

cachedFilePath :: CachedFile -> FilePath
cachedFilePath CachedTimestamp = "timestamp.json"
cachedFilePath CachedRoot      = "root.json"
cachedFilePath CachedSnapshot  = "snapshot.json"
cachedFilePath CachedMirrors   = "mirrors.json"

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
  deriving (Eq, Ord, Show)

-- | Which remote files should we cache locally?
mustCache :: RemoteFile fs -> IsCached
mustCache RemoteTimestamp      = CacheAs CachedTimestamp
mustCache (RemoteRoot _)       = CacheAs CachedRoot
mustCache (RemoteSnapshot _)   = CacheAs CachedSnapshot
mustCache (RemoteMirrors _)    = CacheAs CachedMirrors
mustCache (RemoteIndex {})     = CacheIndex
mustCache (RemotePkgTarGz _ _) = DontCache

formatLogMessage :: LogMessage -> String
formatLogMessage LogRootUpdated =
    "Root info updated"
formatLogMessage (LogVerificationError err) =
    "Verification error: " ++ formatVerificationError err
formatLogMessage (LogDownloading file) =
    "Downloading " ++ file
formatLogMessage (LogUpdating file) =
    "Updating " ++ file
formatLogMessage (LogSelectedMirror mirror) =
    "Selected mirror " ++ mirror
formatLogMessage (LogUpdateFailed file ex) =
    "Updating " ++ file ++ " failed (" ++ formatUpdateFailure ex ++ ")"
formatLogMessage (LogMirrorFailed mirror ex) =
       "Exception " ++ formatRecoverableException ex
    ++ " when using mirror " ++ mirror

formatUpdateFailure :: UpdateFailure -> String
formatUpdateFailure UpdateImpossibleOnlyCompressed =
    "server only provides file in compressed format"
formatUpdateFailure UpdateImpossibleUnsupported =
    "server does not provide incremental downloads"
formatUpdateFailure UpdateImpossibleNoLocalCopy =
    "no local copy"
formatUpdateFailure (UpdateFailed ex) =
    formatRecoverableException ex

describeRemoteFile :: RemoteFile fs -> String
describeRemoteFile RemoteTimestamp          = "timestamp"
describeRemoteFile (RemoteRoot _)           = "root"
describeRemoteFile (RemoteSnapshot _)       = "snapshot"
describeRemoteFile (RemoteMirrors _)        = "mirrors"
describeRemoteFile (RemoteIndex _ _)        = "index"
describeRemoteFile (RemotePkgTarGz pkgId _) = "package " ++ display pkgId
