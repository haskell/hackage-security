module Hackage.Security.Client.Repository (
    Repository(..)
  , RemoteFile(..)
  , CachedFile(..)
  , TempPath
  , LogMessage(..)
    -- * Utility
  , mustCache
  , formatLogMessage
  ) where

import Distribution.Package (PackageIdentifier)

import Hackage.Security.Trusted
import Hackage.Security.TUF

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
    -- to decide whether to download @00-index.tar@ or @00-index.tar.gz@. We
    -- can see from the returned filename which file we are given.
    --
    -- It is not required for repositories to provide the uncompressed tarball,
    -- so the file length for the @.tar@ file is optional.
  | RemoteIndex {
        fileIndexTarGzInfo :: Trusted FileLength
      , fileIndexTarInfo   :: Maybe (Trusted FileLength)
      }

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

    -- | Index (uncompressed)
  | CachedIndexTar
  deriving Show

-- | Path to temporary file
type TempPath = FilePath

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
    repWithRemote :: forall a. RemoteFile -> (TempPath -> IO a) -> IO a

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
  Utility
-------------------------------------------------------------------------------}

-- | Which remote files should we cache locally?
mustCache :: RemoteFile -> Maybe CachedFile
mustCache RemoteTimestamp      = Just CachedTimestamp
mustCache (RemoteRoot _)       = Just CachedRoot
mustCache (RemoteSnapshot _)   = Just CachedSnapshot
mustCache (RemoteIndex {})     = Just CachedIndexTar
mustCache (RemotePkgTarGz _ _) = Nothing

formatLogMessage :: LogMessage -> String
formatLogMessage LogRootUpdated =
    "Root info updated"
formatLogMessage (LogVerificationError err) =
    "Verification error " ++ formatVerificationError err
