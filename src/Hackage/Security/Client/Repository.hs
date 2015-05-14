module Hackage.Security.Client.Repository (
    Repository(..)
  , File(..)
  , TempPath
  ) where

import Distribution.Package (PackageIdentifier)

import Hackage.Security.Trusted
import Hackage.Security.TUF

-- | Abstract definition of a file to be provided by a Repository
--
-- We parametrize 'File' by the information we provide the Repository about
-- this file. In practice, we either instantiate this by a 'FileLength' (to
-- provide against endless data attacks) or '()' (for local files).
data File a =
    -- | The timestamp metadata (@timestamp.json@)
    --
    -- We never have (explicit) file length available for timestamps.
    FileTimestamp

    -- | The root metadata (@root.json@)
    --
    -- For root information we may or may not have the file length available:
    --
    -- * If during the normal update process the new snapshot tells us the root
    --   information has changed, we can use the file length from the snapshot.
    -- * If however we need to update the root metadata due to a verification
    --   exception we do not know the file length.
  | FileRoot (Maybe a)

    -- | The snapshot metadata (@snapshot.json@)
    --
    -- We get file length of the snapshot from the timestamp.
  | FileSnapshot a

    -- | The index
    --
    -- The index file length comes from the snapshot.
    --
    -- When we request that the index is downloaded, it is up to the repository
    -- to decide whether to download @00-index.tar@ or @00-index.tar.gz@. We
    -- can see from the returned filename which file we are given.
    --
    -- It is not required for repositories to provide the uncompressed tarball,
    -- so the file length for the @.tar@ file is optional.
  | FileIndex {
        fileIndexTarGzInfo :: a
      , fileIndexTarInfo   :: Maybe a
      }

    -- | An actual package
    --
    -- Package file length comes from the corresponding @targets.json@.
  | FilePkgTarGz PackageIdentifier a

    -- | Target file for a specific package
    --
    -- This is extracted from the local copy of the index tarball so does not
    -- a file length.
  | FilePkgMeta PackageIdentifier
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
    repWithRemote :: forall a.
                     File (Trusted FileLength)
                  -> (TempPath -> IO a)
                  -> IO a

    -- | Get a cached file (if available)
  , repGetCached :: File () -> IO (Maybe FilePath)

    -- | Get the cached root
    --
    -- This is a separate method only because clients must ALWAYS have root
    -- information available.
  , repGetCachedRoot :: IO FilePath

    -- | Delete a previously downloaded remote file
    -- (probably because the root metadata changed)
  , repDeleteCached :: File () -> IO ()
  }
