-- | Local repository
module Hackage.Security.Client.Repository.Local (
    LocalRepo
  , LocalFile -- opaque
  , withRepository
  ) where

import Hackage.Security.Client.Formats
import Hackage.Security.Client.Repository
import Hackage.Security.Client.Repository.Cache
import Hackage.Security.Client.Verify
import Hackage.Security.TUF
import Hackage.Security.Trusted
import Hackage.Security.Util.IO
import Hackage.Security.Util.Path
import Hackage.Security.Util.Pretty
import Hackage.Security.Util.Some

-- | Location of the repository
--
-- Note that we regard the local repository as immutable; we cache files just
-- like we do for remote repositories.
type LocalRepo = Path Absolute

-- | Initialize the repository (and cleanup resources afterwards)
--
-- Like a remote repository, a local repository takes a RepoLayout as argument;
-- but where the remote repository interprets this RepoLayout relative to a URL,
-- the local repository interprets it relative to a local directory.
--
-- It uses the same cache as the remote repository.
withRepository
  :: LocalRepo                       -- ^ Location of local repository
  -> Cache                           -- ^ Location of local cache
  -> RepoLayout                      -- ^ Repository layout
  -> IndexLayout                     -- ^ Index layout
  -> (LogMessage -> IO ())           -- ^ Logger
  -> (Repository LocalFile -> IO a)  -- ^ Callback
  -> IO a
withRepository repo
               cache
               repLayout
               repIndexLayout
               logger
               callback
               =
  callback Repository {
      repGetRemote     = getRemote repLayout repo cache
    , repGetCached     = getCached     cache
    , repGetCachedRoot = getCachedRoot cache
    , repClearCache    = clearCache    cache
    , repWithIndex     = withIndex     cache
    , repGetIndexIdx   = getIndexIdx   cache
    , repLockCache     = lockCacheWithLogger logger cache
    , repWithMirror    = mirrorsUnsupported
    , repLog           = logger
    , repLayout        = repLayout
    , repIndexLayout   = repIndexLayout
    , repDescription   = "Local repository at " ++ pretty repo
    }

-- | Get a file from the server
getRemote :: RepoLayout -> LocalRepo -> Cache
          -> AttemptNr
          -> RemoteFile fs typ
          -> Verify (Some (HasFormat fs), LocalFile typ)
getRemote repoLayout repo cache _attemptNr remoteFile = do
    case remoteFileDefaultFormat remoteFile of
      Some format -> do
        let remotePath' = remoteRepoPath' repoLayout remoteFile format
            remotePath  = anchorRepoPathLocally repo remotePath'
            localFile   = LocalFile remotePath
        ifVerified $
          cacheRemoteFile cache
                          localFile
                          (hasFormatGet format)
                          (mustCache remoteFile)
        return (Some format, localFile)

{-------------------------------------------------------------------------------
  Files in the local repository
-------------------------------------------------------------------------------}

newtype LocalFile a = LocalFile (Path Absolute)

instance DownloadedFile LocalFile where
  downloadedVerify = verifyLocalFile
  downloadedRead   = \(LocalFile local) -> readLazyByteString local
  downloadedCopyTo = \(LocalFile local) -> copyFile local

verifyLocalFile :: LocalFile typ -> Trusted FileInfo -> IO Bool
verifyLocalFile (LocalFile fp) trustedInfo = do
    -- Verify the file size before comparing the entire file info
    sz <- FileLength <$> getFileSize fp
    if sz /= fileInfoLength (trusted trustedInfo)
      then return False
      else compareTrustedFileInfo (trusted trustedInfo) <$> computeFileInfo fp
