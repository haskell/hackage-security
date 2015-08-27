module TestSuite.InMemRepository (
    newInMemRepository
  ) where

-- stdlib
import Prelude hiding (log)
import qualified Data.ByteString as BS

-- hackage-security
import Hackage.Security.Client
import Hackage.Security.Client.Formats
import Hackage.Security.Client.Repository
import Hackage.Security.Util.Checked
import Hackage.Security.Util.Pretty

-- TestSuite
import TestSuite.InMemCache
import TestSuite.InMemRepo

newInMemRepository :: RepoLayout -> InMemRepo -> InMemCache -> Repository
newInMemRepository layout repo cache = Repository {
      repWithRemote    = withRemote    repo cache
    , repGetCached     = inMemGetCached     cache
    , repGetCachedRoot = inMemGetCachedRoot cache
    , repClearCache    = inMemClearCache    cache
    , repGetFromIndex  = getFromIndex
    , repWithMirror    = withMirror
    , repLog           = log
    , repLayout        = layout
    , repDescription   = "In memory repository"
    }

{-------------------------------------------------------------------------------
  Repository methods
-------------------------------------------------------------------------------}

-- | Get a file from the server
withRemote :: forall a fs.
              (Throws VerificationError, Throws SomeRemoteError)
           => InMemRepo
           -> InMemCache
           -> IsRetry
           -> RemoteFile fs
           -> (forall f. HasFormat fs f -> TempPath -> IO a)
           -> IO a
withRemote InMemRepo{..} InMemCache{..} _isRetry remoteFile callback =
    inMemWithRemote remoteFile $ \format tempPath -> do
      result <- callback format tempPath
      inMemCacheFile tempPath (hasFormatGet format) (mustCache remoteFile)
      return result

-- | Get a file from the index
getFromIndex :: IndexFile -> IO (Maybe BS.ByteString)
getFromIndex = error "repGetFromIndex not implemented"

-- | Mirror selection
withMirror :: forall a. Maybe [Mirror] -> IO a -> IO a
withMirror Nothing   callback = callback
withMirror (Just []) callback = callback
withMirror _ _ = error "Mirror selection not implemented"

-- | Logging
--
-- TODO: We should write these to an MVar and verify them
log :: LogMessage -> IO ()
log = putStrLn . pretty
