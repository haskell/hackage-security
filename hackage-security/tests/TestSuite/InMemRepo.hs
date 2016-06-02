module TestSuite.InMemRepo (
    InMemRepo(..)
  , newInMemRepo
  , initRoot
  , InMemFile(..)
  , inMemFileRender
  ) where

-- stdlib
import Control.Exception
import Data.Time
import qualified Codec.Archive.Tar      as Tar
import qualified Codec.Compression.GZip as GZip
import qualified Data.ByteString.Lazy   as BS.L

-- Cabal
import Distribution.Text

-- hackage-security
import Hackage.Security.Client
import Hackage.Security.Client.Formats
import Hackage.Security.Client.Repository
import Hackage.Security.Client.Verify
import Hackage.Security.JSON
import Hackage.Security.Util.Path
import Hackage.Security.Util.Some

-- TestSuite
import TestSuite.PrivateKeys
import TestSuite.Util.StrictMVar

{-------------------------------------------------------------------------------
  "Files" from the in-memory repository
-------------------------------------------------------------------------------}

data InMemFile :: * -> * where
    InMemMetadata :: ToJSON WriteJSON a => RepoLayout -> a -> InMemFile Metadata
    InMemBinary   :: BS.L.ByteString -> InMemFile Binary

inMemFileRender :: InMemFile typ -> BS.L.ByteString
inMemFileRender (InMemMetadata layout file) = renderJSON layout file
inMemFileRender (InMemBinary bs)            = bs

instance DownloadedFile InMemFile where
    downloadedRead file =
      return $ inMemFileRender file

    downloadedVerify file info =
      return $ knownFileInfoEqual (fileInfo (inMemFileRender file))
                                  (trusted info)

    downloadedCopyTo file dest =
      writeLazyByteString dest (inMemFileRender file)

{-------------------------------------------------------------------------------
  In-memory repository
-------------------------------------------------------------------------------}

data InMemRepo = InMemRepo {
    -- | Get a file from the repository
    inMemRepoGet :: forall fs typ.
                    RemoteFile fs typ
                 -> Verify (Some (HasFormat fs), InMemFile typ)

    -- | Get a file, based on a path (uses hackageRepoLayout)
  , inMemRepoGetPath :: RepoPath -> IO (Some InMemFile)

    -- | Run the "cron job" on the server
    --
    -- That is, resign the timestamp and the snapshot
  , inMemRepoCron :: UTCTime -> IO ()

    -- | Rollover the timestamp and snapshot keys
  , inMemRepoKeyRollover :: UTCTime -> IO ()

    -- | Set the content of the repo tar index and resign
  , inMemRepoSetIndex :: UTCTime -> [Tar.Entry] -> IO ()
  }

newInMemRepo :: RepoLayout
             -> Signed Root
             -> UTCTime
             -> PrivateKeys
             -> IO InMemRepo
newInMemRepo layout root now keys = do
    state <- newMVar $ initRemoteState now layout keys root
    return InMemRepo {
        inMemRepoGet         = get         state
      , inMemRepoGetPath     = getPath     state
      , inMemRepoCron        = cron        state
      , inMemRepoKeyRollover = keyRollover state
      , inMemRepoSetIndex    = setIndex    state
      }

{-------------------------------------------------------------------------------
  "Remote" state (as it is "on the server")
-------------------------------------------------------------------------------}

data RemoteState = RemoteState {
      remoteKeys      :: !PrivateKeys
    , remoteLayout    :: !RepoLayout
    , remoteRoot      :: !(Signed Root)
    , remoteTimestamp :: !(Signed Timestamp)
    , remoteSnapshot  :: !(Signed Snapshot)
    , remoteMirrors   :: !(Signed Mirrors)
    , remoteTar       :: !BS.L.ByteString
    , remoteTarGz     :: !BS.L.ByteString
    }

initRoot :: UTCTime -> RepoLayout -> PrivateKeys -> Signed Root
initRoot now layout keys = withSignatures layout (privateRoot keys) Root {
      rootVersion = FileVersion 1
    , rootExpires = expiresInDays now (365 * 10)
    , rootKeys    = privateKeysEnv   keys
    , rootRoles   = privateKeysRoles keys
    }

initRemoteState :: UTCTime
                -> RepoLayout
                -> PrivateKeys
                -> Signed Root
                -> RemoteState
initRemoteState now layout keys signedRoot = RemoteState {
      remoteKeys      = keys
    , remoteLayout    = layout
    , remoteRoot      = signedRoot
    , remoteTimestamp = signedTimestamp
    , remoteSnapshot  = signedSnapshot
    , remoteMirrors   = signedMirrors
    , remoteTar       = initTar
    , remoteTarGz     = initTarGz
    }
  where
    signedTimestamp = withSignatures layout [privateTimestamp keys] initTimestamp
    signedSnapshot  = withSignatures layout [privateSnapshot  keys] initSnapshot
    signedMirrors   = withSignatures layout [privateMirrors   keys] initMirrors

    initMirrors :: Mirrors
    initMirrors = Mirrors {
        mirrorsVersion = FileVersion 1
      , mirrorsExpires = expiresNever
      , mirrorsMirrors = []
      }

    initSnapshot :: Snapshot
    initSnapshot = Snapshot {
        snapshotVersion     = FileVersion 1
      , snapshotExpires     = expiresInDays now 3
      , snapshotInfoRoot    = fileInfo $ renderJSON layout signedRoot
      , snapshotInfoMirrors = fileInfo $ renderJSON layout signedMirrors
      , snapshotInfoTarGz   = fileInfo $ initTarGz
      , snapshotInfoTar     = Just $ fileInfo initTar
      }

    initTimestamp :: Timestamp
    initTimestamp = Timestamp {
        timestampVersion      = FileVersion 1
      , timestampExpires      = expiresInDays now 3
      , timestampInfoSnapshot = fileInfo $ renderJSON layout signedSnapshot
      }

    initTar :: BS.L.ByteString
    initTar = Tar.write []

    initTarGz :: BS.L.ByteString
    initTarGz = GZip.compress initTar

{-------------------------------------------------------------------------------
  InMemRepo methods
-------------------------------------------------------------------------------}

-- | Get a file from the server
get :: MVar RemoteState -> RemoteFile fs typ -> Verify (Some (HasFormat fs), InMemFile typ)
get state remoteFile = do
    RemoteState{..} <- liftIO $ readMVar state
    case remoteFile of
      RemoteTimestamp        -> return (Some (HFZ FUn), InMemMetadata remoteLayout remoteTimestamp)
      RemoteSnapshot       _ -> return (Some (HFZ FUn), InMemMetadata remoteLayout remoteSnapshot)
      RemoteMirrors        _ -> return (Some (HFZ FUn), InMemMetadata remoteLayout remoteMirrors)
      RemoteRoot           _ -> return (Some (HFZ FUn), InMemMetadata remoteLayout remoteRoot)
      RemoteIndex    hasGz _ -> return (Some hasGz, InMemBinary remoteTarGz)
      RemotePkgTarGz pkgId _ -> error $ "withRemote: RemotePkgTarGz " ++ display pkgId

getPath :: MVar RemoteState -> RepoPath -> IO (Some InMemFile)
getPath state repoPath = do
    RemoteState{..} <- readMVar state
    case toUnrootedFilePath (unrootPath repoPath) of
      "root.json"       -> return $ Some (InMemMetadata remoteLayout remoteRoot)
      "timestamp.json"  -> return $ Some (InMemMetadata remoteLayout remoteTimestamp)
      "snapshot.json"   -> return $ Some (InMemMetadata remoteLayout remoteSnapshot)
      "mirrors.json"    -> return $ Some (InMemMetadata remoteLayout remoteMirrors)
      "01-index.tar.gz" -> return $ Some (InMemBinary remoteTarGz)
      "01-index.tar"    -> return $ Some (InMemBinary remoteTar)
      otherPath -> throwIO . userError $ "getPath: Unknown path " ++ otherPath
  where

cron :: MVar RemoteState -> UTCTime -> IO ()
cron state now = modifyMVar_ state $ \st@RemoteState{..} -> do
    let snapshot, snapshot' :: Snapshot
        snapshot  = signed remoteSnapshot
        snapshot' = snapshot {
            snapshotVersion = versionIncrement $ snapshotVersion snapshot
          , snapshotExpires = expiresInDays now 3
          }

        timestamp, timestamp' :: Timestamp
        timestamp  = signed remoteTimestamp
        timestamp' = Timestamp {
            timestampVersion      = versionIncrement $ timestampVersion timestamp
          , timestampExpires      = expiresInDays now 3
          , timestampInfoSnapshot = fileInfo $ renderJSON remoteLayout signedSnapshot
          }

        signedTimestamp = withSignatures remoteLayout [privateTimestamp remoteKeys] timestamp'
        signedSnapshot  = withSignatures remoteLayout [privateSnapshot  remoteKeys] snapshot'

    return st {
        remoteTimestamp = signedTimestamp
      , remoteSnapshot  = signedSnapshot
      }

setIndex :: MVar RemoteState -> UTCTime -> [Tar.Entry] -> IO ()
setIndex state now entries = modifyMVar_ state $ \st@RemoteState{..} -> do
    let snapshot, snapshot' :: Snapshot
        snapshot  = signed remoteSnapshot
        snapshot' = snapshot {
            snapshotVersion   = versionIncrement $ snapshotVersion snapshot
          , snapshotExpires   = expiresInDays now 3
          , snapshotInfoTarGz = fileInfo $ newTarGz
          , snapshotInfoTar   = Just $ fileInfo newTar
          }

        newTar :: BS.L.ByteString
        newTar = Tar.write entries

        newTarGz :: BS.L.ByteString
        newTarGz = GZip.compress newTar

        timestamp, timestamp' :: Timestamp
        timestamp  = signed remoteTimestamp
        timestamp' = Timestamp {
            timestampVersion      = versionIncrement $ timestampVersion timestamp
          , timestampExpires      = expiresInDays now 3
          , timestampInfoSnapshot = fileInfo $ renderJSON remoteLayout signedSnapshot
          }

        signedTimestamp = withSignatures remoteLayout [privateTimestamp remoteKeys] timestamp'
        signedSnapshot  = withSignatures remoteLayout [privateSnapshot  remoteKeys] snapshot'

    return st {
        remoteTimestamp = signedTimestamp
      , remoteSnapshot  = signedSnapshot
      , remoteTar       = newTar
      , remoteTarGz     = newTarGz
      }

keyRollover :: MVar RemoteState -> UTCTime -> IO ()
keyRollover state now = modifyMVar_ state $ \st@RemoteState{..} -> do
    newKeySnapshot  <- createKey' KeyTypeEd25519
    newKeyTimestamp <- createKey' KeyTypeEd25519

    let remoteKeys' :: PrivateKeys
        remoteKeys' = remoteKeys {
            privateSnapshot  = newKeySnapshot
          , privateTimestamp = newKeyTimestamp
          }

        root, root' :: Root
        root  = signed remoteRoot
        root' = Root {
            rootVersion = versionIncrement $ rootVersion root
          , rootExpires = expiresInDays now (365 * 10)
          , rootKeys    = privateKeysEnv   remoteKeys'
          , rootRoles   = privateKeysRoles remoteKeys'
          }

        snapshot, snapshot' :: Snapshot
        snapshot  = signed remoteSnapshot
        snapshot' = snapshot {
            snapshotVersion  = versionIncrement $ snapshotVersion snapshot
          , snapshotExpires  = expiresInDays now 3
          , snapshotInfoRoot = fileInfo $ renderJSON remoteLayout signedRoot
          }

        timestamp, timestamp' :: Timestamp
        timestamp  = signed remoteTimestamp
        timestamp' = Timestamp {
            timestampVersion      = versionIncrement $ timestampVersion timestamp
          , timestampExpires      = expiresInDays now 3
          , timestampInfoSnapshot = fileInfo $ renderJSON remoteLayout signedSnapshot
          }

        signedRoot      = withSignatures remoteLayout (privateRoot      remoteKeys') root'
        signedTimestamp = withSignatures remoteLayout [privateTimestamp remoteKeys'] timestamp'
        signedSnapshot  = withSignatures remoteLayout [privateSnapshot  remoteKeys'] snapshot'

    return st {
        remoteRoot      = signedRoot
      , remoteTimestamp = signedTimestamp
      , remoteSnapshot  = signedSnapshot
      }
