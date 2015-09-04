module TestSuite.InMemRepo (
    InMemRepo(..)
  , newInMemRepo
  , initRoot
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
import Hackage.Security.JSON
import Hackage.Security.Util.Path
import Hackage.Security.Util.IO

-- TestSuite
import TestSuite.PrivateKeys
import TestSuite.Util.StrictMVar

data InMemRepo = InMemRepo {
    -- | Get a file from the repository
    inMemRepoGet :: forall a fs.
                    RemoteFile fs
                 -> (forall f. HasFormat fs f -> TempPath -> IO a)
                 -> IO a

    -- | Get a file, based on a path (uses hackageRepoLayout)
  , inMemRepoGetPath :: forall a. RepoPath -> (TempPath -> IO a) -> IO a

    -- | Run the "cron job" on the server
    --
    -- That is, resign the timestamp and the snapshot
  , inMemRepoCron :: UTCTime -> IO ()

    -- | Rollover the timestamp and snapshot keys
  , inMemRepoKeyRollover :: UTCTime -> IO ()
  }

newInMemRepo :: AbsolutePath
             -> RepoLayout
             -> Signed Root
             -> UTCTime
             -> PrivateKeys
             -> IO InMemRepo
newInMemRepo tempDir layout root now keys = do
    state <- newMVar $ initRemoteState now layout keys root
    return InMemRepo {
        inMemRepoGet         = get     tempDir state
      , inMemRepoGetPath     = getPath tempDir state
      , inMemRepoCron        = cron            state
      , inMemRepoKeyRollover = keyRollover     state
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
get :: forall a fs.
       AbsolutePath
    -> MVar RemoteState
    -> RemoteFile fs
    -> (forall f. HasFormat fs f -> TempPath -> IO a)
    -> IO a
get remoteTempDir state remoteFile callback = do
    case remoteFile of
      RemoteTimestamp        -> serve "timestamp.json"  (HFZ FUn) $ render remoteTimestamp
      RemoteSnapshot       _ -> serve "snapshot.json"   (HFZ FUn) $ render remoteSnapshot
      RemoteMirrors        _ -> serve "mirrors.json"    (HFZ FUn) $ render remoteMirrors
      RemoteRoot           _ -> serve "root.json"       (HFZ FUn) $ render remoteRoot
      RemoteIndex    hasGz _ -> serve "01-index.tar.gz" hasGz     $ remoteTarGz
      RemotePkgTarGz pkgId _ -> error $ "withRemote: RemotePkgTarGz " ++ display pkgId
  where
    serve :: String -> HasFormat fs f -> (RemoteState -> BS.L.ByteString) -> IO a
    serve template hasFormat f =
      withTempFile remoteTempDir template $ \tempFile h -> do
        withMVar state $ BS.L.hPut h . f
        hClose h
        callback hasFormat tempFile

getPath :: forall a.
           AbsolutePath
        -> MVar RemoteState
        -> RepoPath
        -> (TempPath -> IO a)
        -> IO a
getPath remoteTempDir state repoPath callback = do
    case toFilePath (castRoot repoPath) of
      "/root.json"       -> serve $ render remoteRoot
      "/timestamp.json"  -> serve $ render remoteTimestamp
      "/snapshot.json"   -> serve $ render remoteSnapshot
      "/mirrors.json"    -> serve $ render remoteMirrors
      "/01-index.tar.gz" -> serve $ remoteTarGz
      "/01-index.tar"    -> serve $ remoteTar
      otherPath -> throwIO . userError $ "getPath: Unknown path " ++ otherPath
  where
    template :: String
    template = unFragment (takeFileName repoPath)

    serve :: (RemoteState -> BS.L.ByteString) -> IO a
    serve f =
      withTempFile remoteTempDir template $ \tempFile h -> do
        withMVar state $ BS.L.hPut h . f
        hClose h
        callback tempFile

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

{-------------------------------------------------------------------------------
  Auxiliary
-------------------------------------------------------------------------------}

render :: forall b. ToJSON WriteJSON b
       => (RemoteState -> b)
       -> (RemoteState -> BS.L.ByteString)
render f st = renderJSON (remoteLayout st) (f st)
