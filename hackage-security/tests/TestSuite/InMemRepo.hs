module TestSuite.InMemRepo (
    InMemRepo(..)
  , newInMemRepo
  , initRoot
  ) where

-- stdlib
import Control.Concurrent
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

data InMemRepo = InMemRepo {
    inMemWithRemote :: forall a fs.
                       RemoteFile fs
                    -> (forall f. HasFormat fs f -> TempPath -> IO a)
                    -> IO a
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
        inMemWithRemote = withRemote tempDir state
      }

{-------------------------------------------------------------------------------
  "Remote" state (as it is "on the server")
-------------------------------------------------------------------------------}

data RemoteState = RemoteState {
      remoteKeys      :: PrivateKeys
    , remoteLayout    :: RepoLayout
    , remoteRoot      :: Signed Root
    , remoteTimestamp :: Signed Timestamp
    , remoteSnapshot  :: Signed Snapshot
    , remoteMirrors   :: Signed Mirrors
    , remoteTar       :: BS.L.ByteString
    , remoteTarGz     :: BS.L.ByteString
    }

initRoot :: UTCTime -> RepoLayout -> PrivateKeys -> Signed Root
initRoot now layout keys = withSignatures layout (privateRoot keys) Root {
      rootVersion = FileVersion 1
    , rootExpires = expiresInDays now (365 * 10)
    , rootKeys    = privateKeysEnv keys
    , rootRoles   = privateRoles   keys
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
withRemote :: forall a fs.
              AbsolutePath
           -> MVar RemoteState
           -> RemoteFile fs
           -> (forall f. HasFormat fs f -> TempPath -> IO a)
           -> IO a
withRemote remoteTempDir state remoteFile callback = do
    case remoteFile of
      RemoteTimestamp        -> serve "timestamp.json"  (HFZ FUn) $ render remoteTimestamp
      RemoteSnapshot       _ -> serve "snapshot.json"   (HFZ FUn) $ render remoteSnapshot
      RemoteMirrors        _ -> serve "mirrors.json"    (HFZ FUn) $ render remoteMirrors
      RemoteRoot           _ -> serve "root.json"       (HFZ FUn) $ render remoteRoot
      RemoteIndex    hasGz _ -> serve "01-index.tar.gz" hasGz     $ remoteTarGz
      RemotePkgTarGz pkgId _ -> error $ "withRemote: RemotePkgTarGz " ++ display pkgId
  where
    render :: forall b. ToJSON WriteJSON b
           => (RemoteState -> b)
           -> (RemoteState -> BS.L.ByteString)
    render f st = renderJSON (remoteLayout st) (f st)

    serve :: String -> HasFormat fs f -> (RemoteState -> BS.L.ByteString) -> IO a
    serve template hasFormat f =
      withTempFile remoteTempDir template $ \tempFile h -> do
        withMVar state $ BS.L.hPut h . f
        hClose h
        callback hasFormat tempFile
