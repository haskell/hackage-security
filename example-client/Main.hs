module Main where

import Data.List (isPrefixOf)
import Network.URI

import Hackage.Security.Client
import Hackage.Security.Client.Repository
import qualified Hackage.Security.Client.Repository.Local as Local
import qualified Hackage.Security.Client.Repository.HTTP  as Remote

import ExampleClient.Options
import qualified ExampleClient.HTTP as HTTP

main :: IO ()
main = do
    opts@GlobalOpts{..} <- getOptions
    case globalCommand of
      Check -> check opts

{-------------------------------------------------------------------------------
  Checking for updates
-------------------------------------------------------------------------------}

check :: GlobalOpts -> IO ()
check opts = do
    let rep = initRepo opts
    print =<< checkForUpdates rep CheckExpiry

initRepo :: GlobalOpts -> Repository
initRepo GlobalOpts{..}
    | "http://" `isPrefixOf` globalRepo = initRemoteRepo
    | otherwise                         = initLocalRepo
  where
    initLocalRepo :: Repository
    initLocalRepo = Local.initRepo globalRepo globalCache

    initRemoteRepo :: Repository
    initRemoteRepo = Remote.initRepo HTTP.initClient auth globalCache
      where
        auth = URIAuth {
            uriUserInfo = ""
          , uriRegName  = drop 7 globalRepo
          , uriPort     = "80"
          }

{-
import Control.Exception
import Control.Monad
import Data.Time
import Data.Version
import System.Directory
import System.FilePath
import qualified Data.Map as Map
import qualified Data.ByteString.Lazy       as BS.L
import qualified Data.ByteString.Lazy.Char8 as BS.L.C8

#if !MIN_VERSION_base(4,8,0)
import Control.Applicative
#endif

import Hackage.Security.JSON
import Hackage.Security.Key
import Hackage.Security.Key.Env (KeyEnv)
import Hackage.Security.Key.ExplicitSharing
import Hackage.Security.Some
import Hackage.Security.TUF
import qualified Hackage.Security.TUF.FileMap as FileMap
import qualified Hackage.Security.Key.Env     as KeyEnv
import qualified Hackage.Security.Client
import qualified Hackage.Security.Client.Repository.Local

interpretCommand :: Command -> Options -> IO ()
interpretCommand Check                = cmdCheck
interpretCommand (Upload pkg version) = cmdUpload pkg version

{-------------------------------------------------------------------------------
  Check for updates
-------------------------------------------------------------------------------}

cmdCheck :: Options -> IO ()
cmdCheck opts = undefined -- replaced by generic function in lib
{-


    now <- getCurrentTime

    -- If the client does not yet have a copy of root.json, get one
    clientHasRootJson <- doesFileExist pathClientRoot
    unless clientHasRootJson $ bootstrapClient opts

    -- Read the root JSON, and get timestamp from the server
    --
    -- TODO: When verification fails, we need to get new root metadata from the
    -- server, and try again. In this case we will not be able to verify the
    -- cached timestamp and snapshot data, so we will need to erase them and
    -- start afresh.
    --
    -- NOTE: When an attacker who gains control over the server sets the
    -- "version" field at maximum, clients will subsequently reject all updates
    -- because the version number cannot increase anymore. When we do start
    -- afresh (as above), this problem is resolved because we start from a
    -- clean slate.
    --
    -- TODO: Although the version number is allowed to stay the same, we should
    -- probably verify that _if_ it does stay the same _then_ the snapshot
    -- timestamp should also stay the same?
    (root, keyEnv) <- readRoot pathClientRoot
    oldTS <- readJSON keyEnv pathClientTime
    newTS <- readJSON keyEnv pathServerTime

    -- Verify the timestamp file
    let tsRole = roleTimestamp (signed root)
    unless (verifyTimestamp now tsRole oldTS newTS) $
      throwIO $ userError "Timestamp file tampered with!"

    -- TODO: We should make a type level distinction between "the signatures
    -- have been verified" (Signed) and "they have been verified against a
    -- particular role" (Verified).

    -- Check for updates
    if snapshotHash (signed newTS) == snapshotHash (signed oldTS)
      then
        putStrLn "No updates"
      else
        putStrLn "There are updates"
  where
    pathClientRoot = mkPath opts Client "root.json"
    pathClientTime = mkPath opts Client "timestamp.json"
    pathServerTime = mkPath opts Server "timestamp.json"
-}

bootstrapClient :: Options -> IO ()
bootstrapClient opts = do
    copyFromServer "root.json"
    copyFromServer "timestamp.json"
    copyFromServer "snapshot.json"
  where
    copyFromServer :: FilePath -> IO ()
    copyFromServer fp = do
        createDirectoryIfMissing True (takeDirectory dstPath)
        copyFile srcPath dstPath
      where
        srcPath = mkPath opts Server fp
        dstPath = mkPath opts Client fp

{-------------------------------------------------------------------------------
  Uploading new packages
-------------------------------------------------------------------------------}

cmdUpload :: String -> Version -> Options -> IO ()
cmdUpload pkg version opts = do
    now <- getCurrentTime

    -- Read root metadata
    (root, keyEnv) <- readRoot pathRoot
    let root'          = signed root
        snapshotKeys'  = roleSpecKeys (rootRolesSnapshot  (rootRoles root'))
        timestampKeys' = roleSpecKeys (rootRolesTimestamp (rootRoles root'))

    -- Read the corresponding private keys
    snapshotKeys  <- forM snapshotKeys'  $ readPrivateKey opts "snapshot"
    timestampKeys <- forM timestampKeys' $ readPrivateKey opts "timestamp"

    -- Fake the package tarball
    let tarGzContents = BS.L.C8.pack pkg -- Fake package contents
        tarGzMetaInfo = fileInfo tarGzContents
        tarGzFileName = pkg ++ "-" ++ showVersion version ++ ".tar.gz"

    -- Construct target metadata
    let packageTargets = Targets {
            targetsVersion     = versionInitial
          , targetsExpires     = expiresNever
          , targets            = FileMap.fromList [
                (tarGzFileName, tarGzMetaInfo)
              ]
          , targetsDelegations = Nothing
          }
        signedPackageTargets = withSignatures [] packageTargets
        packageTargetsPath   = joinPath [
                                   "targets"
                                 , pkg
                                 , showVersion version
                                 , "targets.json"
                                 ]

    -- Write package targets
    writeCanonical' (mkPath opts Server packageTargetsPath) signedPackageTargets

    -- Update snapshot
    oldSnapshot <- readJSON keyEnv pathSnapshot
    let oldSnapshot' = signed oldSnapshot
        newSnapshot' = Snapshot {
            snapshotVersion = versionIncrement (snapshotVersion oldSnapshot')
          , snapshotExpires = expiresInDays now 3
          {-
          , snapshotMeta    = FileMap.insert
                                packageTargetsPath
                                (fileInfoJSON packageTargets)
                                (snapshotMeta oldSnapshot')
          -}
          }
        newSnapshot = withSignatures snapshotKeys newSnapshot'

    -- Create new timestamp
    oldTimestamp <- readJSON keyEnv pathTimestamp
    let oldTimestamp' = signed oldTimestamp
        newTimestamp' = Timestamp {
            timestampVersion      = versionIncrement (timestampVersion oldTimestamp')
          , timestampExpires      = expiresInDays now 3
          --, timestampInfoSnapshot = fileInfoJSON newSnapshot
          }
        newTimestamp  = withSignatures timestampKeys newTimestamp'

    -- Write new files
    -- TODO: There is a race condition here. The spec talk about "consistent
    -- snapshots" but there's a lot of detail there and I don't know if we
    -- want to adopt the same solution.
    writeCanonical pathSnapshot  newSnapshot
    writeCanonical pathTimestamp newTimestamp
  where
    pathRoot      = mkPath opts Server "root.json"
    pathSnapshot  = mkPath opts Server "snapshot.json"
    pathTimestamp = mkPath opts Server "timestamp.json"

{-------------------------------------------------------------------------------
  Auxiliary
-------------------------------------------------------------------------------}

data Where = Client | Server | Offline

mkPath :: Options -> Where -> FilePath -> FilePath
mkPath Options{..} where_ fp =
    case where_ of
      Server  -> optServer  </> fp
      Client  -> optClient  </> fp
      Offline -> optOffline </> fp

readRoot :: FilePath -> IO (Signed Root, KeyEnv)
readRoot fp = either throwIO (return . aux) =<< readCanonical KeyEnv.empty fp
  where
    aux :: Signed Root -> (Signed Root, KeyEnv)
    aux root@Signed{signed = Root{..}} = (root, rootKeys)

readJSON :: FromJSON ReadJSON a => KeyEnv -> FilePath -> IO a
readJSON env fp = either throwIO return =<< readCanonical env fp

readPrivateKey :: Options -> FilePath -> Some PublicKey -> IO (Some Key)
readPrivateKey opts prefix pub =
    readJSON KeyEnv.empty path
  where
    kId   = keyIdString (someKeyId pub)
    path' = "keys" </> prefix </> kId <.> "private"
    path  = mkPath opts Server path'

oneDay :: NominalDiffTime
oneDay = 24 * 60 * 60

writeCanonical' :: ToJSON a => FilePath -> a -> IO ()
writeCanonical' fp a = do
    createDirectoryIfMissing True (takeDirectory fp)
    writeCanonical fp a
-}
