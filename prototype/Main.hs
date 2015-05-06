{-# LANGUAGE CPP #-}
{-# LANGUAGE TemplateHaskell #-}
module Main where

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
import Hackage.Security.TUF.Ints
import Hackage.Security.TUF.Root
import Hackage.Security.TUF.Signed
import Hackage.Security.TUF.Snapshot
import Hackage.Security.TUF.Targets
import Hackage.Security.TUF.Timestamp
import qualified Hackage.Security.TUF.FileMap as FileMap
import qualified Hackage.Security.Key.Env     as KeyEnv

import Prototype.Options

main :: IO ()
main = do
    opts <- getOptions
    interpretCommand (optCommand opts) opts

interpretCommand :: Command -> Options -> IO ()
interpretCommand Bootstrap            = cmdBootstrap
interpretCommand (Roundtrip fp)       = cmdRoundtrip fp
interpretCommand Check                = cmdCheck
interpretCommand (Upload pkg version) = cmdUpload pkg version

{-------------------------------------------------------------------------------
  Bootstrapping
-------------------------------------------------------------------------------}

cmdBootstrap :: Options -> IO ()
cmdBootstrap opts = do
    now <- getCurrentTime
    rootKeys     <- replicateM 3 $ createKey' KeyTypeEd25519
    snapshotKey  <- createKey' KeyTypeEd25519
    timestampKey <- createKey' KeyTypeEd25519
    targetKeys   <- replicateM 3 $ createKey' KeyTypeEd25519
    trustees     <- replicateM 3 $ createKey' KeyTypeEd25519
    let root = Root {
            rootVersion = FileVersion 1
          , rootExpires = addUTCTime (365 * oneDay) now
          , rootKeys    = KeyEnv.fromKeys $ concat [
                              rootKeys
                            , [snapshotKey]
                            , [timestampKey]
                            , targetKeys
                            ]
          , rootRoles   = Map.fromList [
                (RoleRoot, RoleSpec {
                    roleSpecKeys      = map somePublicKey rootKeys
                  , roleSpecThreshold = KeyThreshold 2
                  })
              , (RoleSnapshot, RoleSpec {
                    roleSpecKeys      = [somePublicKey snapshotKey]
                  , roleSpecThreshold = KeyThreshold 1
                  })
              , (RoleTimestamp, RoleSpec {
                    roleSpecKeys      = [somePublicKey timestampKey]
                  , roleSpecThreshold = KeyThreshold 1
                  })
              , (RoleTargets, RoleSpec {
                    roleSpecKeys      = map somePublicKey targetKeys
                  , roleSpecThreshold = KeyThreshold 1
                  })
              ]
          }
        snapshot = Snapshot {
            snapshotVersion = FileVersion 1
          , snapshotExpires = addUTCTime (3 * oneDay) now
          , snapshotMeta    = FileMap.empty
          }
        timestamp = Timestamp {
            timestampVersion = FileVersion 1
          , timestampExpires = addUTCTime (3 * oneDay) now
          , timestampMeta    = FileMap.fromList [
                ("snapshot.json", FileMap.fileInfoJSON signedSnapshot)
              ]
          }
        topLevelTargets = Targets {
            targetsVersion     = FileVersion 1
          , targetsExpires     = never
          , targets            = FileMap.empty
          , targetsDelegations = Just $ Delegations {
                delegationsKeys  = KeyEnv.fromKeys trustees
              , delegationsRoles = [
                    DelegationSpec {
                        delegationSpecKeys      = []
                      , delegationSpecThreshold = KeyThreshold 0
                      , delegation = $(qqd "targets/*/*/*" "targets/*/*/targets.json")
                      }
                  ]
              }
          }
        signedRoot            = withSignatures rootKeys       root
        signedSnapshot        = withSignatures [snapshotKey]  snapshot
        signedTimestamp       = withSignatures [timestampKey] timestamp
        signedTopLevelTargets = withSignatures targetKeys     topLevelTargets

    -- Write keys
    forM_ rootKeys   $ writeKey Offline "root"
    forM_ targetKeys $ writeKey Offline "target"
    forM_ trustees   $ writeKey Offline "trustee"
    writeKey Server "snapshot"  snapshotKey
    writeKey Server "timestamp" timestampKey

    -- Write server state
    writeCanonical pathRoot            signedRoot
    writeCanonical pathSnapshot        signedSnapshot
    writeCanonical pathTimestamp       signedTimestamp
    writeCanonical pathTopLevelTargets signedTopLevelTargets
  where
    pathRoot            = mkPath opts Server "root.json"
    pathSnapshot        = mkPath opts Server "snapshot.json"
    pathTimestamp       = mkPath opts Server "timestamp.json"
    pathTopLevelTargets = mkPath opts Server "targets.json"

    writeKey :: Where -> FilePath -> Some Key -> IO ()
    writeKey where_ prefix key = writeCanonical' path key
      where
        kId  = keyIdString (someKeyId key)
        path = mkPath opts where_ ("keys" </> prefix </> kId <.> "private")

{-------------------------------------------------------------------------------
  Internal checks
-------------------------------------------------------------------------------}

cmdRoundtrip :: FilePath -> Options -> IO ()
cmdRoundtrip fp _opts = do
    case fp of
      "root.json" -> do
        (root, _keyEnv) <- readRoot fp
        BS.L.putStr $ renderJSON root
      "snapshot.json" -> do
        -- We need the root file to resolve keys
        (_root, keyEnv) <- readRoot "root.json"
        (snapshot :: Signed Snapshot) <- readJSON keyEnv "snapshot.json"
        BS.L.putStr $ renderJSON snapshot
      "timestamp.json" -> do
        -- We need the root file to resolve keys
        (_root, keyEnv) <- readRoot "root.json"
        (timestamp :: Signed Timestamp) <- readJSON keyEnv "timestamp.json"
        BS.L.putStr $ renderJSON timestamp
      _otherwise ->
        putStrLn $ "Don't know how to parse " ++ fp

{-------------------------------------------------------------------------------
  Check for updates
-------------------------------------------------------------------------------}

cmdCheck :: Options -> IO ()
cmdCheck opts = do
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

-- | Timestamp verification
--
-- NOTE: deserialization for Signed documents will already have verified that
-- the signatures are correct; so here we just need to need to verify that we
-- have at least @threshold@ of the timestamp role keys.
verifyTimestamp :: UTCTime           -- ^ Now
                -> RoleSpec          -- ^ Timestamp role specification
                -> Signed Timestamp  -- ^ Old timestamp
                -> Signed Timestamp  -- ^ New timestamp
                -> Bool
verifyTimestamp now tsRole oldTS newTS
  | timestampExpires newTS' < now                     = False
  | timestampVersion newTS' < timestampVersion oldTS' = False
  | not (verifyThreshold tsRole (signatures newTS))   = False
  | otherwise = True
  where
    oldTS', newTS' :: Timestamp
    oldTS' = signed oldTS
    newTS' = signed newTS

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
        snapshotKeys'  = roleSpecKeys (roleSnapshot  root')
        timestampKeys' = roleSpecKeys (roleTimestamp root')

    -- Read the corresponding private keys
    snapshotKeys  <- forM snapshotKeys'  $ readPrivateKey opts "snapshot"
    timestampKeys <- forM timestampKeys' $ readPrivateKey opts "timestamp"

    -- Fake the package tarball
    let tarGzContents = BS.L.C8.pack pkg -- Fake package contents
        tarGzMetaInfo = FileMap.fileInfo tarGzContents
        tarGzFileName = pkg ++ "-" ++ showVersion version ++ ".tar.gz"

    -- Construct target metadata
    let packageTargets = Targets {
            targetsVersion     = FileVersion 1
          , targetsExpires     = never
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
            snapshotVersion = incrementFileVersion (snapshotVersion oldSnapshot')
          , snapshotExpires = addUTCTime (3 * oneDay) now
          , snapshotMeta    = FileMap.insert
                                packageTargetsPath
                                (FileMap.fileInfoJSON packageTargets)
                                (snapshotMeta oldSnapshot')
          }
        newSnapshot = withSignatures snapshotKeys newSnapshot'

    -- Create new timestamp
    oldTimestamp <- readJSON keyEnv pathTimestamp
    let oldTimestamp' = signed oldTimestamp
        newTimestamp' = Timestamp {
            timestampVersion = incrementFileVersion (timestampVersion oldTimestamp')
          , timestampExpires = addUTCTime (3 * oneDay) now
          , timestampMeta    = FileMap.fromList [
                ("snapshot.json", FileMap.fileInfoJSON newSnapshot)
              ]
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

never :: UTCTime
never = UTCTime (toEnum maxBound) 0

writeCanonical' :: ToJSON a => FilePath -> a -> IO ()
writeCanonical' fp a = do
    createDirectoryIfMissing True (takeDirectory fp)
    writeCanonical fp a
