{-# LANGUAGE TemplateHaskell #-}
module Main (main) where

import Control.Exception
import Control.Monad
import Data.Maybe (catMaybes)
import Data.Time
import System.Directory
import System.FilePath
import System.IO
import System.IO.Error
import qualified Codec.Compression.GZip as GZip
import qualified Data.ByteString.Lazy   as BS.L

-- Cabal
import Distribution.Package
import Distribution.Text

-- hackage-security
import Hackage.Security.JSON
import Hackage.Security.Key
import Hackage.Security.Key.ExplicitSharing
import Hackage.Security.TUF
import Hackage.Security.Util.Some
import Hackage.Security.Util.IO
import qualified Hackage.Security.TUF.FileMap         as FileMap
import qualified Hackage.Security.Key.Env             as KeyEnv
import qualified Hackage.Security.Server.IndexTarball as Index

-- hackage-secure-local
import Hackage.Security.Local.Options

{-------------------------------------------------------------------------------
  Main application driver
-------------------------------------------------------------------------------}

main :: IO ()
main = do
    opts@GlobalOpts{..} <- getOptions
    case globalCommand of
      CreateKeys -> createKeys opts
      Bootstrap  -> bootstrapOrUpdate opts True
      Update     -> bootstrapOrUpdate opts False

{-------------------------------------------------------------------------------
  Creating keys
-------------------------------------------------------------------------------}

createKeys :: GlobalOpts -> IO ()
createKeys opts = do
    keys <- PrivateKeys <$> (replicateM 3 $ createKey' KeyTypeEd25519)
                        <*> (replicateM 3 $ createKey' KeyTypeEd25519)
                        <*> (replicateM 1 $ createKey' KeyTypeEd25519)
                        <*> (replicateM 1 $ createKey' KeyTypeEd25519)
    writeKeys opts keys

{-------------------------------------------------------------------------------
  Dealing with (private) keys
-------------------------------------------------------------------------------}

data PrivateKeys = PrivateKeys {
    privateRoot      :: [Some Key]
  , privateTarget    :: [Some Key]
  , privateTimestamp :: [Some Key]
  , privateSnapshot  :: [Some Key]
  }

readKeys :: GlobalOpts -> IO PrivateKeys
readKeys GlobalOpts{..} =
    PrivateKeys <$> readKeysAt (globalKeys </> "root")
                <*> readKeysAt (globalKeys </> "target")
                <*> readKeysAt (globalKeys </> "timestamp")
                <*> readKeysAt (globalKeys </> "snapshot")

writeKeys :: GlobalOpts -> PrivateKeys -> IO ()
writeKeys opts PrivateKeys{..} = do
    forM_ privateRoot      $ writeKey opts "root"
    forM_ privateTarget    $ writeKey opts "target"
    forM_ privateTimestamp $ writeKey opts "timestamp"
    forM_ privateSnapshot  $ writeKey opts "snapshot"

readKeysAt :: FilePath -> IO [Some Key]
readKeysAt dir = catMaybes <$> do
    contents <- getDirectoryContents dir
    forM (filter (not . skip) contents) $ \file -> do
      let path = dir </> file
      mKey <- readCanonical KeyEnv.empty path
      case mKey of
        Left _err -> do logWarn $ "Skipping unrecognized " ++ path
                        return Nothing
        Right key -> return $ Just key
  where
    skip :: FilePath -> Bool
    skip "."            = True
    skip ".."           = True
    skip _              = False

writeKey :: GlobalOpts -> FilePath -> Some Key -> IO ()
writeKey GlobalOpts{..} prefix key = do
    logInfo $ "Creating " ++ path
    createDirectoryIfMissing True (takeDirectory path)
    writeCanonical path key
  where
    kId  = keyIdString (someKeyId key)
    path = globalKeys </> prefix </> kId <.> "private"

{-------------------------------------------------------------------------------
  Bootstrapping / updating

  TODO: Some of this functionality should be moved to
  @Hackage.Security.Server.*@ (to be shared by both, say, Hackage, and
  secure-local),  but I'm not sure precisely in what form yet.
-------------------------------------------------------------------------------}

bootstrapOrUpdate :: GlobalOpts -> Bool -> IO ()
bootstrapOrUpdate opts@GlobalOpts{..} isBootstrap = do
    keys <- readKeys opts
    now  <- getCurrentTime

    newBootstrapped <-
      if not isBootstrap
        then return []
        else do
          -- Create root metadata
          logInfo $ "Creating " ++ globalRepo </> "root.json"
          let root = Root {
                  rootVersion = versionInitial
                , rootExpires = expiresInDays now 365
                , rootKeys    = KeyEnv.fromKeys $ concat [
                                    privateRoot      keys
                                  , privateTarget    keys
                                  , privateSnapshot  keys
                                  , privateTimestamp keys
                                  ]
                , rootRoles   = RootRoles {
                      rootRolesRoot = RoleSpec {
                          roleSpecKeys      = map somePublicKey (privateRoot keys)
                        , roleSpecThreshold = KeyThreshold 2
                        }
                    , rootRolesTargets = RoleSpec {
                          roleSpecKeys      = map somePublicKey (privateTarget keys)
                        , roleSpecThreshold = KeyThreshold 1
                        }
                    , rootRolesSnapshot = RoleSpec {
                          roleSpecKeys      = map somePublicKey (privateSnapshot keys)
                        , roleSpecThreshold = KeyThreshold 1
                        }
                    , rootRolesTimestamp = RoleSpec {
                          roleSpecKeys      = map somePublicKey (privateTimestamp keys)
                        , roleSpecThreshold = KeyThreshold 1
                        }
                    }
                }
              signedRoot = withSignatures (privateRoot keys) root
          void $ writeCanonical' globalRepo "root.json" signedRoot

          -- Create global package metadata
          --
          -- NOTE: Until we introduce author signing, this file is entirely static
          -- (and in fact ignored)
          logInfo $ "Creating " ++ globalRepo </> "targets.json"
          let globalTargets = Targets {
                  targetsVersion     = versionInitial
                , targetsExpires     = Nothing
                , targets            = FileMap.empty
                , targetsDelegations = Just $ Delegations {
                      delegationsKeys  = KeyEnv.empty
                    , delegationsRoles = [
                          DelegationSpec {
                              delegationSpecKeys      = []
                            , delegationSpecThreshold = KeyThreshold 0
                            , delegation = $(qqd "*/*/*" "*/*/targets.json")
                            }
                        ]
                    }
                }
              signedGlobalTargets = withSignatures (privateTarget keys) globalTargets
          newGlobalTargets <- writeCanonical' globalRepo "targets.json" signedGlobalTargets

          return [newGlobalTargets]

    -- Create targets.json for each package version
    pkgs <- findPackages opts
    newPackageMetadata <- forM pkgs $ createPackageMetadata opts

    -- New files to be added to the index
    let newFiles :: [FilePath]
        newFiles = concat [
            catMaybes newBootstrapped
          , concat newPackageMetadata
          ]

    -- Recreate index tarball
    -- TODO: This currently does not allow for .cabal file revisions
    -- (I don't know if this is relevant at all for local repos)
    -- NOTE: This cannot contain snapshot.json (because snapshot has the
    -- hash of the index) or timestamp.json (because that in turn has the
    -- hash of the snapshot).
    logInfo $ "Creating " ++ globalRepo </> "00-index.tar"
    extraFiles <- findExtraIndexFiles opts
    -- TODO: Currently this means that we add the extra files a-new to the index
    -- on every iteration
    let addToIndex = newFiles ++ extraFiles
    Index.appendToTarball
      (globalRepo </> "00-index.tar")
      globalRepo
      addToIndex
    BS.L.writeFile (globalRepo </> "00-index.tar.gz") =<<
      GZip.compress <$> BS.L.readFile (globalRepo </> "00-index.tar")

    -- Create snapshot
    logInfo $ "Creating " ++ globalRepo </> "snapshot.json"
    rootInfo  <- computeFileInfo $ globalRepo </> "root.json"
    tarInfo   <- computeFileInfo $ globalRepo </> "00-index.tar"
    tarGzInfo <- computeFileInfo $ globalRepo </> "00-index.tar.gz"
    let snapshot = Snapshot {
            snapshotVersion   = versionInitial
          , snapshotExpires   = expiresInDays now 3
          , snapshotInfoRoot  = rootInfo
          , snapshotInfoTar   = Just tarInfo
          , snapshotInfoTarGz = tarGzInfo
          }
        signedSnapshot = withSignatures (privateSnapshot keys) snapshot
    writeCanonical (globalRepo </> "snapshot.json") signedSnapshot

    -- Finally, create the timestamp
    logInfo $ "Creating " ++ globalRepo </> "timestamp.json"
    snapshotInfo <- computeFileInfo $ globalRepo </> "snapshot.json"
    let timestamp = Timestamp {
            timestampVersion      = versionInitial
          , timestampExpires      = expiresInDays now 3
          , timestampInfoSnapshot = snapshotInfo
          }
        signedTimestamp = withSignatures (privateTimestamp keys) timestamp
    writeCanonical (globalRepo </> "timestamp.json") signedTimestamp

-- | Create package metadata
--
-- If we find that the package metadata has changed, we return the path of the
-- new @target.json@ as well as the path of the @.cabal@ file so that we know
-- to include it in the index. If nothing changed, we return the empty list.
createPackageMetadata :: GlobalOpts -> PackageIdentifier -> IO [FilePath]
createPackageMetadata GlobalOpts{..} pkgId = do
    logInfo $ "Creating " ++ fullPkgPath </> "targets.json"
    fileMapEntries <- computeFileMapEntries
    let targets = Targets {
            targetsVersion     = versionInitial
          , targetsExpires     = Nothing
          , targets            = FileMap.fromList fileMapEntries
          , targetsDelegations = Nothing
          }
        -- Currently we "sign" with no keys
        signedTargets = withSignatures [] targets
    mUpdated <- writeCanonical' globalRepo (pathPkgMetadata pkgId) signedTargets
    case mUpdated of
      Nothing      -> return []
      Just updated -> return [updated, pathPkgCabal pkgId]
  where
    computeFileMapEntries :: IO [(FilePath, FileInfo)]
    computeFileMapEntries = catMaybes <$> do
      contents <- getDirectoryContents fullPkgPath
      forM (filter (not . skip) contents) $ \file -> do
        let path = fullPkgPath </> file
        isDir <- doesDirectoryExist path
        if isDir
          then do
            logWarn $ "Skipping unrecognized " ++ path
            return Nothing
          else do
            let (_, ext) = splitExtension file
            -- TODO: Not sure how (or if) cabal revisions are stored
            case ext of
              ".gz"      -> Just <$> computeFileMapEntry file
              ".cabal"   -> Just <$> computeFileMapEntry file
              _otherwise -> do logWarn $ "Skipping unrecognized " ++ path
                               return Nothing

    computeFileMapEntry :: FilePath -> IO (FilePath, FileInfo)
    computeFileMapEntry file = do
      info <- computeFileInfo (fullPkgPath </> file)
      return (file, info)

    fullPkgPath :: FilePath
    fullPkgPath = globalRepo </> pathPkg pkgId

    skip :: FilePath -> Bool
    skip "."            = True
    skip ".."           = True
    skip "targets.json" = True
    skip _              = False

{-------------------------------------------------------------------------------
  Auxiliary
-------------------------------------------------------------------------------}

-- | Find all packages in a local repository
--
-- We don't rely on the index because we might have to _create_ the index.
findPackages :: GlobalOpts -> IO [PackageIdentifier]
findPackages GlobalOpts{..} = do
    contents <- getDirectoryContents globalRepo
    pkgs <- forM (filter (not . skipPkg) contents) $ \pkg -> do
      let path = globalRepo </> pkg
      isDir <- doesDirectoryExist path
      if isDir
        then
          findVersions pkg
        else do
          logWarn $ "Skipping unrecognized file " ++ show path
          return []
    return $ concat pkgs
  where
    findVersions :: FilePath -> IO [PackageIdentifier]
    findVersions pkg = catMaybes <$> do
        contents <- getDirectoryContents (globalRepo </> pkg)
        forM (filter (not . skipVersion) contents) $ \version -> do
          let path = globalRepo </> pkg </> version
          isDir <- doesDirectoryExist path
          if isDir
             then
               case simpleParse (pkg ++ "-" ++ version) of
                 Just pkgId -> return $ Just pkgId
                 Nothing    -> do logWarn $ "Skipping unrecognized " ++ path
                                  return Nothing
             else do
               logWarn $ "Skipping unrecognized " ++ path
               return Nothing

    skipPkg :: FilePath -> Bool
    skipPkg "."                  = True
    skipPkg ".."                 = True
    skipPkg "00-index.tar"       = True
    skipPkg "00-index.tar.gz"    = True
    skipPkg "preferred-versions" = True
    skipPkg "targets.json"       = True
    skipPkg "root.json"          = True
    skipPkg "snapshot.json"      = True
    skipPkg "timestamp.json"     = True
    skipPkg _                    = False

    skipVersion :: FilePath -> Bool
    skipVersion "."  = True
    skipVersion ".." = True
    skipVersion _    = False

-- | Find additional files that should be added to the index
findExtraIndexFiles :: GlobalOpts -> IO [FilePath]
findExtraIndexFiles GlobalOpts{..} = catMaybes <$> do
    forM extraIndexFiles $ \file -> do
      let path = globalRepo </> file
      isFile <- doesFileExist path
      if isFile then return $ Just file
                else return Nothing
  where
    extraIndexFiles = [
        "preferred-versions"
      ]

{-------------------------------------------------------------------------------
  Paths
-------------------------------------------------------------------------------}

pathPkg :: PackageIdentifier -> FilePath
pathPkg pkgId = display (packageName pkgId) </> display (packageVersion pkgId)

pathPkgCabal :: PackageIdentifier -> FilePath
pathPkgCabal pkgId = pathPkg pkgId </> display (packageName pkgId) <.> "cabal"

pathPkgMetadata :: PackageIdentifier -> FilePath
pathPkgMetadata pkgId = pathPkg pkgId </> "targets.json"

{-------------------------------------------------------------------------------
  Logging

  TODO: Replace this with a proper logging package
-------------------------------------------------------------------------------}

logInfo :: String -> IO ()
logInfo str = putStrLn $ "Info: " ++ str

logWarn :: String -> IO ()
logWarn str = putStrLn $ "Warning: " ++ str

{-------------------------------------------------------------------------------
  Auxiliary
-------------------------------------------------------------------------------}

-- | Write canonical JSON
--
-- We write the file to a temporary location and compare file info with the
-- file that was already in the target location (if any). If it's the same
-- we don't overwrite it and return Nothing; otherwise we return the path to
-- the file that we wrote (not including the baseDir).
--
-- TODO: This currently uses withSystemTempFile, which means that 'renameFile'
-- might not work. Instead we should (here and elsewhere) have a temporary
-- directory on the same file system. A worry for later.
writeCanonical' :: ToJSON a => FilePath -> FilePath -> a -> IO (Maybe FilePath)
writeCanonical' baseDir file a = do
    withSystemTempFile (takeFileName file) $ \tempPath h -> do
      BS.L.hPut h $ renderJSON a
      hClose h
      oldFileInfo <- computeFileInfo' fp
      newFileInfo <- computeFileInfo tempPath
      if oldFileInfo == Just newFileInfo
        then return $ Nothing
        else do renameFile tempPath fp
                return $ Just file
  where
    fp = baseDir </> file

computeFileInfo' :: FilePath -> IO (Maybe FileInfo)
computeFileInfo' fp =
    handle doesNotExist $ Just <$> computeFileInfo fp
  where
    doesNotExist e = if isDoesNotExistError e
                       then return Nothing
                       else throwIO e
