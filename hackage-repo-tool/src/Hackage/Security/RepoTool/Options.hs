{-# LANGUAGE CPP #-}
module Hackage.Security.RepoTool.Options (
    GlobalOpts(..)
  , Command(..)
  , KeyLoc
  , DeleteExistingSignatures
  , getOptions
  ) where

import Network.URI (URI, parseURI)
import Options.Applicative
import System.IO.Unsafe (unsafePerformIO)

import Hackage.Security.Client
import Hackage.Security.Util.Path

import Hackage.Security.RepoTool.Layout.Keys
import Hackage.Security.RepoTool.Paths

{-------------------------------------------------------------------------------
  Types
-------------------------------------------------------------------------------}

-- | Command line options
data GlobalOpts = GlobalOpts {
    -- | Key directory layout
    globalKeysLayout :: KeysLayout

    -- | Local repository layout
  , globalRepoLayout :: RepoLayout

    -- | Local index layout
  , globalIndexLayout :: IndexLayout

    -- | Should we be verbose?
  , globalVerbose :: Bool

    -- | Expiry time when creating root (in years)
  , globalExpireRoot :: Integer

    -- | Expiry time when creating mirrors (in years)
  , globalExpireMirrors :: Integer

    -- | Command to execute
  , globalCommand :: Command
  }

data Command =
    -- | Create keys
    CreateKeys KeysLoc

    -- | Bootstrap a secure local repository
  | Bootstrap KeysLoc RepoLoc

    -- | Update a previously bootstrapped local repository
  | Update KeysLoc RepoLoc

    -- | Create root metadta
  | CreateRoot KeysLoc (Path Absolute)

    -- | Create mirrors metadata
  | CreateMirrors KeysLoc (Path Absolute) [URI]

#ifndef mingw32_HOST_OS
    -- | Create a directory with symlinks in cabal-local-rep layout
  | SymlinkCabalLocalRepo RepoLoc RepoLoc
#endif

    -- | Sign an individual file
  | Sign [KeyLoc] DeleteExistingSignatures (Path Absolute)

type KeyLoc                   = Path Absolute
type DeleteExistingSignatures = Bool

{-------------------------------------------------------------------------------
  Parsers
-------------------------------------------------------------------------------}

getOptions :: IO GlobalOpts
getOptions = execParser opts
  where
    opts = info (helper <*> parseGlobalOptions) $ mconcat [
        fullDesc
      , header "Manage local Hackage repositories"
      ]

parseRepoLoc :: Parser RepoLoc
parseRepoLoc = RepoLoc <$> (option (str >>= readAbsolutePath) $ mconcat [
      long "repo"
    , metavar "PATH"
    , help "Path to local repository"
    ])

parseKeysLoc :: Parser KeysLoc
parseKeysLoc = KeysLoc <$> (option (str >>= readAbsolutePath) $ mconcat [
      long "keys"
    , metavar "PATH"
    , help "Path to key store"
    ])

parseCreateKeys :: Parser Command
parseCreateKeys = CreateKeys <$> parseKeysLoc

parseBootstrap :: Parser Command
parseBootstrap = Bootstrap <$> parseKeysLoc <*> parseRepoLoc

parseUpdate :: Parser Command
parseUpdate = Update <$> parseKeysLoc <*> parseRepoLoc

parseCreateRoot :: Parser Command
parseCreateRoot = CreateRoot
  <$> parseKeysLoc
  <*> (option (str >>= readAbsolutePath) $ mconcat [
          short 'o'
        , metavar "FILE"
        , help "Location of the root file"
        ])

parseCreateMirrors :: Parser Command
parseCreateMirrors = CreateMirrors
  <$> parseKeysLoc
  <*> (option (str >>= readAbsolutePath) $ mconcat [
          short 'o'
        , metavar "FILE"
        , help "Location of the mirrors file"
        ])
  <*> (many $ argument (str >>= readURI) (metavar "MIRROR"))

#ifndef mingw32_HOST_OS
parseSymlinkCabalLocalRepo :: Parser Command
parseSymlinkCabalLocalRepo = SymlinkCabalLocalRepo
  <$> parseRepoLoc
  <*> (option (str >>= liftA RepoLoc . readAbsolutePath) $ mconcat [
          long "cabal-repo"
        , help "Location of the cabal repo"
        ])
#endif

parseSign :: Parser Command
parseSign = Sign
  <$> (many . option (str >>= readAbsolutePath) $ mconcat [
         long "key"
       , help "Path to private key (can be specified multiple times)"
       ])
  <*> (switch $ mconcat [
         long "delete-existing"
       , help "Delete any existing signatures"
       ])
  <*> argument (str >>= readAbsolutePath) (metavar "FILE")

-- | Global options
--
-- TODO: Make repo and keys layout configurable
parseGlobalOptions :: Parser GlobalOpts
parseGlobalOptions = GlobalOpts
  <$> (pure defaultKeysLayout)
  <*> (pure hackageRepoLayout)
  <*> (pure hackageIndexLayout)
  <*> (switch $ mconcat [
          long "verbose"
        , short 'v'
        , help "Verbose logging"
        ])
  <*> (option auto $ mconcat [
          long "expire-root"
        , metavar "YEARS"
        , help "Expiry time for the root info"
        , value 1
        , showDefault
        ])
  <*> (option auto $ mconcat [
          long "expire-mirrors"
        , metavar "YEARS"
        , help "Expiry time for the mirrors"
        , value 10
        , showDefault
        ])
  <*> (subparser $ mconcat [
          command "create-keys" $ info (helper <*> parseCreateKeys) $
            progDesc "Create keys"
        , command "bootstrap" $ info (helper <*> parseBootstrap) $
            progDesc "Bootstrap a local repository"
        , command "update" $ info (helper <*> parseUpdate) $
            progDesc "Update a (previously bootstrapped) local repository"
        , command "create-root" $ info (helper <*> parseCreateRoot) $
            progDesc "Create root metadata"
        , command "create-mirrors" $ info (helper <*> parseCreateMirrors) $
            progDesc "Create mirrors metadata. All MIRRORs specified on the command line will be written to the file."
#ifndef mingw32_HOST_OS
        , command "symlink-cabal-local-repo" $ info (helper <*> parseSymlinkCabalLocalRepo) $
            progDesc "Create a directory in cabal-local-repo layout with symlinks to the specified repository."
#endif
        , command "sign" $ info (helper <*> parseSign) $
            progDesc "Sign a file"
        ])

readURI :: String -> ReadM URI
readURI uriStr =
   case parseURI uriStr of
     Nothing  -> fail $ "Invalid URI " ++ show uriStr
     Just uri -> return uri

-- Sadly, cannot do I/O actions inside ReadM
readAbsolutePath :: String -> ReadM (Path Absolute)
readAbsolutePath = return . unsafePerformIO . makeAbsolute . fromFilePath
