module ExampleClient.Options (
    GlobalOpts(..)
  , Command(..)
  , getOptions
  ) where

import Options.Applicative

import Distribution.Package
import Distribution.Text

import Hackage.Security.Key
import Hackage.Security.TUF
import Hackage.Security.Client (CheckExpiry(..))

{-------------------------------------------------------------------------------
  Datatypes
-------------------------------------------------------------------------------}

data GlobalOpts = GlobalOpts {
    -- | Root directory of the repository
    globalRepo :: FilePath

    -- | Directory to store the client cache
  , globalCache :: FilePath

    -- | HTTP client to use
  , globalHttpClient :: String

    -- | Trusted root key (used for bootstrapping)
  , globalRootKeys :: [KeyId]

    -- | Should we check expiry times?
  , globalCheckExpiry :: CheckExpiry

    -- | Command to execute
  , globalCommand :: Command
  }
  deriving Show

data Command =
    -- | Get initial root info
    Bootstrap KeyThreshold

    -- | Check for updates on the server
  | Check

    -- | Download a specific package
  | Get PackageIdentifier
  deriving Show

{-------------------------------------------------------------------------------
  Parsers
-------------------------------------------------------------------------------}

getOptions :: IO GlobalOpts
getOptions = execParser opts
  where
    opts = info (helper <*> parseGlobalOptions) $ mconcat [
        fullDesc
      , header "Example Hackage client"
      ]

parseGlobalOptions :: Parser GlobalOpts
parseGlobalOptions = GlobalOpts
  <$> (strOption $ mconcat [
          long "repo"
        , metavar "URL"
        , help "Path to local repository"
        ])
  <*> (strOption $ mconcat [
          long "cache"
        , metavar "PATH"
        , help "Path to client cache"
        ])
  <*> (strOption $ mconcat [
         long "http-client"
       , metavar "CLIENT"
       , value "HTTP"
       , showDefault
       , help "HTTP client to use (currently supported: HTTP, http-conduit, curl)"
       ])
  <*> (many . option readKeyId $ mconcat [
         long "root-key"
       , metavar "KEYID"
       , help "Root key (used for bootstrapping; can be used multiple times)"
       ])
  <*> (flag CheckExpiry DontCheckExpiry $ mconcat [
         long "ignore-expiry"
       , help "Don't check expiry dates (should only be used in exceptional circumstances)"
       ])
  <*> (subparser $ mconcat [
          command "bootstrap" $
            info (Bootstrap <$> argument readKeyThreshold (metavar "THRESHOLD"))
                 (progDesc "Get the initial root information. If using a key threshold larger than 0, you will need to use the --root-key option to specify one or more trusted root keys.")
        , command "check" $
            info (pure Check)
                 (progDesc "Check for updates")
        , command "get" $
            info (Get <$> argument readPackageIdentifier (metavar "PKG"))
                 (progDesc "Download a package")
        ])

readKeyId :: ReadM KeyId
readKeyId = KeyId <$> str

readKeyThreshold :: ReadM KeyThreshold
readKeyThreshold = KeyThreshold <$> auto

readPackageIdentifier :: ReadM PackageIdentifier
readPackageIdentifier = do
    raw <- str
    case simpleParse raw of
      Just pkgId -> return pkgId
      Nothing    -> fail $ "Invalid package ID " ++ show raw
