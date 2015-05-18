module ExampleClient.Options (
    GlobalOpts(..)
  , Command(..)
  , getOptions
  ) where

import Options.Applicative

import Distribution.Package
import Distribution.Text

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

    -- | Command to execute
  , globalCommand :: Command
  }
  deriving Show

data Command =
    -- | Check for updates on the server
    Check

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
        , metavar "PATH"
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
       , help "HTTP client to use (currently supported: HTTP and http-conduit)"
       ])
  <*> (subparser $ mconcat [
          command "check" $
            info (pure Check)
                 (progDesc "Check for updates")
        , command "get" $
            info (Get <$> argument readPackageIdentifier (metavar "PKG"))
                 (progDesc "Download a package")
        ])

readPackageIdentifier :: ReadM PackageIdentifier
readPackageIdentifier = do
    raw <- str
    case simpleParse raw of
      Just pkgId -> return pkgId
      Nothing    -> fail $ "Invalid package ID " ++ show raw
