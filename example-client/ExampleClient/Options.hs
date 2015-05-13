module ExampleClient.Options (
    GlobalOpts(..)
  , Command(..)
  , getOptions
  ) where

import Options.Applicative

{-------------------------------------------------------------------------------
  Datatypes
-------------------------------------------------------------------------------}

data GlobalOpts = GlobalOpts {
    -- | Root directory of the repository
    globalRepo :: FilePath

    -- | Directory to store the client cache
  , globalCache :: FilePath

    -- | Command to execute
  , globalCommand :: Command
  }
  deriving Show

data Command =
    -- | Check for updates on the server
    Check
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
  <*> (subparser $ mconcat [
          command "check" $
            info (pure Check)
                 (progDesc "Check for updates")
        ])
