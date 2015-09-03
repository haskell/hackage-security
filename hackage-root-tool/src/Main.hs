{-# LANGUAGE CPP, ScopedTypeVariables, RecordWildCards #-}
module Main (main) where

import Data.Monoid
import Control.Exception
import GHC.Conc.Sync (setUncaughtExceptionHandler)
import System.Exit

-- hackage-security
import Hackage.Security.Server
import Hackage.Security.Util.Some
import Hackage.Security.Util.Path
import Text.JSON.Canonical (JSValue)

import Options.Applicative


{-------------------------------------------------------------------------------
  Main application driver
-------------------------------------------------------------------------------}

main :: IO ()
main = do
    setUncaughtExceptionHandler topLevelExceptionHandler
    GlobalOpts{..} <- getOptions
    case globalCommand of
      CreateKeys ->
        createKeys

      Sign key deleteExisting file -> do
        key'  <- makeAbsolute (fromFilePath key)
        file' <- makeAbsolute (fromFilePath file)
        signFile key' deleteExisting file'

-- | Top-level exception handler that uses 'displayException'
--
-- Although base 4.8 introduces 'displayException', the top-level exception
-- handler still uses 'show', sadly. See "PROPOSAL: Add displayException to
-- Exception typeclass" thread on the libraries mailing list.
--
-- NOTE: This is a terrible hack. See the above thread for some insights into
-- how we should do this better. For now it will do however.
topLevelExceptionHandler :: SomeException -> IO ()
topLevelExceptionHandler e = do
    putStrLn $ displayException e
    exitFailure

#if !MIN_VERSION_base(4,8,0)
displayException :: Exception e => e -> String
displayException = show
#endif

{-------------------------------------------------------------------------------
  Creating keys
-------------------------------------------------------------------------------}

createKeys :: IO ()
createKeys = do
    privateRoot <- createKey' KeyTypeEd25519
    writeKey privateRoot

{-------------------------------------------------------------------------------
  Dealing with (private) keys
-------------------------------------------------------------------------------}

writeKey :: Some Key -> IO ()
writeKey keypair = do
    let keypath = keyIdString (someKeyId keypair)
    keypathabs <- makeAbsolute (fromFilePath keypath)

    logInfo $ "Writing new key:\n  " ++ keypath ++ ".{private,public}"

    writeJSON_NoLayout (keypathabs <.> "private") keypair
    writeJSON_NoLayout (keypathabs <.> "public")  keypublic
  where
    keypublic :: Some PublicKey
    keypublic = somePublicKey keypair

{-------------------------------------------------------------------------------
  Signing individual files
-------------------------------------------------------------------------------}

signFile :: KeyLoc -> DeleteExistingSignatures -> AbsolutePath -> IO ()
signFile keyLoc deleteExisting fp = do
    UninterpretedSignatures (payload :: JSValue) oldSigs <-
      throwErrors =<< readJSON_NoKeys_NoLayout fp
    keys :: [Some Key] <-
      throwErrors =<< readJSON_NoKeys_NoLayout keyLoc
    let newSigs = concat [
            if deleteExisting then [] else oldSigs
          , toPreSignatures (signRendered keys $ renderJSON_NoLayout payload)
          ]
    writeJSON_NoLayout (fp </> fragment' "sig") newSigs

{-------------------------------------------------------------------------------
  Logging
-------------------------------------------------------------------------------}

logInfo :: String -> IO ()
logInfo msg = putStrLn msg

{-------------------------------------------------------------------------------
  Auxiliary
-------------------------------------------------------------------------------}

throwErrors :: Exception e => Either e a -> IO a
throwErrors (Left err) = throwIO err
throwErrors (Right a)  = return a

{-------------------------------------------------------------------------------
  Types
-------------------------------------------------------------------------------}

-- | Command line options
data GlobalOpts = GlobalOpts {

    -- | Command to execute
    globalCommand :: Command
  }

data Command =
    -- | Create keys
    CreateKeys

    -- | Sign an individual file
  | Sign FilePath DeleteExistingSignatures FilePath

type KeyLoc                   = AbsolutePath
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

parseCreateKeys :: Parser Command
parseCreateKeys = pure CreateKeys

parseSign :: Parser Command
parseSign = Sign
  <$> (option str $ mconcat [
         long "key"
       , help "Path to private key (can be specified multiple times)"
       ])
  <*> (switch $ mconcat [
         long "delete-existing"
       , help "Delete any existing signatures"
       ])
  <*> argument str (metavar "FILE")

-- | Global options
--
-- TODO: Make repo and keys layout configurable
parseGlobalOptions :: Parser GlobalOpts
parseGlobalOptions =
      GlobalOpts
  <$> (subparser $ mconcat [
          command "create-key" $ info (helper <*> parseCreateKeys) $
            progDesc "Create keys"
        , command "sign" $ info (helper <*> parseSign) $
            progDesc "Sign a file"
        ])

