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

      Sign key file -> do
        key'  <- makeAbsolute (fromFilePath key)
        file' <- makeAbsolute (fromFilePath file)
        signFile key' file'

      GetKeyId key -> do
        key'  <- makeAbsolute (fromFilePath key)
        getKeyId key'

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

signFile :: KeyLoc -> Path Absolute -> IO ()
signFile keyLoc fp = do
    UninterpretedSignatures (payload :: JSValue) _oldSigs <-
      throwErrors =<< readJSON_NoKeys_NoLayout fp
    key :: Some Key <-
      throwErrors =<< readJSON_NoKeys_NoLayout keyLoc
    let newSig = toPreSignatures (signRendered [key]
                                               (renderJSON_NoLayout payload))
    writeJSON_NoLayout (fp <.> "sig") newSig

{-------------------------------------------------------------------------------
  Retrieving the key id of a key
-------------------------------------------------------------------------------}

getKeyId :: KeyLoc -> IO ()
getKeyId keyLoc = do
    pubkey :: Some PublicKey <-
      throwErrors =<< readJSON_NoKeys_NoLayout keyLoc
    let keyid = keyIdString (someKeyId pubkey)
    logInfo $ "The keyid of this key is:\n  " ++ keyid

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
  | Sign FilePath FilePath

    -- | Get the key id of a key file
  | GetKeyId FilePath

type KeyLoc = Path Absolute

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
  <$> argument str (metavar "KEY")
  <*> argument str (metavar "FILE")

parseGetKeyId :: Parser Command
parseGetKeyId = GetKeyId
  <$> argument str (metavar "KEY")

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
        , command "keyid" $ info (helper <*> parseGetKeyId) $
            progDesc "Get the KeyId of a key file"
        ])
