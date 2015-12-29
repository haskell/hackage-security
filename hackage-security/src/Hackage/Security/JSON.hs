-- | Hackage-specific wrappers around the Util.JSON module
{-# LANGUAGE CPP #-}
module Hackage.Security.JSON (
    -- * Deserialization errors
    DeserializationError(..)
  , validate
  , verifyType
    -- * MonadKeys
  , MonadKeys(..)
  , addKeys
  , withKeys
  , lookupKey
  , readKeyAsId
    -- * Reader monads
  , ReadJSON_Keys_Layout
  , ReadJSON_Keys_NoLayout
  , ReadJSON_NoKeys_NoLayout
  , runReadJSON_Keys_Layout
  , runReadJSON_Keys_NoLayout
  , runReadJSON_NoKeys_NoLayout
    -- ** Utility
  , parseJSON_Keys_Layout
  , parseJSON_Keys_NoLayout
  , parseJSON_NoKeys_NoLayout
  , readJSON_Keys_Layout
  , readJSON_Keys_NoLayout
  , readJSON_NoKeys_NoLayout
    -- * Writing
  , WriteJSON
  , runWriteJSON
    -- ** Utility
  , renderJSON
  , renderJSON_NoLayout
  , writeJSON
  , writeJSON_NoLayout
  , writeKeyAsId
    -- * Re-exports
  , module Hackage.Security.Util.JSON
  ) where

import Control.Arrow (first, second)
import Control.Exception
import Control.Monad.Except
import Control.Monad.Reader
import Data.Functor.Identity
import Data.Typeable (Typeable)
import qualified Data.ByteString.Lazy as BS.L

import Hackage.Security.Key
import Hackage.Security.Key.Env (KeyEnv)
import Hackage.Security.TUF.Layout.Repo
import Hackage.Security.Util.JSON
import Hackage.Security.Util.Path
import Hackage.Security.Util.Pretty
import Hackage.Security.Util.Some
import Text.JSON.Canonical
import qualified Hackage.Security.Key.Env as KeyEnv

{-------------------------------------------------------------------------------
  Deserialization errors
-------------------------------------------------------------------------------}

data DeserializationError =
    -- | Malformed JSON has syntax errors in the JSON itself
    -- (i.e., we cannot even parse it to a JSValue)
    DeserializationErrorMalformed String

    -- | Invalid JSON has valid syntax but invalid structure
    --
    -- The string gives a hint about what we expected instead
  | DeserializationErrorSchema String

    -- | The JSON file contains a key ID of an unknown key
  | DeserializationErrorUnknownKey KeyId

    -- | Some verification step failed
  | DeserializationErrorValidation String

    -- | Wrong file type
    --
    -- Records actual and expected types.
  | DeserializationErrorFileType String String
  deriving (Typeable)

#if MIN_VERSION_base(4,8,0)
deriving instance Show DeserializationError
instance Exception DeserializationError where displayException = pretty
#else
instance Show DeserializationError where show = pretty
instance Exception DeserializationError
#endif

instance Pretty DeserializationError where
  pretty (DeserializationErrorMalformed str) =
      "Malformed: " ++ str
  pretty (DeserializationErrorSchema str) =
      "Schema error: " ++ str
  pretty (DeserializationErrorUnknownKey kId) =
      "Unknown key: " ++ keyIdString kId
  pretty (DeserializationErrorValidation str) =
      "Invalid: " ++ str
  pretty (DeserializationErrorFileType actualType expectedType) =
         "Expected file of type " ++ show expectedType
      ++ " but got file of type " ++ show actualType

validate :: MonadError DeserializationError m => String -> Bool -> m ()
validate _   True  = return ()
validate msg False = throwError $ DeserializationErrorValidation msg

verifyType :: (ReportSchemaErrors m, MonadError DeserializationError m)
           => JSValue -> String -> m ()
verifyType enc expectedType = do
    actualType <- fromJSField enc "_type"
    unless (actualType == expectedType) $
      throwError $ DeserializationErrorFileType actualType expectedType

{-------------------------------------------------------------------------------
  Access to keys
-------------------------------------------------------------------------------}

-- | MonadReader-like monad, specialized to key environments
class (ReportSchemaErrors m, MonadError DeserializationError m) => MonadKeys m where
  localKeys :: (KeyEnv -> KeyEnv) -> m a -> m a
  askKeys   :: m KeyEnv

readKeyAsId :: MonadKeys m => JSValue -> m (Some PublicKey)
readKeyAsId (JSString kId) = lookupKey (KeyId kId)
readKeyAsId val            = expected' "key ID" val

addKeys :: MonadKeys m => KeyEnv -> m a -> m a
addKeys keys = localKeys (KeyEnv.union keys)

withKeys :: MonadKeys m => KeyEnv -> m a -> m a
withKeys keys = localKeys (const keys)

lookupKey :: MonadKeys m => KeyId -> m (Some PublicKey)
lookupKey kId = do
    keyEnv <- askKeys
    case KeyEnv.lookup kId keyEnv of
      Just key -> return key
      Nothing  -> throwError $ DeserializationErrorUnknownKey kId

{-------------------------------------------------------------------------------
  Reading
-------------------------------------------------------------------------------}

newtype ReadJSON_Keys_Layout a = ReadJSON_Keys_Layout {
    unReadJSON_Keys_Layout :: ExceptT DeserializationError (Reader (RepoLayout, KeyEnv)) a
  }
  deriving ( Functor
           , Applicative
           , Monad
           , MonadError DeserializationError
           )

newtype ReadJSON_Keys_NoLayout a = ReadJSON_Keys_NoLayout {
    unReadJSON_Keys_NoLayout :: ExceptT DeserializationError (Reader KeyEnv) a
  }
  deriving ( Functor
           , Applicative
           , Monad
           , MonadError DeserializationError
           )

newtype ReadJSON_NoKeys_NoLayout a = ReadJSON_NoKeys_NoLayout {
    unReadJSON_NoKeys_NoLayout :: Except DeserializationError a
  }
  deriving ( Functor
           , Applicative
           , Monad
           , MonadError DeserializationError
           )

instance ReportSchemaErrors ReadJSON_Keys_Layout where
  expected str mgot = throwError $ expectedError str mgot
instance ReportSchemaErrors ReadJSON_Keys_NoLayout where
  expected str mgot = throwError $ expectedError str mgot
instance ReportSchemaErrors ReadJSON_NoKeys_NoLayout where
  expected str mgot = throwError $ expectedError str mgot

expectedError :: Expected -> Maybe Got -> DeserializationError
expectedError str mgot = DeserializationErrorSchema msg
  where
    msg = case mgot of
            Nothing  -> "Expected " ++ str
            Just got -> "Expected " ++ str ++ " but got " ++ got

instance MonadReader RepoLayout ReadJSON_Keys_Layout where
  ask         = ReadJSON_Keys_Layout $ fst `liftM` ask
  local f act = ReadJSON_Keys_Layout $ local (first f) act'
    where
      act' = unReadJSON_Keys_Layout act

instance MonadKeys ReadJSON_Keys_Layout where
  askKeys         = ReadJSON_Keys_Layout $ snd `liftM` ask
  localKeys f act = ReadJSON_Keys_Layout $ local (second f) act'
    where
      act' = unReadJSON_Keys_Layout act

instance MonadKeys ReadJSON_Keys_NoLayout where
  askKeys         = ReadJSON_Keys_NoLayout $ ask
  localKeys f act = ReadJSON_Keys_NoLayout $ local f act'
    where
      act' = unReadJSON_Keys_NoLayout act

runReadJSON_Keys_Layout :: KeyEnv
                        -> RepoLayout
                        -> ReadJSON_Keys_Layout a
                        -> Either DeserializationError a
runReadJSON_Keys_Layout keyEnv repoLayout act =
    runReader (runExceptT (unReadJSON_Keys_Layout act)) (repoLayout, keyEnv)

runReadJSON_Keys_NoLayout :: KeyEnv
                          -> ReadJSON_Keys_NoLayout a
                          -> Either DeserializationError a
runReadJSON_Keys_NoLayout keyEnv act =
    runReader (runExceptT (unReadJSON_Keys_NoLayout act)) keyEnv

runReadJSON_NoKeys_NoLayout :: ReadJSON_NoKeys_NoLayout a
                            -> Either DeserializationError a
runReadJSON_NoKeys_NoLayout act =
    runExcept (unReadJSON_NoKeys_NoLayout act)

{-------------------------------------------------------------------------------
  Utility
-------------------------------------------------------------------------------}

parseJSON_Keys_Layout :: FromJSON ReadJSON_Keys_Layout a
                      => KeyEnv
                      -> RepoLayout
                      -> BS.L.ByteString
                      -> Either DeserializationError a
parseJSON_Keys_Layout keyEnv repoLayout bs =
    case parseCanonicalJSON bs of
      Left  err -> Left (DeserializationErrorMalformed err)
      Right val -> runReadJSON_Keys_Layout keyEnv repoLayout (fromJSON val)

parseJSON_Keys_NoLayout :: FromJSON ReadJSON_Keys_NoLayout a
                        => KeyEnv
                        -> BS.L.ByteString
                        -> Either DeserializationError a
parseJSON_Keys_NoLayout keyEnv bs =
    case parseCanonicalJSON bs of
      Left  err -> Left (DeserializationErrorMalformed err)
      Right val -> runReadJSON_Keys_NoLayout keyEnv (fromJSON val)

parseJSON_NoKeys_NoLayout :: FromJSON ReadJSON_NoKeys_NoLayout a
                          => BS.L.ByteString
                          -> Either DeserializationError a
parseJSON_NoKeys_NoLayout bs =
    case parseCanonicalJSON bs of
      Left  err -> Left (DeserializationErrorMalformed err)
      Right val -> runReadJSON_NoKeys_NoLayout (fromJSON val)

readJSON_Keys_Layout :: ( FsRoot root
                        , FromJSON ReadJSON_Keys_Layout a
                        )
                     => KeyEnv
                     -> RepoLayout
                     -> Path root
                     -> IO (Either DeserializationError a)
readJSON_Keys_Layout keyEnv repoLayout fp = do
    withFile fp ReadMode $ \h -> do
      bs <- BS.L.hGetContents h
      evaluate $ parseJSON_Keys_Layout keyEnv repoLayout bs

readJSON_Keys_NoLayout :: ( FsRoot root
                          , FromJSON ReadJSON_Keys_NoLayout a
                          )
                       => KeyEnv
                       -> Path root
                       -> IO (Either DeserializationError a)
readJSON_Keys_NoLayout keyEnv fp = do
    withFile fp ReadMode $ \h -> do
      bs <- BS.L.hGetContents h
      evaluate $ parseJSON_Keys_NoLayout keyEnv bs

readJSON_NoKeys_NoLayout :: ( FsRoot root
                            , FromJSON ReadJSON_NoKeys_NoLayout a
                            )
                         => Path root
                         -> IO (Either DeserializationError a)
readJSON_NoKeys_NoLayout fp = do
    withFile fp ReadMode $ \h -> do
      bs <- BS.L.hGetContents h
      evaluate $ parseJSON_NoKeys_NoLayout bs

{-------------------------------------------------------------------------------
  Writing
-------------------------------------------------------------------------------}

newtype WriteJSON a = WriteJSON {
    unWriteJSON :: Reader RepoLayout a
  }
  deriving ( Functor
           , Applicative
           , Monad
           , MonadReader RepoLayout
           )

runWriteJSON :: RepoLayout -> WriteJSON a -> a
runWriteJSON repoLayout act = runReader (unWriteJSON act) repoLayout

{-------------------------------------------------------------------------------
  Writing: Utility
-------------------------------------------------------------------------------}

-- | Render to canonical JSON format
renderJSON :: ToJSON WriteJSON a => RepoLayout -> a -> BS.L.ByteString
renderJSON repoLayout = renderCanonicalJSON . runWriteJSON repoLayout . toJSON

-- | Variation on 'renderJSON' for files that don't require the repo layout
renderJSON_NoLayout :: ToJSON Identity a => a -> BS.L.ByteString
renderJSON_NoLayout = renderCanonicalJSON . runIdentity . toJSON

writeJSON :: ToJSON WriteJSON a => RepoLayout -> Path Absolute -> a -> IO ()
writeJSON repoLayout fp = writeLazyByteString fp . renderJSON repoLayout

writeJSON_NoLayout :: ToJSON Identity a => Path Absolute -> a -> IO ()
writeJSON_NoLayout fp = writeLazyByteString fp . renderJSON_NoLayout

writeKeyAsId :: Some PublicKey -> JSValue
writeKeyAsId = JSString . keyIdString . someKeyId
