module Hackage.Security.TUF.Targets (
    -- * TUF types
    Targets(..)
  , DelegationSpec(..)
  , Delegation(..)
    -- * Utility
  , matchDelegation
  ) where

import Control.Monad.Except
import Data.Time
import System.FilePath

import Hackage.Security.JSON
import Hackage.Security.Key
import Hackage.Security.Key.Env (KeyEnv)
import Hackage.Security.Key.ExplicitSharing
import Hackage.Security.Some
import Hackage.Security.TUF.Ints
import Hackage.Security.TUF.FileMap (FileMap)

{-------------------------------------------------------------------------------
  TUF types
-------------------------------------------------------------------------------}

data Targets = Targets {
    targetsVersion     :: FileVersion
  , targetsExpires     :: UTCTime
  , targets            :: FileMap
  , targetsDelegations :: Delegations
  }

-- | Delegations
--
-- Much like the Root datatype, this must have an invariant that ALL used keys
-- (apart from the global keys, which are in the root key environment) must
-- be listed in 'delegationsKeys'.
data Delegations = Delegations {
    delegationsKeys  :: KeyEnv
  , delegationsRoles :: [DelegationSpec]
  }

-- | Delegation specification
--
-- NOTE: This is a close analogue of 'RoleSpec'.
data DelegationSpec = DelegationSpec {
    delegationSpecKeys      :: [Some PublicKey]
  , delegationSpecThreshold :: KeyThreshold
  , delegation              :: Delegation
  }

-- | A delegation
--
-- See 'match' for an example.
data Delegation = forall a. Delegation (Pattern a) (Replacement a)

deriving instance Show Delegation

{-------------------------------------------------------------------------------
  Patterns and replacements
-------------------------------------------------------------------------------}

data h :- t = h :- t
  deriving (Eq, Show)
infixr 5 :-

type FileName  = String
type Directory = String
type Extension = String
type BaseName  = String

-- | Structured patterns over paths
--
-- The type argument indicates what kind of function we expect when the
-- pattern matches. For example, we have the pattern @"*/*.txt"@:
--
-- > PathPatternDirAny (PathPatternFileExt ".txt")
-- >   :: PathPattern (Directory :- BaseName :- ())
data Pattern a where
    -- | Match against a specific filename
    PatFileConst :: FileName -> Pattern ()

    -- | Match against a filename with the given extension
    PatFileExt :: Extension -> Pattern (BaseName :- ())

    -- | Match against a specific directory
    PatDirConst :: Directory -> Pattern a -> Pattern a

    -- | Match against any directory
    PatDirAny :: Pattern a -> Pattern (Directory :- a)

-- | Replacement patterns
--
-- These constructors match the ones in 'Pattern': wildcards must be used
-- in the same order as they appear in the pattern, but they don't all have to
-- be used (that's why the base constructors are polymorphic in the stack tail).
data Replacement a where
    RepFileConst :: FileName -> Replacement a
    RepFileExt   :: Extension -> Replacement (BaseName :- a)
    RepDirConst  :: Directory -> Replacement a -> Replacement a
    RepDirAny    :: Replacement a -> Replacement (Directory :- a)

deriving instance Eq   (Pattern typ)
deriving instance Show (Pattern typ)

deriving instance Eq   (Replacement typ)
deriving instance Ord  (Replacement typ)
deriving instance Show (Replacement typ)

-- Somewhat tricky to define (must either skip inaccessible patterns, but then
-- add an error case, or else use wildcards to cover these cases)
instance Ord (Pattern typ) where
    a `compare` b =
      case (a, b) of
        (PatFileConst f   , PatFileConst f'   ) -> f `compare` f'
        (PatFileConst _   , _                 ) -> LT

        (PatFileExt   e   , PatFileExt   e'   ) -> e `compare` e'
        (PatFileExt   _   , PatDirConst  _ _  ) -> LT
        (PatFileExt   _   , PatDirAny      _  ) -> LT
        (PatFileExt   _   , _                 ) -> GT -- case for PatFileConst

        (PatDirConst  _ _ , PatFileConst _    ) -> GT
        (PatDirConst  _ _ , PatFileExt   _    ) -> GT
        (PatDirConst  c p , PatDirConst  c' p') -> (c, p) `compare` (c', p')
        (PatDirConst  _ _ , _                 ) -> LT

        (PatDirAny      p , PatDirAny       p') -> compare p p'
        (PatDirAny      _ , _                 ) -> GT

{-------------------------------------------------------------------------------
  Matching
-------------------------------------------------------------------------------}

matchPattern :: String -> Pattern a -> Maybe a
matchPattern = go . splitDirectories
  where
    go :: [String] -> Pattern a -> Maybe a
    go []    _                    = Nothing
    go [f]   (PatFileConst f')    = do guard (f == f')
                                       return ()
    go [f]   (PatFileExt   e')    = do let (bn, _:e) = splitExtension f
                                       guard $ e == e'
                                       return (bn :- ())
    go [_]   _                    = Nothing
    go (d:p) (PatDirConst  d' p') = do guard (d == d')
                                       go p p'
    go (d:p) (PatDirAny       p') = (d :-) <$> go p p'
    go (_:_) _                    = Nothing

constructReplacement :: Replacement a -> a -> String
constructReplacement = \repl a -> joinPath $ go repl a
  where
    go :: Replacement a -> a -> [String]
    go (RepFileConst c)   _         = [c]
    go (RepFileExt   e)   (bn :- _) = [bn <.> e]
    go (RepDirConst  d p) a         = d : go p a
    go (RepDirAny      p) (d  :- a) = d : go p a

matchDelegation :: Delegation -> String -> Maybe String
matchDelegation (Delegation pat repl) str =
    constructReplacement repl <$> matchPattern str pat

{-------------------------------------------------------------------------------
  Typechecking patterns and replacements
-------------------------------------------------------------------------------}

data PatternType a where
  PatTypeNil       :: PatternType ()
  PatTypeBaseName  :: PatternType a -> PatternType (BaseName  :- a)
  PatTypeDirectory :: PatternType a -> PatternType (Directory :- a)

instance Unify PatternType where
  unify PatTypeNil           PatTypeNil            = Just Refl
  unify (PatTypeBaseName  p) (PatTypeBaseName  p') = case unify p p' of
                                                       Just Refl -> Just Refl
                                                       Nothing   -> Nothing
  unify (PatTypeDirectory p) (PatTypeDirectory p') = case unify p p' of
                                                       Just Refl -> Just Refl
                                                       Nothing   -> Nothing
  unify _                    _                     = Nothing

type instance TypeOf Pattern     = PatternType
type instance TypeOf Replacement = PatternType

instance Typed Pattern where
  typeOf (PatFileConst _)   = PatTypeNil
  typeOf (PatFileExt   _)   = PatTypeBaseName PatTypeNil
  typeOf (PatDirConst  _ p) = typeOf p
  typeOf (PatDirAny      p) = PatTypeDirectory (typeOf p)

instance AsType Replacement where
  asType = go
    where
      go :: Replacement typ -> PatternType typ' -> Maybe (Replacement typ')
      go (RepFileConst c)   _                     = return $ RepFileConst c
      go (RepFileExt   e)   (PatTypeBaseName _)   = return $ RepFileExt e
      go (RepFileExt   _)   _                     = Nothing
      go (RepDirConst  c p) tp                    = RepDirConst c <$> go p tp
      go (RepDirAny      p) (PatTypeDirectory tp) = RepDirAny     <$> go p tp
      go (RepDirAny      _) _                     = Nothing

{-------------------------------------------------------------------------------
  Pretty-printing and parsing patterns and replacements
-------------------------------------------------------------------------------}

prettyPattern :: Pattern typ -> String
prettyPattern (PatFileConst f)   = f
prettyPattern (PatFileExt   e)   = "*" <.> e
prettyPattern (PatDirConst  d p) = d   </> prettyPattern p
prettyPattern (PatDirAny      p) = "*" </> prettyPattern p

prettyReplacement :: Replacement typ -> String
prettyReplacement (RepFileConst f)   = f
prettyReplacement (RepFileExt   e)   = "*" <.> e
prettyReplacement (RepDirConst  d p) = d   </> prettyReplacement p
prettyReplacement (RepDirAny      p) = "*" </> prettyReplacement p

parsePattern :: String -> Except String (Some Pattern)
parsePattern = go . splitDirectories
  where
    go :: [String] -> Except String (Some Pattern)
    go [] =
      throwError "Empty pattern"
    go [p] =
      if '*' `notElem` p
        then return . Some $ PatFileConst p
        else case splitExtension p of
               ("*", _:ext) -> return . Some $ PatFileExt ext
               _otherwise   -> throwError "Invalid file pattern"
    go (p:ps) = do
      Some p' <- go ps
      if '*' `notElem` p
        then return . Some $ PatDirConst p p'
        else case p of
               "*"        -> return . Some $ PatDirAny p'
               _otherwise -> throwError "Invalid directory pattern"

parseReplacement :: String -> Except String (Some Replacement)
parseReplacement = go . splitDirectories
  where
    go :: [String] -> Except String (Some Replacement)
    go [] =
      throwError "Empty replacement"
    go [p] =
      if '*' `notElem` p
        then return . Some $ RepFileConst p
        else case splitExtension p of
               ("*", _:ext) -> return . Some $ RepFileExt ext
               _otherwise   -> throwError "Invalid file pattern"
    go (p:ps) = do
      Some p' <- go ps
      if '*' `notElem` p
        then return . Some $ RepDirConst p p'
        else case p of
               "*"        -> return . Some $ RepDirAny p'
               _otherwise -> throwError "Invalid directory pattern"

parseDelegation :: String -> String -> Either String Delegation
parseDelegation = \pat repl -> runExcept $ go pat repl
  where
    go :: String -> String -> Except String Delegation
    go pat repl = do
      Some pat'  <- parsePattern pat
      Some repl' <- parseReplacement repl
      case repl' `asType` typeOf pat' of
        Just repl'' -> return $ Delegation pat' repl''
        Nothing     -> throwError "Replacement does not match pattern type"

{-------------------------------------------------------------------------------
  JSON
-------------------------------------------------------------------------------}

instance ToJSON (Pattern typ) where
  toJSON = JSString . prettyPattern
instance ToJSON (Replacement typ) where
  toJSON = JSString . prettyReplacement

instance ToJSON DelegationSpec where
  toJSON DelegationSpec{delegation = Delegation path name, ..} = JSObject [
        ("name"      , toJSON name)
      , ("keyids"    , JSArray $ map writeKeyAsId delegationSpecKeys)
      , ("threshold" , toJSON delegationSpecThreshold)
      , ("path"      , toJSON path)
      ]

instance FromJSON ReadJSON DelegationSpec where
  fromJSON enc = do
    delegationName          <- fromJSField enc "name"
    delegationSpecKeys      <- mapM readKeyAsId =<< fromJSField enc "keyids"
    delegationSpecThreshold <- fromJSField enc "threshold"
    delegationPath          <- fromJSField enc "path"
    case parseDelegation delegationName delegationPath of
      Left  err        -> expected $ "valid name/path combination: " ++ err
      Right delegation -> return DelegationSpec{..}

-- NOTE: Unlike the Root object, the keys that are used to sign the delegations
-- are NOT listed inside the delegations, so the same "bootstrapping" problems
-- do not arise here.
instance ToJSON Delegations where
  toJSON Delegations{..} = JSObject [
        ("keys"  , toJSON delegationsKeys)
      , ("roles" , toJSON delegationsRoles)
      ]

instance FromJSON ReadJSON Delegations where
  fromJSON enc = do
    delegationsKeys  <- fromJSField enc "keys"
    delegationsRoles <- fromJSField enc "roles"
    return Delegations{..}

instance ToJSON Targets where
  toJSON Targets{..} = JSObject [
        ("_type"       , JSString "Targets")
      , ("version"     , toJSON targetsVersion)
      , ("expires"     , toJSON targetsExpires)
      , ("targets"     , toJSON targets)
      , ("delegations" , toJSON targetsDelegations)
      ]

instance FromJSON ReadJSON Targets where
  fromJSON enc = do
    -- TODO: verify _type
    targetsVersion     <- fromJSField enc "version"
    targetsExpires     <- fromJSField enc "expires"
    targets            <- fromJSField enc "targets"
    targetsDelegations <- fromJSField enc "delegations"
    return Targets{..}

{-------------------------------------------------------------------------------
  Debugging: examples
-------------------------------------------------------------------------------}

_ex1 :: Maybe String
_ex1 = matchDelegation del "A/x/y/z.foo"
  where
    del = Delegation
            ( PatDirConst "A"
            $ PatDirAny
            $ PatDirAny
            $ PatFileExt "foo"
            )
            ( RepDirConst "B"
            $ RepDirAny
            $ RepDirConst "C"
            $ RepDirAny
            $ RepFileExt "bar"
            )

_ex2 :: Maybe String
_ex2 = matchDelegation del "A/x/y/z.foo"
  where
    Right del = parseDelegation "A/*/*/*.foo" "B/*/C/*/*.bar"

_ex3 :: Either String Delegation
_ex3 = parseDelegation "foo" "*/bar"
