-- | Patterns and replacements
--
-- NOTE: This module was developed to prepare for proper delegation (#39).
-- It is currently unusued.
{-# LANGUAGE CPP #-}
#if __GLASGOW_HASKELL__ >= 800
{-# LANGUAGE DeriveLift #-}
{-# LANGUAGE StandaloneDeriving #-}
#else
{-# LANGUAGE TemplateHaskell #-}
#endif
module Hackage.Security.TUF.Patterns (
    -- * Patterns and replacements
    FileName
  , Directory
  , Extension
  , BaseName
  , Pattern(..)
  , Replacement(..)
  , Delegation(..)
    -- ** Utility
  , identityReplacement
  , matchDelegation
    -- ** Parsing and quasi-quoting
  , parseDelegation
  , qqd
  ) where

import Control.Monad.Except
import Language.Haskell.TH (Q, Exp)
import System.FilePath.Posix
import qualified Language.Haskell.TH.Syntax as TH

import Hackage.Security.JSON
import Hackage.Security.Util.Some
import Hackage.Security.Util.Stack
import Hackage.Security.Util.TypedEmbedded

{-------------------------------------------------------------------------------
  Patterns and replacements
-------------------------------------------------------------------------------}

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
--
-- TODOs (see README.md):
--
-- * Update this to work with 'Path' rather than 'FilePath'/'String'
-- * Add different kinds of wildcards
-- * Add path roots
--
-- Currently this is a proof of concept more than anything else; the right
-- structure is here, but it needs updating. However, until we add author
-- signing (or out-of-tarball targets) we don't actually use this yet.
--
-- NOTE: Haddock lacks GADT support so constructors have only regular comments.
data Pattern a where
    -- Match against a specific filename
    PatFileConst :: FileName -> Pattern ()

    -- Match against a filename with the given extension
    PatFileExt :: Extension -> Pattern (BaseName :- ())

    -- Match against any filename
    PatFileAny :: Pattern (FileName :- ())

    -- Match against a specific directory
    PatDirConst :: Directory -> Pattern a -> Pattern a

    -- Match against any directory
    PatDirAny :: Pattern a -> Pattern (Directory :- a)

-- | Replacement patterns
--
-- These constructors match the ones in 'Pattern': wildcards must be used
-- in the same order as they appear in the pattern, but they don't all have to
-- be used (that's why the base constructors are polymorphic in the stack tail).
data Replacement a where
    RepFileConst :: FileName -> Replacement a
    RepFileExt   :: Extension -> Replacement (BaseName :- a)
    RepFileAny   :: Replacement (FileName :- a)
    RepDirConst  :: Directory -> Replacement a -> Replacement a
    RepDirAny    :: Replacement a -> Replacement (Directory :- a)

deriving instance Eq   (Pattern typ)
deriving instance Show (Pattern typ)

deriving instance Eq   (Replacement typ)
deriving instance Show (Replacement typ)

-- | The identity replacement replaces a matched pattern with itself
identityReplacement :: Pattern typ -> Replacement typ
identityReplacement = go
  where
    go :: Pattern typ -> Replacement typ
    go (PatFileConst fn)  = RepFileConst fn
    go (PatFileExt   e)   = RepFileExt   e
    go PatFileAny         = RepFileAny
    go (PatDirConst  d p) = RepDirConst  d (go p)
    go (PatDirAny      p) = RepDirAny      (go p)

-- | A delegation
--
-- A delegation is a pair of a pattern and a replacement.
--
-- See 'match' for an example.
data Delegation = forall a. Delegation (Pattern a) (Replacement a)

deriving instance Show Delegation

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
    go RepFileAny         (fn :- _) = [fn]
    go (RepDirConst  d p) a         = d : go p a
    go (RepDirAny      p) (d  :- a) = d : go p a

matchDelegation :: Delegation -> String -> Maybe String
matchDelegation (Delegation pat repl) str =
    constructReplacement repl <$> matchPattern str pat

{-------------------------------------------------------------------------------
  Typechecking patterns and replacements
-------------------------------------------------------------------------------}

-- | Types for pattern and replacements
--
-- We intentially are not very precise here, saying @String@ (instead of
-- @FileName@, @BaseName@, or @Directory@, say) so that we can, for example,
-- use a matched filename in a pattern as a directory in a replacement.
data PatternType a where
  PatTypeNil :: PatternType ()
  PatTypeStr :: PatternType a -> PatternType (String :- a)

instance Unify PatternType where
  unify PatTypeNil     PatTypeNil       = Just Refl
  unify (PatTypeStr p) (PatTypeStr  p') = case unify p p' of
                                            Just Refl -> Just Refl
                                            Nothing   -> Nothing
  unify _              _                = Nothing

type instance TypeOf Pattern     = PatternType
type instance TypeOf Replacement = PatternType

instance Typed Pattern where
  typeOf (PatFileConst _)   = PatTypeNil
  typeOf (PatFileExt   _)   = PatTypeStr PatTypeNil
  typeOf (PatFileAny    )   = PatTypeStr PatTypeNil
  typeOf (PatDirConst  _ p) = typeOf p
  typeOf (PatDirAny      p) = PatTypeStr (typeOf p)

instance AsType Replacement where
  asType = go
    where
      go :: Replacement typ -> PatternType typ' -> Maybe (Replacement typ')
      go (RepFileConst c)   _                = return $ RepFileConst c
      go (RepFileExt   _)   PatTypeNil       = Nothing
      go (RepFileExt   e)   (PatTypeStr _)   = return $ RepFileExt e
      go RepFileAny         PatTypeNil       = Nothing
      go RepFileAny         (PatTypeStr _)   = return $ RepFileAny
      go (RepDirConst  c p) tp               = RepDirConst c <$> go p tp
      go (RepDirAny      _) PatTypeNil       = Nothing
      go (RepDirAny      p) (PatTypeStr tp)  = RepDirAny     <$> go p tp

{-------------------------------------------------------------------------------
  Pretty-printing and parsing patterns and replacements
-------------------------------------------------------------------------------}

prettyPattern :: Pattern typ -> String
prettyPattern (PatFileConst f)   = f
prettyPattern (PatFileExt   e)   = "*" <.> e
prettyPattern PatFileAny         = "*"
prettyPattern (PatDirConst  d p) = d   </> prettyPattern p
prettyPattern (PatDirAny      p) = "*" </> prettyPattern p

prettyReplacement :: Replacement typ -> String
prettyReplacement (RepFileConst f)   = f
prettyReplacement (RepFileExt   e)   = "*" <.> e
prettyReplacement RepFileAny         = "*"
prettyReplacement (RepDirConst  d p) = d   </> prettyReplacement p
prettyReplacement (RepDirAny      p) = "*" </> prettyReplacement p

-- | Parse a pattern
parsePattern :: String -> Maybe (Some Pattern)
parsePattern = go . splitDirectories
  where
    go :: [String] -> Maybe (Some Pattern)
    go []     = Nothing
    go ["*"]  = return . Some $ PatFileAny
    go [p]    = if '*' `notElem` p
                  then return . Some $ PatFileConst p
                  else case splitExtension p of
                         ("*", _:ext) -> return . Some $ PatFileExt ext
                         _otherwise   -> Nothing
    go (p:ps) = do Some p' <- go ps
                   if '*' `notElem` p
                     then return . Some $ PatDirConst p p'
                     else case p of
                            "*"        -> return . Some $ PatDirAny p'
                            _otherwise -> Nothing

-- | Parse a replacement
--
-- We cheat and use the parser for patterns and then translate using the
-- identity replacement.
parseReplacement :: String -> Maybe (Some Replacement)
parseReplacement = fmap aux . parsePattern
  where
    aux :: Some Pattern -> Some Replacement
    aux (Some pat) = Some (identityReplacement pat)

parseDelegation :: String -> String -> Either String Delegation
parseDelegation pat repl =
    case (parsePattern pat, parseReplacement repl) of
      (Just (Some pat'), Just (Some repl')) ->
        case repl' `asType` typeOf pat' of
          Just repl'' -> Right $ Delegation pat' repl''
          Nothing     -> Left "Replacement does not match pattern type"
      _otherwise ->
        Left "Cannot parse delegation"

{-------------------------------------------------------------------------------
  Quasi-quotation

  We cannot (easily) use dataToExpQ because of the use of GADTs, so we manually
  give Lift instances.
-------------------------------------------------------------------------------}

-- | Quasi-quoter for delegations to make them easier to write in code
--
-- This allows to write delegations as
--
-- > $(qqd "targets/*/*/*.cabal" "targets/*/*/revisions.json")
--
-- (The alternative syntax which actually uses a quasi-quoter doesn't work very
-- well because the '/*' bits confuse CPP: "unterminated comment")
qqd :: String -> String -> Q Exp
qqd pat repl  =
    case parseDelegation pat repl of
      Left  err -> fail $ "Invalid delegation: " ++ err
      Right del -> TH.lift del

#if __GLASGOW_HASKELL__ >= 800
deriving instance TH.Lift (Pattern a)
deriving instance TH.Lift (Replacement a)
deriving instance TH.Lift Delegation
#else
instance TH.Lift (Pattern a) where
  lift (PatFileConst fn)  = [| PatFileConst fn  |]
  lift (PatFileExt   e)   = [| PatFileExt   e   |]
  lift PatFileAny         = [| PatFileAny       |]
  lift (PatDirConst  d p) = [| PatDirConst  d p |]
  lift (PatDirAny      p) = [| PatDirAny      p |]

instance TH.Lift (Replacement a) where
  lift (RepFileConst fn)  = [| RepFileConst fn  |]
  lift (RepFileExt   e )  = [| RepFileExt   e   |]
  lift RepFileAny         = [| RepFileAny       |]
  lift (RepDirConst  d r) = [| RepDirConst  d r |]
  lift (RepDirAny      r) = [| RepDirAny      r |]

instance TH.Lift Delegation where
  lift (Delegation pat repl) = [| Delegation pat repl |]
#endif

{-------------------------------------------------------------------------------
  JSON
-------------------------------------------------------------------------------}

instance Monad m => ToJSON m (Pattern typ) where
  toJSON = return . JSString . prettyPattern
instance Monad m => ToJSON m (Replacement typ) where
  toJSON = return . JSString . prettyReplacement

instance Monad m => ToJSON m (Some Pattern) where
  toJSON (Some p) = toJSON p
instance Monad m => ToJSON m (Some Replacement) where
  toJSON (Some r) = toJSON r

instance ReportSchemaErrors m => FromJSON m (Some Pattern) where
  fromJSON enc = do
    str <- fromJSON enc
    case parsePattern str of
      Nothing -> expected "valid pattern" (Just str)
      Just p  -> return p

instance ReportSchemaErrors m => FromJSON m (Some Replacement) where
  fromJSON enc = do
    str <- fromJSON enc
    case parseReplacement str of
      Nothing -> expected "valid replacement" (Just str)
      Just r  -> return r

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
