module Hackage.Security.TUF.Targets (
    Targets(..)
  , DelegationSpec(..)
  , Delegation(..)
  , PathPattern(..)
    -- * Utility
  , match
  ) where

import Control.Monad.Except
import Data.Time
import Data.List (elemIndices)
import System.FilePath

import Hackage.Security.TUF.Ints
import Hackage.Security.TUF.FileMap (FileMap)
import Hackage.Security.Key

data Targets = Targets {
    targetsVersion    :: Version
  , targetsExpires    :: UTCTime
  , targets           :: FileMap
  , targetDelegations :: [DelegationSpec]
  }

-- | Delegation specification
--
-- NOTE: This is a close analogue of 'RoleSpec'.
data DelegationSpec = DelegationSpec {
    delegationSpecKeys      :: [Some PublicKey]
  , delegationSpecThreshold :: KeyThreshold
  , delegations             :: Delegation
  }

-- | A delegation
--
-- See 'match' for an example.
data Delegation = forall a. Delegation (PathPattern a) a

{-------------------------------------------------------------------------------
  Path patterns
-------------------------------------------------------------------------------}

type Directory = String
type Extension = String
type BaseName  = String

data PathPattern a where
    -- | Match against a specific filename
    PathPatternFileConst :: String -> PathPattern String

    -- | Match against a filename with the given extension
    PathPatternFileExt :: Extension -> PathPattern (BaseName -> String)

    -- | Match against a specific directory
    PathPatternDirConst :: String -> PathPattern a -> PathPattern a

    -- | Match against any directory
    PathPatternDirAny :: PathPattern a -> PathPattern (Directory -> a)

renderPathPattern :: PathPattern a -> String
renderPathPattern (PathPatternFileConst f)   = f
renderPathPattern (PathPatternFileExt   e)   = "*" <.> e
renderPathPattern (PathPatternDirConst  d p) = d   </> renderPathPattern p
renderPathPattern (PathPatternDirAny      p) = "*" </> renderPathPattern p

-- | Match a path pattern against a path
--
-- For example, given a pattern and replacement given by
--
-- > case parseDelegation "targets/*/*/*.cabal" "(*, *, *)" of
-- >   Delegation patt repl -> ...
--
-- we get that
--
-- > match "targets/Foo/1.0/Foo-1.0.cabal" patt repl
--
-- evaluates to
--
-- > Just "(Foo, 1.0, Foo-1.0)"
match :: String -> PathPattern a -> a -> Maybe String
match = go . splitDirectories
  where
    go :: [String] -> PathPattern a -> a -> Maybe String
    go [f] (PathPatternFileConst f') r = do
      guard (f == f')
      return r
    go [f] (PathPatternFileExt e') r = do
      let (bn, _:e) = splitExtension f
      guard (e == e')
      return $ r bn
    go (d:p) (PathPatternDirConst d' p') r = do
      guard (d == d')
      go p p' r
    go (d:p) (PathPatternDirAny p') r =
      go p p' $ r d
    go _ _ _ =
      Nothing

{-------------------------------------------------------------------------------
  Parsing patterns
-------------------------------------------------------------------------------}

data SomePattern = forall a. SomePattern (PathPattern a)

parsePattern :: String -> Except String SomePattern
parsePattern = go . splitDirectories
  where
    go :: [String] -> Except String SomePattern
    go [] =
      throwError "Empty pattern"
    go [p] =
      if '*' `notElem` p
        then return . SomePattern $ PathPatternFileConst p
        else case splitExtension p of
               ("*", _:ext) ->
                 return . SomePattern $ PathPatternFileExt ext
               _otherwise ->
                 throwError "Invalid file pattern"
    go (p:ps) = do
      SomePattern p' <- go ps
      if '*' `notElem` p
        then return . SomePattern $ PathPatternDirConst p p'
        else case p of
               "*" ->
                 return . SomePattern $ PathPatternDirAny p'
               _otherwise ->
                 throwError "Invalid directory pattern"

parseReplacement :: String -> SomePattern -> Except String Delegation
parseReplacement repl' (SomePattern p) = do
    f <- go 0 p
    return $ Delegation p (f repl')
  where
    go :: Int -> PathPattern a -> Except String (String -> a)
    go numWildcards (PathPatternFileConst _) = do
      checkWildcards numWildcards repl'
      return $ \repl -> repl
    go numWildcards (PathPatternFileExt _) = do
      checkWildcards (numWildcards + 1) repl'
      return $ \repl bn -> replaceWildcard bn repl
    go numWildcards (PathPatternDirConst _ p') = do
      go numWildcards p'
    go numWildcards (PathPatternDirAny p') = do
      f <- go (numWildcards + 1) p'
      return $ \repl dir -> f (replaceWildcard dir repl)

    replaceWildcard :: String -> String -> String
    replaceWildcard repl str =
      case break (== '*') str of
        (before, _:after) -> before ++ repl ++ after
        _otherwise        -> str

    checkWildcards :: Int -> String -> Except String ()
    checkWildcards numWildcards repl =
      unless (count '*' repl <= numWildcards) $
        throwError $ "Too many wildcards in replacement "
                  ++ show repl'
                  ++ " for pattern "
                  ++ show (renderPathPattern p)

    count :: Eq a => a -> [a] -> Int
    count x = length . elemIndices x

parseDelegation :: String -> String -> Either String Delegation
parseDelegation patt repl = runExcept $
    parseReplacement repl =<< parsePattern patt

{-------------------------------------------------------------------------------
  Examples
-------------------------------------------------------------------------------}

_ex1 :: Maybe String
_ex1 = match "targets/Foo/1.0/Foo-1.0.cabal"
             (PathPatternDirConst "targets" $
              PathPatternDirAny $
              PathPatternDirAny $
              PathPatternFileExt "cabal")
             (\pkg version name -> show (pkg, version, name))

_ex2 :: Maybe String
_ex2 =
   case parseDelegation "targets/*/*/*.cabal" "(*, *, *)" of
     Right (Delegation patt repl) ->
       match "targets/Foo/1.0/Foo-1.0.cabal" patt repl
     Left err ->
       error err
