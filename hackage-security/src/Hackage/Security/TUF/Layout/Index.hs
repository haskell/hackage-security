module Hackage.Security.TUF.Layout.Index (
    -- * Repository layout
    IndexLayout(..)
  , IndexFile(..)
  , hackageIndexLayout
  ) where

import qualified System.FilePath as FP

import Distribution.Package
import Distribution.Text

import Hackage.Security.TUF.Paths
import Hackage.Security.Util.Path
import Hackage.Security.Util.Pretty

{-------------------------------------------------------------------------------
  Index layout
-------------------------------------------------------------------------------}

-- | Layout of the files within the index tarball
data IndexLayout = IndexLayout  {
      -- | Translate an 'IndexFile' to a path
      indexFileToPath :: IndexFile -> IndexPath

      -- | Parse an 'FilePath'
    , indexFileFromPath :: IndexPath -> Maybe IndexFile
    }

-- | Files that we might request from the index
--
-- TODO: If we wanted to support legacy Hackage, we should also have a case for
-- the global preferred-versions file. But supporting legacy Hackage will
-- probably require more work anyway..
data IndexFile =
    -- | Package-specific metadata (@targets.json@)
    IndexPkgMetadata PackageIdentifier

    -- | Cabal file for a package
  | IndexPkgCabal PackageIdentifier

    -- | Preferred versions a package
  | IndexPkgPrefs PackageName
  deriving Show

instance Pretty IndexFile where
  pretty (IndexPkgMetadata pkgId) = "metadata for " ++ display pkgId
  pretty (IndexPkgCabal    pkgId) = ".cabal for " ++ display pkgId
  pretty (IndexPkgPrefs    pkgNm) = "preferred-versions for " ++ display pkgNm

-- | The layout of the index as maintained on Hackage
hackageIndexLayout :: IndexLayout
hackageIndexLayout = IndexLayout {
      indexFileToPath   = toPath
    , indexFileFromPath = fromPath . toUnrootedFilePath . unrootPath
    }
  where
    toPath :: IndexFile -> IndexPath
    toPath (IndexPkgCabal    pkgId) = fromFragments [
                                          display (packageName    pkgId)
                                        , display (packageVersion pkgId)
                                        , display (packageName pkgId) ++ ".cabal"
                                        ]
    toPath (IndexPkgMetadata pkgId) = fromFragments [
                                          display (packageName    pkgId)
                                        , display (packageVersion pkgId)
                                        , "package.json"
                                        ]
    toPath (IndexPkgPrefs    pkgNm) = fromFragments [
                                          display pkgNm
                                        , "preferred-versions"
                                        ]

    fromFragments :: [String] -> IndexPath
    fromFragments = rootPath . joinFragments

    fromPath :: FilePath -> Maybe IndexFile
    fromPath fp = case FP.splitPath fp of
      [pkg, version, file] -> do
        pkgId <- simpleParse (init pkg ++ "-" ++ init version)
        case FP.takeExtension file of
          ".cabal"   -> return $ IndexPkgCabal    pkgId
          ".json"    -> return $ IndexPkgMetadata pkgId
          _otherwise -> Nothing
      [pkg, "preferred-versions"] ->
        IndexPkgPrefs <$> simpleParse (init pkg)
      _otherwise -> Nothing
