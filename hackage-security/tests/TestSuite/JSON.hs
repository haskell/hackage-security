{-# OPTIONS_GHC -fno-warn-orphans #-}
module TestSuite.JSON (
    prop_roundtrip_canonical,
    prop_roundtrip_pretty,
    prop_canonical_pretty,
    prop_aeson_canonical,
  ) where

-- stdlib
import Data.Int
import Data.List (sortBy, nubBy)
import Data.Function (on)
import Control.Applicative
import qualified Data.ByteString.Lazy.Char8 as BS
import Test.QuickCheck

-- hackage-security
import Text.JSON.Canonical

-- aeson
import Data.Aeson (Value (..), eitherDecode)
import Data.String (fromString)
import qualified Data.Vector as V
import qualified Data.HashMap.Strict as HM

prop_aeson_canonical, prop_roundtrip_canonical, prop_roundtrip_pretty, prop_canonical_pretty
  :: JSValue -> Bool

prop_roundtrip_canonical jsval =
    parseCanonicalJSON (renderCanonicalJSON jsval) == Right (canonicalise jsval)

prop_roundtrip_pretty jsval =
    parseCanonicalJSON (BS.pack (prettyCanonicalJSON jsval)) == Right jsval

prop_canonical_pretty jsval =
    parseCanonicalJSON (renderCanonicalJSON jsval) ==
    fmap canonicalise (parseCanonicalJSON (BS.pack (prettyCanonicalJSON jsval)))

prop_aeson_canonical jsval =
    eitherDecode (renderCanonicalJSON jsval) == Right (toAeson (canonicalise jsval))

canonicalise :: JSValue -> JSValue
canonicalise v@JSNull        = v
canonicalise v@(JSBool    _) = v
canonicalise v@(JSNum     _) = v
canonicalise v@(JSString  _) = v
canonicalise   (JSArray  vs) = JSArray  [ canonicalise v | v <- vs]
canonicalise   (JSObject vs) = JSObject [ (k, canonicalise v)
                                        | (k,v) <- sortBy (compare `on` fst) vs ]

instance Arbitrary JSValue where
  arbitrary =
    sized $ \sz ->
    frequency
      [ (1, pure JSNull)
      , (1, JSBool   <$> arbitrary)
      , (2, JSNum    <$> arbitrary)
      , (2, JSString . getASCIIString <$> arbitrary)
      , (3, JSArray                <$> resize (sz `div` 2) arbitrary)
      , (3, JSObject . mapFirst getASCIIString .  noDupFields <$> resize (sz `div` 2) arbitrary)
      ]
    where
      noDupFields = nubBy (\(x,_) (y,_) -> x==y)
      mapFirst f = map (\(x, y) -> (f x, y))

  shrink JSNull        = []
  shrink (JSBool    _) = []
  shrink (JSNum     n) = [ JSNum    n' | n' <- shrink n ]
  shrink (JSString  s) = [ JSString s' | s' <- shrink s ]
  shrink (JSArray  vs) = [ JSArray vs' | vs' <- shrink vs ]
  shrink (JSObject vs) = [ JSObject vs' | vs' <- shrinkList shrinkSnd vs ]
    where
      shrinkSnd (a,b) = [ (a,b') | b' <- shrink b ]

toAeson :: JSValue -> Value
toAeson JSNull        = Null
toAeson (JSBool b)    = Bool b
toAeson (JSNum n)     = Number (fromIntegral n)
toAeson (JSString s)  = String (fromString s)
toAeson (JSArray xs)  = Array $ V.fromList [ toAeson x | x <- xs ]
toAeson (JSObject xs) = Object $ HM.fromList [ (fromString k, toAeson v) | (k, v) <- xs ]

instance Arbitrary Int54 where
  arbitrary = fromIntegral <$>
              frequency [ (1, pure lowerbound)
                        , (1, pure upperbound)
                        , (8, choose (lowerbound, upperbound))
                        ]
    where
      upperbound, lowerbound :: Int64
      upperbound =   999999999999999  -- 15 decimal digits
      lowerbound = (-999999999999999)
  shrink = shrinkIntegral

