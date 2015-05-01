--------------------------------------------------------------------
-- |
-- Module    : Text.JSON.Parsec
-- Copyright : (c) Galois, Inc. 2007-2009, Duncan Coutts 2015
--
--
-- Minimal implementation of Canonical JSON.
--
-- <http://wiki.laptop.org/go/Canonical_JSON>
--
-- A "canonical JSON" format is provided in order to provide meaningful and
-- repeatable hashes of JSON-encoded data. Canonical JSON is parsable with any
-- full JSON parser, but security-conscious applications will want to verify
-- that input is in canonical form before authenticating any hash or signature
-- on that input.
--
-- This implementation is derived from the json parser from the json package,
-- with simplifications to meet the Canonical JSON grammar.
--

module Text.JSON.Canonical
  ( JSValue(..)
  , parseCanonicalJSON
  , renderCanonicalJSON
  ) where

import Text.ParserCombinators.Parsec
         ( CharParser, (<|>), (<?>), many, between, sepBy
         , satisfy, char, string, digit, spaces
         , parse )
import Data.Char (isDigit, digitToInt)
import Data.List (foldl', sortBy)
import Data.Function (on)
import qualified Data.ByteString.Lazy.Char8 as BS


data JSValue
    = JSNull
    | JSBool     !Bool
    | JSNum      !Int
    | JSString   String
    | JSArray    [JSValue]
    | JSObject   [(String, JSValue)]
    deriving (Show, Read, Eq, Ord)

------------------------------------------------------------------------------

renderCanonicalJSON :: JSValue -> BS.ByteString
renderCanonicalJSON v = BS.pack (s_value v [])

s_value :: JSValue -> ShowS
s_value JSNull         = showString "null"
s_value (JSBool False) = showString "false"
s_value (JSBool True)  = showString "true"
s_value (JSNum n)      = shows n
s_value (JSString s)   = s_string s
s_value (JSArray vs)   = s_array  vs
s_value (JSObject fs)  = s_object (sortBy (compare `on` fst) fs)

s_string :: String -> ShowS
s_string s = showChar '"' . showl s
  where showl []     = showChar '"'
        showl (c:cs) = s_char c . showl cs

        s_char '"'   = showChar '\\' . showChar '"'
        s_char '\\'  = showChar '\\' . showChar '\\'
        s_char c     = showChar c

s_array :: [JSValue] -> ShowS
s_array []           = showString "[]"
s_array (v0:vs0)     = showChar '[' . s_value v0 . showl vs0
  where showl []     = showChar ']'
        showl (v:vs) = showChar ',' . s_value v . showl vs

s_object :: [(String, JSValue)] -> ShowS
s_object []               = showString "{}"
s_object ((k0,v0):kvs0)   = showChar '{' . s_string k0
                          . showChar ':' . s_value v0
                          . showl kvs0
  where showl []          = showChar '}'
        showl ((k,v):kvs) = showChar ',' . s_string k
                          . showChar ':' . s_value v
                          . showl kvs

------------------------------------------------------------------------------

parseCanonicalJSON :: BS.ByteString -> Either String JSValue
parseCanonicalJSON = either (Left . show) Right
                   . parse p_value ""
                   . BS.unpack

p_value :: CharParser () JSValue
p_value = spaces *> p_jvalue

tok              :: CharParser () a -> CharParser () a
tok p             = p <* spaces

{-
value:
   string
   number
   object
   array
   true
   false
   null
-}
p_jvalue         :: CharParser () JSValue
p_jvalue          =  (JSNull      <$  p_null)
                 <|> (JSBool      <$> p_boolean)
                 <|> (JSArray     <$> p_array)
                 <|> (JSString    <$> p_string)
                 <|> (JSObject    <$> p_object)
                 <|> (JSNum       <$> p_number)
                 <?> "JSON value"

p_null           :: CharParser () ()
p_null            = tok (string "null") >> return ()

p_boolean        :: CharParser () Bool
p_boolean         = tok
                      (  (True  <$ string "true")
                     <|> (False <$ string "false")
                      )
{-
array:
   []
   [ elements ]
elements:
   value
   value , elements
-}
p_array          :: CharParser () [JSValue]
p_array           = between (tok (char '[')) (tok (char ']'))
                  $ p_jvalue `sepBy` tok (char ',')

{-
string:
   ""
   " chars "
chars:
   char
   char chars
char:
   any byte except hex 22 (") or hex 5C (\)
   \\
   \"
-}
p_string         :: CharParser () String
p_string          = between (tok (char '"')) (tok (char '"')) (many p_char)
  where p_char    =  (char '\\' >> p_esc)
                 <|> (satisfy (\x -> x /= '"' && x /= '\\'))

        p_esc     =  ('"'   <$ char '"')
                 <|> ('\\'  <$ char '\\')
                 <?> "escape character"
{-
object:
    {}
    { members }
members:
   pair
   pair , members
pair:
   string : value
-}
p_object         :: CharParser () [(String,JSValue)]
p_object          = between (tok (char '{')) (tok (char '}'))
                  $ p_field `sepBy` tok (char ',')
  where p_field   = (,) <$> (p_string <* tok (char ':')) <*> p_jvalue

{-
number:
   int
int:
   digit
   digit1-9 digits
   - digit1-9
   - digit1-9 digits
digits:
   digit
   digit digits
-}
p_number         :: CharParser () Int
p_number          = tok
                      (  (char '-' *> (negate <$> pnat))
                     <|> pnat
                     <|> zero
                      )
  where pnat      = (\d ds -> strToInt (d:ds)) <$> digit19 <*> manyN 8 digit
        digit19   = satisfy (\c -> isDigit c && c /= '0') <?> "digit"
        strToInt  = foldl' (\x d -> 10*x + digitToInt d) 0
        zero      = 0 <$ char '0'

manyN :: Int -> CharParser () a -> CharParser () [a]
manyN 0 _ =  pure []
manyN n p =  ((:) <$> p <*> manyN (n-1) p)
         <|> pure []
