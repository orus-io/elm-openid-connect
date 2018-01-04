module OpenIDConnect.Decode exposing (..)

{-| Provide decoders for the most common JWT attributes

@docs expDecoder, subDecoder

-}

import Json.Decode as Json


{-| Decode the 'exp' attribute
-}
expDecoder : Json.Decoder Int
expDecoder =
    Json.field "exp" Json.int


{-| Decode the 'sub' attribute
-}
subDecoder : Json.Decoder String
subDecoder =
    Json.field "sub" Json.string
