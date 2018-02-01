module OpenIDConnect
    exposing
        ( ParseErr(..)
        , Token
        , authorize
        , parse
        , parseWithNonce
        , parseToken
        , newAuth
        , tokenData
        , tokenRaw
        , showToken
        , use
        , withParam
        , withScope
        , withState
        , withNonce
        )

{-| An OpenID Connect implementation


## Token

@docs Token, tokenRaw, tokenData, parseToken, showToken


## Responses

@docs ParseErr, parse, parseWithNonce


## Requests

@docs authorize, newAuth, withScope, withState, withNonce


## Use

@docs use

-}

import Base64
import Json.Decode as JsonD
import QueryString as QS
import Navigation
import Http


{-| Error returned by parsing functions
-}
type ParseErr
    = NoToken
    | Error String
    | OAuthErr Err


type ErrCode
    = InvalidRequest
    | UnauthorizedClient
    | AccessDenied
    | UnsupportedResponseType
    | InvalidScope
    | ServerError
    | TemporarilyUnavailable
    | Unknown


type alias Err =
    { error : ErrCode
    , errorDescription : Maybe String
    , errorUri : Maybe String
    , state : Maybe String
    }


type alias Authorization =
    { url : String
    , redirectUri : String
    , clientID : String
    , scope : List String
    , state : Maybe String
    , nonce : Maybe String
    , params : List ( String, String )
    }


{-| Token holder
-}
type Token data
    = Token String data


{-| Use a token to authenticate a request.
-}
use : Token data -> List Http.Header -> List Http.Header
use token =
    (::) (Http.header "Authorization" (showToken token))


{-| Returns the token as a string
-}
showToken : Token data -> String
showToken token =
    "Bearer " ++ (tokenRaw token)


{-| Returns the data of a Token
-}
tokenData : Token data -> data
tokenData token =
    case token of
        Token token data ->
            data


{-| Returns the raw encoded token as a string
-}
tokenRaw : Token data -> String
tokenRaw token =
    case token of
        Token token _ ->
            token


{-| Map token contents
-}
mapToken : (a -> b) -> Token a -> Token b
mapToken f token =
    case token of
        Token token data ->
            Token token (f data)


{-| Creates a Authorization
-}
newAuth : String -> String -> String -> Authorization
newAuth url redirectUri clientId =
    Authorization url redirectUri clientId [ "openid" ] Nothing Nothing []


{-| Add a custom scope to a Authorization
-}
withScope : List String -> Authorization -> Authorization
withScope scope auth =
    { auth | scope = List.append auth.scope scope }


{-| Add a custom state to a Authorization
-}
withState : String -> Authorization -> Authorization
withState state auth =
    { auth | state = Just state }


{-| Add a nonce to a Authorization (required)

If omitted, the authorize function will work but the openid-connect
protocol will not be respected.
See <http://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthRequest>

-}
withNonce : String -> Authorization -> Authorization
withNonce nonce auth =
    { auth | nonce = Just nonce }


{-| Add additional querystring parameters to the authorize url
-}
withParam : String -> String -> Authorization -> Authorization
withParam key value auth =
    { auth | params = ( key, value ) :: auth.params }


{-| Build a Cmd that will redirect to the identity provider

Make sure to use withNonce

-}
authorize : Authorization -> Cmd msg
authorize { url, redirectUri, clientID, scope, state, nonce, params } =
    let
        qs =
            QS.empty
                |> QS.add "client_id" clientID
                |> QS.add "redirect_uri" redirectUri
                |> QS.add "response_type" "id_token"
                |> qsAddList "scope" scope
                |> qsAddMaybe "state" state
                |> qsAddMaybe "nonce" nonce
                |> qsAddAll params
                |> QS.render
    in
        Navigation.load (url ++ qs)


qsAddList : String -> List String -> QS.QueryString -> QS.QueryString
qsAddList param xs qs =
    case xs of
        [] ->
            qs

        _ ->
            QS.add param (String.join " " xs) qs


qsAddMaybe : String -> Maybe String -> QS.QueryString -> QS.QueryString
qsAddMaybe param ms qs =
    case ms of
        Nothing ->
            qs

        Just s ->
            QS.add param s qs


qsAddAll : List ( String, String ) -> QS.QueryString -> QS.QueryString
qsAddAll params qs =
    let
        append t =
            QS.add (Tuple.first t) (Tuple.second t)
    in
        List.foldl append qs params


parseWithMaybeNonce : Maybe String -> JsonD.Decoder data -> Navigation.Location -> Result ParseErr (Token data)
parseWithMaybeNonce nonce decode { hash } =
    let
        qs =
            QS.parse ("?" ++ String.dropLeft 1 hash)

        gets =
            flip (QS.one QS.string) qs

        geti =
            flip (QS.one QS.int) qs
    in
        case ( gets "id_token", gets "error", nonce ) of
            ( Just token, _, Just nonce ) ->
                let
                    parseResult =
                        parseToken (JsonD.map2 (,) (JsonD.field "nonce" JsonD.string) decode) token

                    validateNonce tokenWithNonce =
                        if Tuple.first (tokenData tokenWithNonce) == nonce then
                            Result.Ok <| mapToken Tuple.second tokenWithNonce
                        else
                            Result.Err <| Error "Invalid nonce"
                in
                    parseResult |> Result.andThen validateNonce

            ( Just token, _, Nothing ) ->
                parseToken decode token

            ( _, Just error, _ ) ->
                parseError
                    error
                    (gets "error_description")
                    (gets "error_uri")
                    (gets "state")

            _ ->
                Result.Err NoToken


{-| Extracts a Token from a location and check the incoming nonce
-}
parseWithNonce : String -> JsonD.Decoder data -> Navigation.Location -> Result ParseErr (Token data)
parseWithNonce nonce =
    parseWithMaybeNonce (Just nonce)


{-| Extracts a Token from a location
-}
parse : JsonD.Decoder data -> Navigation.Location -> Result ParseErr (Token data)
parse =
    parseWithMaybeNonce Nothing


{-| Parse a token
-}
parseToken : JsonD.Decoder data -> String -> Result ParseErr (Token data)
parseToken decode token =
    case String.split "." token of
        [ part0, part1, sign ] ->
            case base64Decode part1 of
                Ok payload ->
                    case JsonD.decodeString decode payload of
                        Ok result ->
                            Ok <| Token token result

                        Err err ->
                            Result.Err <| Error err

                Err err ->
                    Result.Err <| Error ("base64 decode: " ++ err)

        _ ->
            Result.Err <| Error "Invalid id_token"


base64Decode : String -> Result String String
base64Decode data =
    case Base64.decode data of
        Ok result ->
            if String.endsWith "\x00" result then
                Ok <| String.dropRight 1 result
            else
                Ok result

        Err err ->
            Result.Err err


parseError : String -> Maybe String -> Maybe String -> Maybe String -> Result ParseErr a
parseError error errorDescription errorUri state =
    Result.Err <|
        OAuthErr
            { error = errCodeFromString error
            , errorDescription = errorDescription
            , errorUri = errorUri
            , state = state
            }


errCodeFromString : String -> ErrCode
errCodeFromString str =
    case str of
        "invalid_request" ->
            InvalidRequest

        "unauthorized_client" ->
            UnauthorizedClient

        "access_denied" ->
            AccessDenied

        "unsupported_response_type" ->
            UnsupportedResponseType

        "invalid_scope" ->
            InvalidScope

        "server_error" ->
            ServerError

        "temporarily_unavailable" ->
            TemporarilyUnavailable

        _ ->
            Unknown
