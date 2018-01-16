module OpenIDConnect
    exposing
        ( ParseErr(..)
        , Token
        , authorize
        , parse
        , parseToken
        , newAuth
        , tokenData
        , showToken
        , use
        , withScope
        , withState
        )

{-| An OpenID Connect implementation


## Responses

@docs Token, ParseErr, parse


## Requests

@docs authorize, newAuth, withScope, withState


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
    case token of
        Token token data ->
            "Bearer " ++ token


{-| Returns the data of a Token
-}
tokenData : Token data -> data
tokenData token =
    case token of
        Token token data ->
            data


{-| Creates a Authorization
-}
newAuth : String -> String -> String -> Authorization
newAuth url redirectUri clientId =
    Authorization url redirectUri clientId [ "openid" ] Nothing


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


{-| Build a Cmd that will redirect to the identity provider
-}
authorize : Authorization -> Cmd msg
authorize { url, redirectUri, clientID, scope, state } =
    let
        qs =
            QS.empty
                |> QS.add "client_id" clientID
                |> QS.add "redirect_uri" redirectUri
                |> QS.add "response_type" "id_token"
                |> qsAddList "scope" scope
                |> qsAddMaybe "state" state
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


{-| Extracts a Token from a location
-}
parse : JsonD.Decoder data -> Navigation.Location -> Result ParseErr (Token data)
parse decode { hash } =
    let
        qs =
            QS.parse ("?" ++ String.dropLeft 1 hash)

        gets =
            flip (QS.one QS.string) qs

        geti =
            flip (QS.one QS.int) qs
    in
        case ( gets "id_token", gets "error" ) of
            ( Just token, _ ) ->
                parseToken decode token

            ( _, Just error ) ->
                parseError
                    error
                    (gets "error_description")
                    (gets "error_uri")
                    (gets "state")

            ( _, _ ) ->
                Result.Err NoToken


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
