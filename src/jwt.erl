%% @doc JWT Library for Erlang.
%%
%% Written by Peter Hizalev at Kato (http://kato.im)
%%
%% Rewritten by Yuri Artemev (http://artemff.com)
%%
%% @end
-module(jwt).

-export([decode/2, decode/3]).
-export([encode/3, encode/4]).

-define(HOUR, 3600).
-define(DAY, (?HOUR * 24)).

%% Handle version compatibility for crypto
-ifdef(OTP_RELEASE).
  -if(?OTP_RELEASE >= 23).
    -define(HMAC(Type, Key, Data), crypto:mac(hmac, Type, Key, Data)).
  -else.
    -define(HMAC(Type, Key, Data), crypto:hmac(Type, Key, Data)).
  -endif.
-else.
  -define(HMAC(Type, Key, Data), crypto:hmac(Type, Key, Data)).
-endif.

-type expiration() :: {hourly, non_neg_integer()} | {daily, non_neg_integer()} | non_neg_integer().
-type context() :: map().

-type key() :: binary() | public_key:private_key().
-type key_id() :: binary().

%%
%% API
%%
-spec encode(
    Alg :: binary(),
    ClaimsSet :: map() | list(),
    Key :: key() | {key_id() | key()}
) -> {ok, Token :: binary()} | {error, any()}.
%% @doc Creates a token from given data and signs it with a given secret
%%
%% Parameters are
%% <ul>
%%   <li>
%%      `Alg' is a binary one of
%%
%%      [HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512, PS256, PS384, PS512]
%%
%%      But only [HS256, HS384, HS512, RS256] are supported
%%  </li>
%%  <li>`ClaimsSet' the payload of the token. Can be both map and proplist</li>
%%  <li>`Key' binary in case of hmac encryption and private key if rsa, or a tuple of the form `{KeyId, Key}' where `KeyId' is the identifier of the key in the JWKS (JSON Web Key Set)</li>
%% </ul>
%%
%% @end
encode(Alg, ClaimsSet, Key) ->
    {KeyId, Key1} = case Key of
                        {Kid, _} when is_binary(Kid) ->
                            Key;
                        _ ->
                            {undefined, Key}
                    end,
    Claims = base64url:encode(jsx:encode(ClaimsSet)),
    Header = base64url:encode(jsx:encode(jwt_header(Alg, KeyId))),
    Payload = <<Header/binary, ".", Claims/binary>>,
    case jwt_sign(Alg, Payload, Key1) of
        undefined -> {error, algorithm_not_supported};
        Signature -> {ok, <<Payload/binary, ".", Signature/binary>>}
    end.

-spec encode(
    Alg :: binary(),
    ClaimsSet :: map() | list(),
    Expiration :: expiration(),
    Key :: key() | {key_id() | key()}
) -> {ok, Token :: binary()} | {error, any()}.
%% @doc Creates a token from given data and signs it with a given secret
%%
%% and also adds `exp' claim to payload
%%
%% `Expiration' can be one of the tuples:
%%    `{hourly, SecondsAfterBeginningOfCurrentHour}',
%%    `{daily, SecondsAfterBeginningOfCurrentDay}'
%% or can be just an integer representing the amount of seconds
%% the token will live
%%
%% @end
encode(Alg, ClaimsSet, Expiration, Key) ->
    Claims = jwt_add_exp(ClaimsSet, Expiration),
    encode(Alg, Claims, Key).

-spec decode(
    Token :: binary(),
    KeyOrIssuerKeyMapping :: key() | public_key:public_key() | map()
) -> {ok, Claims :: map()} | {error, any()}.
%% @doc Decodes a token, checks the signature and returns the content of the token
%%
%% <ul>
%%   <li>`Token' is a JWT itself</li>
%%   <li>`Key' is a secret phrase or public/private key depend on encryption algorithm</li>
%%   <li>`IssuerKeyMapping' is an issuer key mapping or a JWKS (JSON Web Key SEt).</li>
%% </ul>
%%
%% @end
decode(Token, IssuerKeyMapping) when is_map(IssuerKeyMapping) ->
    decode(Token, <<>>, IssuerKeyMapping);
decode(Token, Key) ->
    decode(Token, Key, #{}).

% When there are multiple issuers and keys are on a per issuer bases
% then apply those keys instead
-spec decode(
    Token :: binary(),
    DefaultKey :: key() | public_key:public_key(),
    IssuerKeyMapping :: map()
) -> {ok, Claims :: map()} | {error, any()}.
%% @doc Decode with an issuer key mapping
%%
%% Receives the issuer key mapping or JWKS (JSON Web Key Set) as the last parameter
%%
%% @end
decode(Token, DefaultKey, IssuerKeyMapping) ->
    result(reduce_while(fun(F, Acc) -> apply(F, [Acc]) end, #{token => Token}, [
        fun split_token/1,
        fun decode_jwt/1,
        fun (Context) ->
            get_key(Context, DefaultKey, IssuerKeyMapping)
        end,
        fun check_signature/1,
        fun check_expired/1
    ])).

result(#{claims_json := ClaimsJSON}) ->
    {ok, ClaimsJSON};
result({error, _} = Error) ->
    Error.

reduce_while(_Fun, Acc, []) ->
    Acc;
reduce_while(Fun, Acc, [Item|Rest]) ->
    case Fun(Item, Acc) of
        {cont, NewAcc} ->
            reduce_while(Fun, NewAcc, Rest);
        {halt, Result} ->
            Result
    end.

-spec split_token(Context :: context()) ->
    {cont, context()} | {halt, {error, invalid_token}}.
%% @private
split_token(#{token := Token} = Context) ->
    case binary:split(Token, <<".">>, [global]) of
        [Header, Claims, Signature] ->
            {cont, maps:merge(Context, #{
                header => Header,
                claims => Claims,
                signature => Signature
            })};
        _ ->
            {halt, {error, invalid_token}}
    end.

-spec decode_jwt(context()) -> {cont, context()} | {halt, {error, invalid_token}}.
%% @private
decode_jwt(#{header := Header, claims := Claims} = Context) ->
    try
        [HeaderJSON, ClaimsJSON] =
            Decoded = [jsx_decode_safe(base64url:decode(X)) || X <- [Header, Claims]],
        case lists:any(fun(E) -> E =:= invalid end, Decoded) of
            false ->
                {cont, maps:merge(Context, #{
                    header_json => HeaderJSON,
                    claims_json => ClaimsJSON
                })};
            true  ->
                {halt, {error, invalid_token}}
        end
    catch _:_ ->
        {halt, {error, invalid_token}}
    end.

%% @private
get_key(
  #{header_json := #{<<"kid">> := _}} = Context,
  _DefaultKey,
  #{<<"keys">> := _} = DecodedJWKS) ->
    get_key_by_kid(Context, DecodedJWKS);
get_key(
  #{header_json := #{<<"kid">> := _}} = Context,
  EncodedJWKS,
  IssuerKeyMapping) when is_binary(EncodedJWKS) ->
    try
        DecodedJWKS = jsx:decode(EncodedJWKS, [{return_maps, true}]),
        get_key_by_kid(Context, DecodedJWKS)
    catch
        exit:badarg ->
            get_key_by_issuer(Context, EncodedJWKS, IssuerKeyMapping)
    end;
get_key(Context, DefaultKey, IssuerKeyMapping) ->
    get_key_by_issuer(Context, DefaultKey, IssuerKeyMapping).

get_key_by_kid(
  #{header_json := #{<<"kid">> := KeyId}} = Context,
  #{<<"keys">> := _} = JwkSet) ->
    case jwk:decode(KeyId, JwkSet) of
        {ok, Key} ->
            {cont, maps:merge(Context, #{key => Key})};
        Error ->
            {halt, Error}
    end.

get_key_by_issuer(
  #{claims_json := Claims} = Context, DefaultKey, IssuerKeyMapping) ->
    Issuer = maps:get(<<"iss">>, Claims, undefined),
    Key = maps:get(Issuer, IssuerKeyMapping, DefaultKey),
    {cont, maps:merge(Context, #{key => Key})}.

%% @private
check_signature(#{
    key         := Key,
    header      := Header,
    claims      := Claims,
    signature   := Signature,
    header_json := #{<<"alg">> := Alg}
} = Context) ->
    case jwt_check_sig(Alg, Header, Claims, Signature, Key) of
        true ->
            {cont, Context};
        false ->
            {halt, {error, invalid_signature}}
    end.

%% @private
check_expired(#{claims_json := ClaimsJSON} = Context) ->
    case jwt_is_expired(ClaimsJSON) of
        true  ->
            {halt, {error, expired}};
        false ->
            {cont, Context}
    end.

%%
%% Decoding helpers
%%
-spec jsx_decode_safe(binary()) -> map() | invalid.
%% @private
jsx_decode_safe(Bin) ->
    try
        jsx:decode(Bin, [return_maps])
    catch _ ->
        invalid
    end.

-spec jwt_is_expired(map()) -> boolean().
%% @private
jwt_is_expired(#{<<"exp">> := Exp} = _ClaimsJSON) ->
    case (Exp - epoch()) of
        DeltaSecs when DeltaSecs > 0 -> false;
        _ -> true
    end;
jwt_is_expired(_) ->
    false.

-spec jwt_check_sig(
    Alg :: binary(),
    Header :: binary(),
    Claims :: binary(),
    Signature :: binary(),
    Key :: key() | public_key:public_key()
) -> boolean().
%% @private
jwt_check_sig(Alg, Header, Claims, Signature, Key) ->
    jwt_check_sig(algorithm_to_crypto(Alg), <<Header/binary, ".", Claims/binary>>, Signature, Key).

-spec jwt_check_sig(
    {atom(), atom()},
    Payload :: binary(),
    Signature :: binary(),
    Key :: key() | public_key:public_key()
) -> boolean().
%% @private
jwt_check_sig({hmac, _} = Alg, Payload, Signature, Key) ->
    jwt_sign_with_crypto(Alg, Payload, Key) =:= Signature;

jwt_check_sig({Algo, Crypto}, Payload, Signature, Pem)
    when (Algo =:= rsa orelse Algo =:= ecdsa) andalso is_binary(Pem) ->
    jwt_check_sig({Algo, Crypto}, Payload, Signature, pem_to_key(Pem));

jwt_check_sig({rsa, Crypto}, Payload, Signature, Key) ->
    public_key:verify(Payload, Crypto, base64url:decode(Signature), Key);

jwt_check_sig({ecdsa, Crypto}, Payload, Signature, Key) ->
    public_key:verify(Payload, Crypto, jwt_ecdsa:signature(Signature), Key);

jwt_check_sig(_, _, _, _) ->
    false.

%%
%% Encoding helpers
%%
-spec jwt_add_exp(ClaimsSet :: map() | list(), Expiration :: expiration()) -> map() | list().
%% @private
jwt_add_exp(ClaimsSet, Expiration) ->
    Exp = expiration_to_epoch(Expiration),
    append_claim(ClaimsSet, <<"exp">>, Exp).

-spec jwt_header(Alg :: binary(), KeyId :: binary() | undefined) -> list().
jwt_header(Alg, KeyId) ->
    EncodedKeyId = case KeyId of
                       undefined ->
                           [];
                       _ ->
                           [{<<"kid">>, KeyId}]
                   end,
    [ {<<"alg">>, Alg}
    , {<<"typ">>, <<"JWT">>}
    | EncodedKeyId
    ].

%%
%% Helpers
%%
-spec jwt_sign(
    Alg :: binary(),
    Payload :: binary(),
    Key :: key()
) -> binary() | undefined.
%% @private
jwt_sign(Alg, Payload, Key) ->
    jwt_sign_with_crypto(algorithm_to_crypto(Alg), Payload, Key).

jwt_sign_with_crypto({hmac, Crypto}, Payload, Key) ->
    base64url:encode(?HMAC(Crypto, Key, Payload));

jwt_sign_with_crypto({Algo, Crypto}, Payload, Pem)
    when (Algo =:= rsa orelse Algo =:= ecdsa) andalso is_binary(Pem) ->
    jwt_sign_with_crypto({Algo, Crypto}, Payload, pem_to_key(Pem));

jwt_sign_with_crypto({rsa, Crypto}, Payload, Key) ->
    base64url:encode(public_key:sign(Payload, Crypto, Key));

jwt_sign_with_crypto({ecdsa, Crypto}, Payload, Key) ->
    base64url:encode(jwt_ecdsa:signature(Payload, Crypto, Key));

jwt_sign_with_crypto(_, _Payload, _Key) ->
    undefined.

-spec algorithm_to_crypto(binary()) -> {atom(), atom()} | undefined.
%% @private
algorithm_to_crypto(<<"HS256">>) -> {hmac, sha256};
algorithm_to_crypto(<<"HS384">>) -> {hmac, sha384};
algorithm_to_crypto(<<"HS512">>) -> {hmac, sha512};
algorithm_to_crypto(<<"RS256">>) -> {rsa,  sha256};
algorithm_to_crypto(<<"RS384">>) -> {rsa,  sha384};
algorithm_to_crypto(<<"RS512">>) -> {rsa,  sha512};
algorithm_to_crypto(<<"ES256">>) -> {ecdsa, sha256};
algorithm_to_crypto(_)           -> undefined.

-spec epoch() -> non_neg_integer().
%% @private
epoch() -> erlang:system_time(seconds).

-spec expiration_to_epoch(Expiration :: expiration()) -> neg_integer().
%% @private
expiration_to_epoch(Expiration) ->
    expiration_to_epoch(Expiration, epoch()).

expiration_to_epoch(Expiration, Ts) ->
    case Expiration of
        {hourly, Expiration0} -> (Ts - (Ts rem ?HOUR)) + Expiration0;
        {daily, Expiration0} -> (Ts - (Ts rem ?DAY)) + Expiration0;
        _ -> epoch() + Expiration
    end.

-spec append_claim(ClaimsSet :: map() | list(), binary(), any()) -> map() | list().
%% @private
append_claim(ClaimsSet, Key, Val) when is_map(ClaimsSet) ->
  ClaimsSet#{ Key => Val };
append_claim(ClaimsSet, Key, Val) -> [{ Key, Val } | ClaimsSet].

pem_to_key(Pem) ->
    Decoded = case public_key:pem_decode(Pem) of
        [_, Key] ->
            Key;
        [Key] ->
            Key
    end,
    public_key:pem_entry_decode(Decoded).
