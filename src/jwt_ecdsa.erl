%% @doc Elliptic curve digital signature algorithm
%%
%% Helper functions for encoding/decoding ECDSA signature
%%
%% @end
-module(jwt_ecdsa).

-include_lib("jwt_ecdsa.hrl").
-include_lib("public_key/include/public_key.hrl").

-export([
    signature/1,
    signature/3
]).

%% @doc Signature for JWT verification
%%
%% Transcode the ECDSA Base64-encoded signature into ASN.1/DER format
%%
%% @end
signature(Base64Sig) ->
    Signature = base64url:decode(Base64Sig),
    SignatureLen = byte_size(Signature),
    {RBin, SBin} = split_binary(Signature, (SignatureLen div 2)),
    R = crypto:bytes_to_integer(RBin),
    S = crypto:bytes_to_integer(SBin),
    public_key:der_encode('ECDSA-Sig-Value', #'ECDSA-Sig-Value'{ r = R, s = S }).

%% @doc Signature to sign JWT
%%
%% Transcodes the JCA ASN.1/DER-encoded signature into the concatenated R + S format
%% a.k.a <em>raw</em> format
%%
%% @end
signature(Payload, Crypto, Key) ->
    Der = public_key:sign(Payload, Crypto, Key),
    raw(Der, Key).

raw(Der, #'ECPrivateKey'{parameters = {namedCurve, NamedCurve}}) ->
    #'ECDSA-Sig-Value'{ r = R, s = S } = public_key:der_decode('ECDSA-Sig-Value', Der),
    CurveName = pubkey_cert_records:namedCurves(NamedCurve),
    GroupDegree = group_degree(CurveName),
    Size = (GroupDegree + 7) div 8,
    RBin = int_to_bin(R),
    SBin = int_to_bin(S),
    RPad = pad(RBin, Size),
    SPad = pad(SBin, Size),
    <<RPad/binary, SPad/binary>>.

%% @private
int_to_bin(X) when X < 0 ->
    int_to_bin_neg(X, []);
int_to_bin(X) ->
    int_to_bin_pos(X, []).

%% @private
int_to_bin_pos(0, Ds = [_|_]) ->
    list_to_binary(Ds);
int_to_bin_pos(X, Ds) ->
    int_to_bin_pos(X bsr 8, [(X band 255)|Ds]).

%% @private
int_to_bin_neg(-1, Ds = [MSB|_]) when MSB >= 16#80 ->
    list_to_binary(Ds);
int_to_bin_neg(X, Ds) ->
    int_to_bin_neg(X bsr 8, [(X band 255)|Ds]).

%% @private
pad(Bin, Size) when byte_size(Bin) =:= Size ->
    Bin;
pad(Bin, Size) when byte_size(Bin) < Size ->
    pad(<<0, Bin/binary>>, Size).

%% See the OpenSSL documentation for EC_GROUP_get_degree()
group_degree(CurveName) ->
    maps:get(CurveName, ?EC_GROUP_DEGREE).
