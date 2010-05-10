%% Copyright (c) 2010, Mazen Harake
%% All rights reserved.
%%
%% Redistribution and use in source and binary forms, with or without
%% modification, are permitted provided that the following conditions are met:
%%
%%     * Redistributions of source code must retain the above copyright notice,
%%       this list of conditions and the following disclaimer.
%%     * Redistributions in binary form must reproduce the above copyright
%%       notice, this list of conditions and the following disclaimer in the
%%       documentation and/or other materials provided with the distribution.
%%     * Neither the name of the <ORGANIZATION> nor the names of its
%%       contributors may be used to endorse or promote products derived from
%%       this software without specific prior written permission.
%%
%% THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
%% AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
%% IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
%% ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
%% LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
%% CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
%% SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
%% INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
%% CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
%% ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
%% POSSIBILITY OF SUCH DAMAGE.
%%
%% USAGE:
%%
%% Server: Start by generating a challenge. Send this challenge to the client in
%% which ever protocol specific way that is required. The challenge is not
%% base64 encoded so that might be needed. After the challenge has been sent the
%% response is received from the client and verified. The server has to keep
%% track of its own Nc value (I.e. how many challenges that have been sent). The
%% password on the server side is retrieved by providing a fun which retrieves
%% it from an application specific source.
%%
%% Client: A Server has sent you a challenge, given the challenge the client
%% inputs the challenge, the number of challenges so far (The Nc value starting
%% from 1 which is the first challange) and the username/password and the
%% digest-uri according to the RFC. The respone given is sent back to the server
%% over the protocol specified. The client has to keep track of the Nc value
%% itself
%%
-module(saserl_digest).
-include("saserl.hrl").
-export([gen_challenge/1, verify_response/3, challenge_response/5,
	 challenge_response/6]).

%% == SERVER USE ==
%% These functions are used by a server trying to authenticate a client. The
%% client functions are found below.

%% Generates a challenge string which consists of the smallest set needed to
%% do a challenge-response cycle. The Additions variable is a proplist with
%% additional key values what are to be sent E.g. realm, maxbuf etc. see RFC
%% for the details on what extra stuff you can send.
gen_challenge(Additions) ->
    Nonce = gen_nonce(),
    BaseStr = io_lib:format("nonce=~p,qop=\"auth\",charset=utf-8,"
			    "algorithm=md5-sess", [Nonce]),
    AdditionStr = [ io_lib:format(",~p=~p",[Attr,Val]) 
		    || {Attr, Val} <- Additions ],
    {Nonce, fl(BaseStr++AdditionStr)}.

%% Generates a salt which according to the RFC needs to be different every time
%% and it is recommended that this is in base64 or hex data and at least 64 bits
%% of entropy... no problem. Note: Just because this is base64 it doesn't mean 
%% that the other side need to decode it... it is just data to salt with. Same
%% goes for Cnonce (further down)
gen_nonce() ->
    [ lists:nth(random:uniform(62),?ALPHANUM) || _ <- lists:seq(1,64) ].

%% Verifies the response given on a challenge. Response is the response string
%% in clear text, meaning that if data is received as base64 from the client 
%% then it needs to be decoded before it is passed to this function. Nc is the
%% number of challenges that has gone out. After the response to the first 
%% challenge has come in the call to this function will have an Nc value of 1.
%% Passfun is a fun/4 which takes the following parameters:
%% Username, AuthorizationId, DigestURI and Realm. given these parameters the
%% fun should return the password of that user within that realm. This password
%% is then used to verify that the digest which was received is valid.
verify_response(Response, Nc, PassFun) ->
    try
	Tokens = challenge_to_proplist(Response),
	RNc = proplists:get_value(nc,Tokens),
	%% Check that this is a response to the N:th challenge, if not (there is
	%% a mismatch) then exit because something is wrong. We expect Nc and
	%% parse out RNc, they must match.
	case nc_to_string(Nc) of
	    RNc -> verify_response_value(Tokens, RNc, PassFun);
	    Nc -> erlang:error({nc_error, Nc, RNc})
	end
    catch
	_:Reason -> {error, Reason}
    end.

%% Verifies that the response value we got from a client is valid by extracting
%% all the information and running it through the same digest functions as the 
%% clients have but with our own password. If the resulting md5 comes out the 
%% same then the client's password is the same as ours.
verify_response_value(Tokens, Nc, PassFun) ->
    ResponseValue = proplists:get_value(response, Tokens),
    Usr = proplists:get_value(username, Tokens),
    Authzid = proplists:get_value(authzid, Tokens),
    Duri = verify_duri(proplists:get_value('digest-uri', Tokens)),
    Realm = proplists:get_value(realm, Tokens, ""),
    %% Evaluate PassFun to get the password. How this is done we don't care just
    %% give us the password :)
    Pwd = PassFun(Usr, Authzid, Duri, Realm),
    Nonce = proplists:get_value(nonce, Tokens),
    Cnonce = proplists:get_value(cnonce, Tokens),
    Qop = proplists:get_value(qop, Tokens, ""),
    case response_value(Usr, Realm, Pwd, Nonce, Cnonce, Nc, Qop,
			"AUTHENTICATE", Duri, Authzid) of
	ResponseValue ->
	    {ok, fl(["rspauth=",response_value(Usr, Realm, Pwd, Nonce, Cnonce, 
					       Nc, Qop, "", Duri, Authzid)])};
	ErrorenousResponse ->
	    exit({nomatch, ResponseValue, ErrorenousResponse})
    end.

%% Verifies that the digest-uri value sent from the client matches according to
%% our criterias... currently this is "it has to exist"... should be better
%% since we want to verify that the client is trying to reach the expected place
verify_duri(undefined) -> exit({missing, 'digest-uri'});
verify_duri(Duri) -> Duri.
			
%% == CLIENT USE ==
%% These functions are intended to be used by a client which wants to respond to
%% a server challenge.

%% Short function for calling challenge_response/6 with zero options
challenge_response(Challenge, Nc, Usr, Pwd, DigestURI) ->
   challenge_response(Challenge, Nc, Usr, Pwd, DigestURI, []).

%% Takes a challenge and extracts all the information needed then returns the
%% response string depending on the information supplied with the challenge.
challenge_response(Challenge, Nc, Usr, Pwd, Duri, Options) ->
    Tokens = challenge_to_proplist(Challenge),
    Realm = proplists:get_value(realm, Tokens, ""),
    Nonce = proplists:get_value(nonce, Tokens),
    Ncval = nc_to_string(Nc),
    Qop = proplists:get_value(qop, Tokens, "auth"),
    Authzid = proplists:get_value(authzid, Options),
    case proplists:get_value(cnonce, Options) of
	undefined -> Cnonce = gen_cnonce();
	Cnonce -> ok
    end,
    RespVal = response_value(Usr, Realm, Pwd, Nonce, Cnonce, Ncval,
			     Qop, "AUTHENTICATE", Duri, Authzid),
    fl(gen_response(Usr, Realm, Nonce, Cnonce, Ncval, Duri, Qop, RespVal)).

%% Function to generate a salt. Since this is just a way to generate a salt the
%% function just calls nonce/0 to produce a salt. The function is here to make
%% the code easier to read by recognizing the various parts of the SASL protocol
gen_cnonce() ->
    gen_nonce().

%% Generates a proper response according to the format specified in the RFC.
gen_response(Usr, Realm, Nonce, Cnonce, Ncval, Duri, Qop, RespVal) ->
    case Realm of
	"" -> Realm2 = "";
	_ -> Realm2 = ",realm=\""++Realm++"\""
    end,
    io_lib:format("username=~p~s,nonce=~p,cnonce=~p,nc=~s,digest-uri=~p,"
		  "qop=~s,response=~s,charset=utf-8",
		  [Usr, Realm2, Nonce, Cnonce, Ncval, Duri, Qop, RespVal]).
    

%% == Functions defined in RFC2831 ==
%% These formats have the same names as specified in the mentioned RFC to make
%% it easier to understand and follow. For more information about the functions
%% look up the relevant sections in the RFC

response_value(Usr, Realm, Pwd, Nonce, Cnonce, Nc, Qop, A2Prefix, Duri, Azid) ->
    A1 = 'A1'(Usr, Realm, Pwd, Nonce, Cnonce, Azid),
    A2 = 'A2'(A2Prefix, Duri, Qop),
    K = 'HEX'('H'(A1)),
    S = [Nonce,":",Nc,":",Cnonce,":",Qop,":",'HEX'('H'(A2))],
    fl('HEX'('KD'(K,S))).

'H'(S) -> erlang:md5(fl(S)).

'KD'(K, S) -> 
    'H'([K,":",S]).

'HEX'(S) -> 
    [io_lib:format("~2.16.0b",[H]) || H <- binary_to_list(S)].

'A1'(Uname, Realm, Passwd, Nonce, Cnonce, undefined) ->
    ['H'([Uname,":",Realm,":",Passwd]),":",Nonce,":",Cnonce];
'A1'(Uname, Realm, Passwd, Nonce, Cnonce, Authzid) ->
    ['H'([Uname,":",Realm,":",Passwd]),":",Nonce,":",Cnonce,":",Authzid].

'A2'(Prefix, Duri, "auth") ->
    [Prefix,":",Duri];
'A2'(Prefix, Duri, _Other) -> 
    [Prefix,":",Duri,":00000000000000000000000000000000"].

%% == Helper functions ==

%% Take a challenge string and chop it up and convert everything to a proplist.
challenge_to_proplist(ChallengeStr) ->
    Tokens = string:tokens(ChallengeStr,","),
    MapFun = fun(Attr) -> keyval(Attr, []) end,
    lists:map(MapFun, Tokens).

%% Use this instead of string:tokens/2 on "=" because nonce can contain the
%% "=" character and that screws up things (idiotic... I know). Basically find
%% the first "=" char and everything before is the key and everything after is
%% the value.
keyval([$=|Rest], Acc) ->
    {list_to_atom(lists:reverse(Acc)), unescape(Rest)};
keyval([C|Rest], Acc) ->
    keyval(Rest, [C|Acc]).

%% This function removes string notations inside strings. E.g. if one has
%% "\"something\"" we simply want it as "something".
unescape(Val) -> unescape(Val, false).
unescape([], _Flag) -> [];
unescape([$\\,X|Rest], Flag) -> [X|unescape(Rest,Flag)];
unescape([$"|_Rest], true) -> [];
unescape([$"|Rest], false) -> unescape(Rest, true);
unescape([C|Rest], Flag) -> [C|unescape(Rest, Flag)].

%% flatten... but shorter. (yes, because I refuse to "import").
fl(L) -> lists:flatten(L).

%% pad a number with 0's to a string length of 8
nc_to_string(Nc) ->
    string:right(integer_to_list(Nc),8,$0).
