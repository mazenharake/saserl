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
%% Server: Takes a request string (sent by the client) which consists of an
%% [optional] authority id (AuthZid) and a username (AuthCid) and password. The
%% request string is sent over a protocol specific manner and may be in
%% base64. However it is not expected that the string given to this library is
%% in base64 and should therefore be decoded before it is used. The values are
%% then checked using a fun which validates them according to application
%% specific logic.
%%
%% Client: A client create a request string using an [optional] authority id
%% (AuthZid) and a username (AuthCid) and password and sends this request in a
%% protocol specific way
%%
-module(saserl_plain).
-include("saserl.hrl").
-export([authorize/2, request_string/3]).

%% == SERVER USE ==
%% These functions are used by a server trying to authenticate a client. The
%% client functions are found below.

%% Takes a string according to the PLAIN format and applies PasswdFun on the
%% parameters to see authorize the request. PasswdFun must be a fun of arity 3
%% taking AuthZid, AuthCid and Passwd as input. AuthZid will be an empty string
%% if it wasn't sent with the request. The function returns what ever the
%% PasswdFun fun returns.
authorize(PasswdFun, PlainString) ->
    case string:tokens(PlainString, "\0") of
	[AuthCid, Passwd] ->
	    PasswdFun("", AuthCid, Passwd);
	[AuthZid, AuthCid, Passwd] ->
	    PasswdFun(AuthZid, AuthCid, Passwd);
	_ ->
	    {error, protocol_error}
    end.

%% == CLIENT USE ==
%% These functions are intended to be used by a client which wants to send an
%% authentication request

%% Returns a proper formated request string
request_string(AuthZid, AuthCid, Passwd) when is_list(AuthZid) andalso
					      is_list(AuthCid) andalso
					      is_list(Passwd) ->
    lists:flatten([AuthZid, "\0", AuthCid, "\0", Passwd]).
    
