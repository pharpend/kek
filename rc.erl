%% @doc
%% this module exists to check that the table on pp. 12 of
%% https://www.crypto-textbook.com/download/Understanding-Cryptography-Keccak.pdf
%% is correct
-module(rc).

-compile([export_all, nowarn_export_all]).

-spec little_rc(T) -> Bit
    when T   :: non_neg_integer(),
         Bit :: 0 | 1.
%% copying from pp. 16 of https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
%%
%% n.b. the || operator there i think means concatenate

little_rc(T) when (T rem 255) =:= 0 ->
    1;
little_rc(T) ->
    R       = <<2#1000_0000>>,
    InitI   = 1,
    TMod255 = T rem 255,
    NewR = little_rc(InitI, TMod255, R),
    <<Result:1, _/bitstring>> = NewR,
    Result.

-spec little_rc(I, MaxI, R) -> NewR
    when I    :: pos_integer(),
         MaxI :: pos_integer(),
         R    :: <<_:8>>,
         NewR :: <<_:8>>.

little_rc(I, MaxI, R) when I =< MaxI ->
    R_  = <<0:1, R/bitstring>>,
    % need R_[0], R_[4], R_[5], R_[6], and R_[8]
    <<R_0:1, R_123:3, R_4:1, R_5:1, R_6:1, R_7:1, R_8:1>> = R_,
    NewR_0 = R_0 bxor R_8,
    NewR_4 = R_4 bxor R_8,
    NewR_5 = R_5 bxor R_8,
    NewR_6 = R_6 bxor R_8,
    NewR   = <<NewR_0  :1,
                  R_123:3,
               NewR_4  :1,
               NewR_5  :1,
               NewR_6  :1,
                  R_7  :1>>,
    NewI = I + 1,
    little_rc(NewI, MaxI, NewR);
little_rc(I, MaxI, R) when I > MaxI ->
    R.


% Table from pp. 12 of https://www.crypto-textbook.com/download/Understanding-Cryptography-Keccak.pdf
%
% RC[ 0] = 0x0000000000000001
% RC[ 1] = 0x0000000000008082
% RC[ 2] = 0x800000000000808A
% RC[ 3] = 0x8000000080008000
% RC[ 4] = 0x000000000000808B
% RC[ 5] = 0x0000000080000001
% RC[ 6] = 0x8000000080008081
% RC[ 7] = 0x8000000000008009
% RC[ 8] = 0x000000000000008A
% RC[ 9] = 0x0000000000000088
% RC[10] = 0x0000000080008009
% RC[11] = 0x000000008000000A
% RC[12] = 0x000000008000808B
% RC[13] = 0x800000000000008B
% RC[14] = 0x8000000000008089
% RC[15] = 0x8000000000008003
% RC[16] = 0x8000000000008002
% RC[17] = 0x8000000000000080
% RC[18] = 0x000000000000800A
% RC[19] = 0x800000008000000A
% RC[20] = 0x8000000080008081
% RC[21] = 0x8000000000008080
% RC[22] = 0x0000000080000001
% RC[23] = 0x8000000080008008

-spec big_rc(RoundIndex) -> BigRC
    when RoundIndex :: 0..23,
         BigRC      :: <<_:64>>.

%% from pp. 16 of the NIST doc:
%%  > 2. Let RC = 0w.
%%  > 3. For j from 0 to l, let RC[2^j – 1] = rc(j + 7*ir).
%%
%% In this case, 0w = <<0:64>>, l = 6, ir ranges between 0..23
%%
%%  > 2. Let RC = 0w.
%%  > 3. For j from 0 to 6, let RC[2^j – 1] = rc(j + 7*ir).

big_rc(RoundIndex) ->
    InitJ     = 0,
    InitBigRC = <<0:64>>,
    big_rc(RoundIndex, InitJ, InitBigRC).


-spec big_rc(RoundIndex, J, BigRCAcc) -> BigRC
    when RoundIndex :: 0..23,
         J          :: 0..6,
         BigRCAcc   :: BigRC,
         BigRC      :: <<_:64>>.

%%  > 3. For j from 0 to 6, let RC[2^j – 1] = rc(j + 7ir).
big_rc(RoundIndex, J, BigRCAcc) when 0 =< J, J =< 6 ->
    Idx0WeAreModifying                       = two_to_the(J) - 1,
    NewBit                                   = little_rc(J + 7*RoundIndex),
    NumSkipBits                              = Idx0WeAreModifying,
    <<Pre:NumSkipBits, _:1, Post/bitstring>> = BigRCAcc,
    NewJ                                     = J + 1,
    NewBigRCAcc                              = <<Pre:NumSkipBits, NewBit:1, Post/bitstring>>,
    big_rc(RoundIndex, NewJ, NewBigRCAcc);
big_rc(_RoundIndex, J, BigRCAcc) when J > 6 ->
    BigRCAcc.

two_to_the(N) when 0 =< N ->
    1 bsl N.


%% expected values
xrc( 0) -> <<( 16#0000000000000001 ):64>>;
xrc( 1) -> <<( 16#0000000000008082 ):64>>;
xrc( 2) -> <<( 16#800000000000808A ):64>>;
xrc( 3) -> <<( 16#8000000080008000 ):64>>;
xrc( 4) -> <<( 16#000000000000808B ):64>>;
xrc( 5) -> <<( 16#0000000080000001 ):64>>;
xrc( 6) -> <<( 16#8000000080008081 ):64>>;
xrc( 7) -> <<( 16#8000000000008009 ):64>>;
xrc( 8) -> <<( 16#000000000000008A ):64>>;
xrc( 9) -> <<( 16#0000000000000088 ):64>>;
xrc(10) -> <<( 16#0000000080008009 ):64>>;
xrc(11) -> <<( 16#000000008000000A ):64>>;
xrc(12) -> <<( 16#000000008000808B ):64>>;
xrc(13) -> <<( 16#800000000000008B ):64>>;
xrc(14) -> <<( 16#8000000000008089 ):64>>;
xrc(15) -> <<( 16#8000000000008003 ):64>>;
xrc(16) -> <<( 16#8000000000008002 ):64>>;
xrc(17) -> <<( 16#8000000000000080 ):64>>;
xrc(18) -> <<( 16#000000000000800A ):64>>;
xrc(19) -> <<( 16#800000008000000A ):64>>;
xrc(20) -> <<( 16#8000000080008081 ):64>>;
xrc(21) -> <<( 16#8000000000008080 ):64>>;
xrc(22) -> <<( 16#0000000080000001 ):64>>;
xrc(23) -> <<( 16#8000000080008008 ):64>>.


%% all false
check() ->
    CheckI =
        fun(I) ->
            io:format("I = ~p: ~p~n", [I, big_rc(I) =:= xrc(I)])
        end,
    lists:foreach(CheckI, lists:seq(0, 23)).

%% checks if the expectation equals the outcome in the reversed case
%% all true
check_rev() ->
    CheckI =
        fun(I) ->
            BigResult = str64(big_rc(I)),
            ExpResult = lists:reverse(str64(xrc(I))),
            io:format("I = ~p: ~p~n", [I, BigResult =:= ExpResult])
        end,
    lists:foreach(CheckI, lists:seq(0, 23)).



%% format a 64 bit binary as a string (no newline)
str64(<<N:64>>) ->
    %% prints with 0 as the padding character
    iolist_to_list(io_lib:format("~64.2.0B", [N])).

%% prints with _ as the padding character, newline
print64_(<<N:64>>) ->
    io:format("~64.2._B~n", [N]).

iolist_to_list(IoList) ->
    binary_to_list(iolist_to_binary(IoList)).


%% print out big_rc(N) -> RC(N)
print_big_rcs() ->
    pbr(0).

% 1 digit numbers
pbr(N) when 0 =< N, N =< 9 ->
    <<ThisRC_int:64>> = big_rc(N),
    io:format("round_constant_int( ~p) -> ~p;~n", [N, ThisRC_int]),
    pbr(N + 1);
% 2 digit numbers
pbr(N) when 10 =< N, N =< 22 ->
    <<ThisRC_int:64>> = big_rc(N),
    io:format("round_constant_int(~p) -> ~p;~n", [N, ThisRC_int]),
    pbr(N + 1);
% terminal case
pbr(N) when N =:= 23 ->
    <<ThisRC_int:64>> = big_rc(N),
    io:format("round_constant_int(~p) -> ~p.~n", [N, ThisRC_int]).
