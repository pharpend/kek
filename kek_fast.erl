%% @doc
%% References
%% 1. Helpful lecture: https://www.youtube.com/watch?v=JWskjzgiIa4
%%    Notes: https://www.crypto-textbook.com/download/Understanding-Cryptography-Keccak.pdf
%% 2. NIST standard: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
%%    (btw: the double bar notation means "concatenate")
%% 3. https://en.wikipedia.org/wiki/SHA-3
%% @end
-module(kek_fast).

-compile([export_all, nowarn_export_all]).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% TOP LEVEL API
%%%
%%% sha*s and shake*s
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

-spec sha3_224(Message) -> Digest
    when Message :: bitstring(),
         Digest  :: <<_:224>>.
%% @doc
%% SHA-3 with an output bit length of 224 bits.
%% @end

sha3_224(Message) ->
    sha3(224, Message).


-spec sha3_256(Message) -> Digest
    when Message :: bitstring(),
         Digest  :: <<_:256>>.
%% @doc
%% SHA-3 with an output bit length of 256 bits.
%% @end

sha3_256(Message) ->
    sha3(256, Message).


-spec sha3_384(Message) -> Digest
    when Message :: bitstring(),
         Digest  :: <<_:384>>.
%% @doc
%% SHA-3 with an output bit length of 384 bits.
%% @end

sha3_384(Message) ->
    sha3(384, Message).


-spec sha3_512(Message) -> Digest
    when Message :: bitstring(),
         Digest  :: <<_:512>>.
%% @doc
%% SHA-3 with an output bit length of 512 bits.
%% @end

sha3_512(Message) ->
    sha3(512, Message).


-spec sha3(OutputBitLength, Message) -> Digest
    when OutputBitLength :: pos_integer(),
         Message         :: bitstring(),
         Digest          :: bitstring().
%% @doc
%% SHA-3 with an arbitrary output bit length.
%%
%% This means Keccak with Capacity = 2*OutputBitLength. Additionally, SHA3
%% concatenates the bits 01 onto the end of the input, before sending the
%% Message to keccak/3.
%% @end

sha3(OutputBitLength, Message) ->
    Capacity = 2*OutputBitLength,
    keccak(Capacity, Message, <<2#01:2>>, OutputBitLength).


-spec shake128(Message, OutputBitLength) -> Digest
    when Message         :: bitstring(),
         OutputBitLength :: pos_integer(),
         Digest          :: bitstring().
%% @doc
%% This is the SHAKE variable-length hash with Capacity 256 = 2*128 bits.
%% @end

shake128(Message, OutputBitLength) ->
    shake(128, Message, OutputBitLength).


-spec shake256(Message, OutputBitLength) -> Digest
    when Message         :: bitstring(),
         OutputBitLength :: pos_integer(),
         Digest          :: bitstring().
%% @doc
%% This is the SHAKE variable-length hash with Capacity 512 = 2*256 bits.
%% @end

shake256(Message, OutputBitLength) ->
    shake(256, Message, OutputBitLength).


-spec shake(ShakeNumber, Message, OutputBitLength) -> Digest
    when ShakeNumber     :: pos_integer(),
         Message         :: bitstring(),
         OutputBitLength :: pos_integer(),
         Digest          :: bitstring().
%% @doc
%% This is the SHAKE variable-length hash with Capacity 512 = 2*ShakeNumber bits.
%%
%% This concatenates the bitstring 1111 onto the end of the Message before
%% sending the message to keccak/3.
%% @end

shake(ShakeNumber, Message, OutputBitLength) ->
    Capacity = 2*ShakeNumber,
    keccak(Capacity, Message, <<2#1111:4>>, OutputBitLength).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% OUTER KECCAK
%%%
%%% Keccak pads the input, absorbs it into the sponge, and squeezes the bits out
%%% of the sponge.  The absorption and squeezing phases invoke "inner keccak",
%%% which is the heart of the algorithm.
%%%
%%% - keccak/3
%%% - pad/2
%%% - absorb/4
%%% - squeeze/3
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

-spec keccak(Capacity, Message, Delimiter, OutputBitLength) -> Digest
    when Capacity        :: pos_integer(),
         Message         :: bitstring(),
         Delimiter       :: bitstring(),
         OutputBitLength :: pos_integer(),
         Digest          :: bitstring().
%% @doc
%% Note: this is Keccak 1600, the only one used in practice
%%
%% Capacity must be strictly less than 1600
%% @end

keccak(Capacity = _c, Message, Delimiter, OutputBitLength) ->
    BitRate       = 1600 - Capacity,
    PaddedMessage = pad(Message, Delimiter, BitRate),
    InitialSponge = <<0:1600>>,
    WetSponge     = absorb(PaddedMessage, BitRate, Capacity, InitialSponge),
    ResultBits    = squeeze(WetSponge, OutputBitLength, BitRate),
    ResultBits.


-spec pad(Message, Delimiter, BitRate) -> NewMessage
    when Message    :: bitstring(),
         Delimiter  :: bitstring(),
         BitRate    :: pos_integer(),
         NewMessage :: bitstring().
%% @private
%% padding
%% divide the message into r-bit blocks
%%
%% the message ends with 1000...0001
%%
%% sha3 calls this /10*1/ as in the regex
%%
%% Reference: https://en.wikipedia.org/wiki/SHA-3#Padding
%% @end

pad(Msg, Delimiter, BitRate) ->
    MsgBits = bit_size(Msg),
    DlmBits = bit_size(Delimiter),
    <<Msg0:(MsgBits div 8)/bytes, Msg1/bitstring>> = Msg,
    case (MsgBits + DlmBits) rem BitRate of
        0 -> %% We add a complete RWord + flip the last chunk of the message
            <<Msg0/binary, (rev_pad(Msg1, Delimiter, BitRate - 2))/bitstring>>;
        N when N == BitRate - 1 -> %% Slightly retarded case
            <<Msg0/binary, (rev_pad(Msg1, Delimiter, BitRate - 1))/bitstring>>;
        N ->
            <<Msg0/binary, (rev_pad(Msg1, Delimiter, BitRate - N - 2))/bitstring>>
    end.

%% Instead of reverting message bits, work with a "reversed" padding
rev_pad(Msg, Delimiter, PadZeros) ->
    Pad = <<Msg/bitstring, Delimiter/bitstring, 1:1, 0:PadZeros, 1:1>>,
    << (flip_bits(X)) || <<X:8>> <= Pad >>.

flip_bits(0) -> <<0:8>>;
flip_bits(<<A:1, B:1, C:1, D:1, E:1, F:1, G:1, H:1>>) ->
  <<H:1, G:1, F:1, E:1, D:1, C:1, B:1, A:1>>;
flip_bits(N) -> flip_bits(<<N:8>>).

-spec absorb(PaddedMessage, BitRate, Capacity, SpongeAcc) -> WetSponge
    when PaddedMessage :: bitstring(),
         BitRate       :: pos_integer(),
         Capacity      :: pos_integer(),
         SpongeAcc     :: <<_:1600>>,
         WetSponge     :: <<_:1600>>.
%% @private
%% Assumptions:
%%  1. BitRate + Capacity = 1600,
%%  2. BitRate divides the PaddedMessage length (i.e. already have done padding)
%% @end

% can pull off r bits from the start of the message
absorb(PaddedMessageBits, BitRate = _r, Capacity = _c, Sponge) when BitRate =< bit_size(PaddedMessageBits) ->
    <<ThisRWord:BitRate, Rest/bitstring>> = PaddedMessageBits,
    % we bitwise xor the sponge against the r word followed by a bunch of 0s
    <<SpongeInt:1600>> = Sponge,
    <<Foo:1600>>       = <<ThisRWord:BitRate, 0:Capacity>>,
    FInputInt          = SpongeInt bxor Foo,
    FInputBits         = <<FInputInt:1600>>,
    NewSponge          = inner_keccak(FInputBits),
    absorb(Rest, BitRate, Capacity, NewSponge);
% empty string, return the sponge
absorb(<<>>, _r, _c, FinalSponge) ->
    FinalSponge.



-spec squeeze(WetSponge, OutputBitLength, BitRate) -> ResultBits
    when WetSponge       :: <<_:1600>>,
         OutputBitLength :: pos_integer(),
         BitRate         :: pos_integer(),
         ResultBits      :: bitstring().
%% @private
%% squeeze the output bits out of the sponge
%% @end

%%% % simple case: bit length is less than (or equal to) the sponge size, just grab
%%% % the first ones
%%% % this is the case for the shas
%%% squeeze(<<ResultBits:OutputBitLength, _Rest/bitstring>>, OutputBitLength, _BitRate) ->
%%%     <<ResultBits:OutputBitLength>>;
% general case: output bit length is greater than the sponge size, construct
% accumulatively
% this is the case for the variable-length encodings
squeeze(WetSponge, OutputBitLength, BitRate) ->
    InitOutputAcc = <<>>,
    really_squeeze(WetSponge, OutputBitLength, BitRate, InitOutputAcc).

% terminal case: we have enough bits in the output, return those
really_squeeze(_WetSponge, OutputBitLength, _BitRate, FinalAccBits) when OutputBitLength =< bit_size(FinalAccBits) ->
    <<ResultBits:OutputBitLength, _/bitstring>> = FinalAccBits,
    <<ResultBits:OutputBitLength>>;
% general case: need moar bits
% in this case
%   - we grab the first r bits of the sponge, add them to the accumulator
%   - re-kek the sponge
%   - try again
really_squeeze(WetSponge, OutputBitLength, BitRate, ResultAcc)->
    <<ThisRWord:BitRate, _/bitstring>> = WetSponge,
    NewResultAcc                       = <<ResultAcc/bitstring, ThisRWord:BitRate>>,
    NewWetSponge                       = inner_keccak(WetSponge),
    really_squeeze(NewWetSponge, OutputBitLength, BitRate, NewResultAcc).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% THE DREADED INNER KECCAK
%%%
%%% This is the "f" function that appears in all the documentation.
%%%
%%% The input is the 1600-bit sponge array. inner_keccak/1 sends the input
%%% through 24 "rounds". Each round consists of the 5 Greek letter steps, each of
%%% which is a weird transformation on the array.
%%%
%%% Here the rounds are unrolled in terms of 64bit integers - for efficiency
%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%


inner_keccak(<<_:1600>> = State) ->
  IntState0 = list_to_tuple([ X || <<X:64/little>> <= State ]),
  IntState6 = inner_keccak_fast(IntState0),
  << <<X:64/little>> || X <- tuple_to_list(IntState6) >>.

inner_keccak_fast(IntState0) ->
  IntState1 = fast_round(IntState0, {16#0000000000000001, 16#0000000000008082, 16#800000000000808A, 16#8000000080008000}),
  IntState2 = fast_round(IntState1, {16#000000000000808B, 16#0000000080000001, 16#8000000080008081, 16#8000000000008009}),
  IntState3 = fast_round(IntState2, {16#000000000000008A, 16#0000000000000088, 16#0000000080008009, 16#000000008000000A}),
  IntState4 = fast_round(IntState3, {16#000000008000808B, 16#800000000000008B, 16#8000000000008089, 16#8000000000008003}),
  IntState5 = fast_round(IntState4, {16#8000000000008002, 16#8000000000000080, 16#000000000000800A, 16#800000008000000A}),
  fast_round(IntState5, {16#8000000080008081, 16#8000000000008080, 16#0000000080000001, 16#8000000080008008}).

-define(INT64, 16#FFFFFFFFFFFFFFFF).
-define(BSL64(X, N), ((X bsl N) band ?INT64)).
-define(BSR64(X, N), (X bsr N)).

-define(ROTL64(X, N), (?BSL64(X, N) bor ?BSR64(X, (64 - N)))).
-define(CAN64(A, B), ((A bxor B) band A)).

fast_round(As0, {RC0, RC1, RC2, RC3}) ->
  As1 = fast_round1(As0, RC0),
  As2 = fast_round2(As1, RC1),
  As3 = fast_round3(As2, RC2),
  fast_round4(As3, RC3).

fast_round1({A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15, A16, A17, A18, A19, A20, A21, A22, A23, A24}, RC0) ->
  %% Round 1
  BC0_0 = A0 bxor A5 bxor A10 bxor A15 bxor A20,
  BC1_0 = A1 bxor A6 bxor A11 bxor A16 bxor A21,
  BC2_0 = A2 bxor A7 bxor A12 bxor A17 bxor A22,
  BC3_0 = A3 bxor A8 bxor A13 bxor A18 bxor A23,
  BC4_0 = A4 bxor A9 bxor A14 bxor A19 bxor A24,
  D0 = BC4_0 bxor ?ROTL64(BC1_0, 1),
  D1 = BC0_0 bxor ?ROTL64(BC2_0, 1),
  D2 = BC1_0 bxor ?ROTL64(BC3_0, 1),
  D3 = BC2_0 bxor ?ROTL64(BC4_0, 1),
  D4 = BC3_0 bxor ?ROTL64(BC0_0, 1),

  BC0_1 = A0 bxor D0,
  BC1_1 = ?ROTL64(A6 bxor D1, 44),
  BC2_1 = ?ROTL64(A12 bxor D2, 43),
  BC3_1 = ?ROTL64(A18 bxor D3, 21),
  BC4_1 = ?ROTL64(A24 bxor D4, 14),
  A0_1  = BC0_1 bxor ?CAN64(BC2_1, BC1_1) bxor RC0,
  A6_1  = BC1_1 bxor ?CAN64(BC3_1, BC2_1),
  A12_1 = BC2_1 bxor ?CAN64(BC4_1, BC3_1),
  A18_1 = BC3_1 bxor ?CAN64(BC0_1, BC4_1),
  A24_1 = BC4_1 bxor ?CAN64(BC1_1, BC0_1),

  BC2_2 = ?ROTL64(A10 bxor D0, 3),
  BC3_2 = ?ROTL64(A16 bxor D1, 45),
  BC4_2 = ?ROTL64(A22 bxor D2, 61),
  BC0_2 = ?ROTL64(A3 bxor D3, 28),
  BC1_2 = ?ROTL64(A9 bxor D4, 20),
  A10_1 = BC0_2 bxor ?CAN64(BC2_2, BC1_2),
  A16_1 = BC1_2 bxor ?CAN64(BC3_2, BC2_2),
  A22_1 = BC2_2 bxor ?CAN64(BC4_2, BC3_2),
  A3_1  = BC3_2 bxor ?CAN64(BC0_2, BC4_2),
  A9_1  = BC4_2 bxor ?CAN64(BC1_2, BC0_2),

  BC4_3 = ?ROTL64(A20 bxor D0, 18),
  BC0_3 = ?ROTL64(A1 bxor D1, 1),
  BC1_3 = ?ROTL64(A7 bxor D2, 6),
  BC2_3 = ?ROTL64(A13 bxor D3, 25),
  BC3_3 = ?ROTL64(A19 bxor D4, 8),
  A20_1 = BC0_3 bxor ?CAN64(BC2_3, BC1_3),
  A1_1  = BC1_3 bxor ?CAN64(BC3_3, BC2_3),
  A7_1  = BC2_3 bxor ?CAN64(BC4_3, BC3_3),
  A13_1 = BC3_3 bxor ?CAN64(BC0_3, BC4_3),
  A19_1 = BC4_3 bxor ?CAN64(BC1_3, BC0_3),

  BC1_4 = ?ROTL64(A5 bxor D0, 36),
  BC2_4 = ?ROTL64(A11 bxor D1, 10),
  BC3_4 = ?ROTL64(A17 bxor D2, 15),
  BC4_4 = ?ROTL64(A23 bxor D3, 56),
  BC0_4 = ?ROTL64(A4 bxor D4, 27),
  A5_1  = BC0_4 bxor ?CAN64(BC2_4, BC1_4),
  A11_1 = BC1_4 bxor ?CAN64(BC3_4, BC2_4),
  A17_1 = BC2_4 bxor ?CAN64(BC4_4, BC3_4),
  A23_1 = BC3_4 bxor ?CAN64(BC0_4, BC4_4),
  A4_1  = BC4_4 bxor ?CAN64(BC1_4, BC0_4),

  BC3_5 = ?ROTL64(A15 bxor D0, 41),
  BC4_5 = ?ROTL64(A21 bxor D1, 2),
  BC0_5 = ?ROTL64(A2 bxor D2, 62),
  BC1_5 = ?ROTL64(A8 bxor D3, 55),
  BC2_5 = ?ROTL64(A14 bxor D4, 39),
  A15_1 = BC0_5 bxor ?CAN64(BC2_5, BC1_5),
  A21_1 = BC1_5 bxor ?CAN64(BC3_5, BC2_5),
  A2_1  = BC2_5 bxor ?CAN64(BC4_5, BC3_5),
  A8_1  = BC3_5 bxor ?CAN64(BC0_5, BC4_5),
  A14_1 = BC4_5 bxor ?CAN64(BC1_5, BC0_5),

  {A0_1, A1_1, A2_1, A3_1, A4_1, A5_1, A6_1, A7_1, A8_1, A9_1, A10_1, A11_1, A12_1, A13_1,
   A14_1, A15_1, A16_1, A17_1, A18_1, A19_1, A20_1, A21_1, A22_1, A23_1, A24_1}.

fast_round2({A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15, A16, A17, A18, A19, A20, A21, A22, A23, A24}, RC1) ->
  %% Round 2
  BC0_0 = A0 bxor A5 bxor A10 bxor A15 bxor A20,
  BC1_0 = A1 bxor A6 bxor A11 bxor A16 bxor A21,
  BC2_0 = A2 bxor A7 bxor A12 bxor A17 bxor A22,
  BC3_0 = A3 bxor A8 bxor A13 bxor A18 bxor A23,
  BC4_0 = A4 bxor A9 bxor A14 bxor A19 bxor A24,
  D0 = BC4_0 bxor ?ROTL64(BC1_0, 1),
  D1 = BC0_0 bxor ?ROTL64(BC2_0, 1),
  D2 = BC1_0 bxor ?ROTL64(BC3_0, 1),
  D3 = BC2_0 bxor ?ROTL64(BC4_0, 1),
  D4 = BC3_0 bxor ?ROTL64(BC0_0, 1),

  BC0_1 = A0 bxor D0,
  BC1_1 = ?ROTL64(A16 bxor D1, 44),
  BC2_1 = ?ROTL64(A7 bxor D2, 43),
  BC3_1 = ?ROTL64(A23 bxor D3, 21),
  BC4_1 = ?ROTL64(A14 bxor D4, 14),
  A0_1  = BC0_1 bxor ?CAN64(BC2_1, BC1_1) bxor RC1,
  A16_1 = BC1_1 bxor ?CAN64(BC3_1, BC2_1),
  A7_1  = BC2_1 bxor ?CAN64(BC4_1, BC3_1),
  A23_1 = BC3_1 bxor ?CAN64(BC0_1, BC4_1),
  A14_1 = BC4_1 bxor ?CAN64(BC1_1, BC0_1),

  BC2_2 = ?ROTL64(A20 bxor D0, 3),
  BC3_2 = ?ROTL64(A11 bxor D1, 45),
  BC4_2 = ?ROTL64(A2 bxor D2, 61),
  BC0_2 = ?ROTL64(A18 bxor D3, 28),
  BC1_2 = ?ROTL64(A9 bxor D4, 20),
  A20_1 = BC0_2 bxor ?CAN64(BC2_2, BC1_2),
  A11_1 = BC1_2 bxor ?CAN64(BC3_2, BC2_2),
  A2_1  = BC2_2 bxor ?CAN64(BC4_2, BC3_2),
  A18_1 = BC3_2 bxor ?CAN64(BC0_2, BC4_2),
  A9_1  = BC4_2 bxor ?CAN64(BC1_2, BC0_2),

  BC4_3 = ?ROTL64(A15 bxor D0, 18),
  BC0_3 = ?ROTL64(A6 bxor D1, 1),
  BC1_3 = ?ROTL64(A22 bxor D2, 6),
  BC2_3 = ?ROTL64(A13 bxor D3, 25),
  BC3_3 = ?ROTL64(A4 bxor D4, 8),
  A15_1 = BC0_3 bxor ?CAN64(BC2_3, BC1_3),
  A6_1  = BC1_3 bxor ?CAN64(BC3_3, BC2_3),
  A22_1 = BC2_3 bxor ?CAN64(BC4_3, BC3_3),
  A13_1 = BC3_3 bxor ?CAN64(BC0_3, BC4_3),
  A4_1  = BC4_3 bxor ?CAN64(BC1_3, BC0_3),

  BC1_4 = ?ROTL64(A10 bxor D0, 36),
  BC2_4 = ?ROTL64(A1 bxor D1, 10),
  BC3_4 = ?ROTL64(A17 bxor D2, 15),
  BC4_4 = ?ROTL64(A8 bxor D3, 56),
  BC0_4 = ?ROTL64(A24 bxor D4, 27),
  A10_1 = BC0_4 bxor ?CAN64(BC2_4, BC1_4),
  A1_1  = BC1_4 bxor ?CAN64(BC3_4, BC2_4),
  A17_1 = BC2_4 bxor ?CAN64(BC4_4, BC3_4),
  A8_1  = BC3_4 bxor ?CAN64(BC0_4, BC4_4),
  A24_1 = BC4_4 bxor ?CAN64(BC1_4, BC0_4),

  BC3_5 = ?ROTL64(A5 bxor D0, 41),
  BC4_5 = ?ROTL64(A21 bxor D1, 2),
  BC0_5 = ?ROTL64(A12 bxor D2, 62),
  BC1_5 = ?ROTL64(A3 bxor D3, 55),
  BC2_5 = ?ROTL64(A19 bxor D4, 39),
  A5_1  = BC0_5 bxor ?CAN64(BC2_5, BC1_5),
  A21_1 = BC1_5 bxor ?CAN64(BC3_5, BC2_5),
  A12_1 = BC2_5 bxor ?CAN64(BC4_5, BC3_5),
  A3_1  = BC3_5 bxor ?CAN64(BC0_5, BC4_5),
  A19_1 = BC4_5 bxor ?CAN64(BC1_5, BC0_5),

  {A0_1, A1_1, A2_1, A3_1, A4_1, A5_1, A6_1, A7_1, A8_1, A9_1, A10_1, A11_1, A12_1, A13_1,
   A14_1, A15_1, A16_1, A17_1, A18_1, A19_1, A20_1, A21_1, A22_1, A23_1, A24_1}.

fast_round3({A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15, A16, A17, A18, A19, A20, A21, A22, A23, A24}, RC2) ->
  %% Round 3
  BC0_0 = A0 bxor A5 bxor A10 bxor A15 bxor A20,
  BC1_0 = A1 bxor A6 bxor A11 bxor A16 bxor A21,
  BC2_0 = A2 bxor A7 bxor A12 bxor A17 bxor A22,
  BC3_0 = A3 bxor A8 bxor A13 bxor A18 bxor A23,
  BC4_0 = A4 bxor A9 bxor A14 bxor A19 bxor A24,
  D0 = BC4_0 bxor ?ROTL64(BC1_0, 1),
  D1 = BC0_0 bxor ?ROTL64(BC2_0, 1),
  D2 = BC1_0 bxor ?ROTL64(BC3_0, 1),
  D3 = BC2_0 bxor ?ROTL64(BC4_0, 1),
  D4 = BC3_0 bxor ?ROTL64(BC0_0, 1),

  BC0_1 = A0 bxor D0,
  BC1_1 = ?ROTL64(A11 bxor D1, 44),
  BC2_1 = ?ROTL64(A22 bxor D2, 43),
  BC3_1 = ?ROTL64(A8 bxor D3, 21),
  BC4_1 = ?ROTL64(A19 bxor D4, 14),
  A0_1  = BC0_1 bxor ?CAN64(BC2_1, BC1_1) bxor RC2,
  A11_1 = BC1_1 bxor ?CAN64(BC3_1, BC2_1),
  A22_1 = BC2_1 bxor ?CAN64(BC4_1, BC3_1),
  A8_1  = BC3_1 bxor ?CAN64(BC0_1, BC4_1),
  A19_1 = BC4_1 bxor ?CAN64(BC1_1, BC0_1),

  BC2_2 = ?ROTL64(A15 bxor D0, 3),
  BC3_2 = ?ROTL64(A1 bxor D1, 45),
  BC4_2 = ?ROTL64(A12 bxor D2, 61),
  BC0_2 = ?ROTL64(A23 bxor D3, 28),
  BC1_2 = ?ROTL64(A9 bxor D4, 20),
  A15_1 = BC0_2 bxor ?CAN64(BC2_2, BC1_2),
  A1_1  = BC1_2 bxor ?CAN64(BC3_2, BC2_2),
  A12_1 = BC2_2 bxor ?CAN64(BC4_2, BC3_2),
  A23_1 = BC3_2 bxor ?CAN64(BC0_2, BC4_2),
  A9_1  = BC4_2 bxor ?CAN64(BC1_2, BC0_2),

  BC4_3 = ?ROTL64(A5 bxor D0, 18),
  BC0_3 = ?ROTL64(A16 bxor D1, 1),
  BC1_3 = ?ROTL64(A2 bxor D2, 6),
  BC2_3 = ?ROTL64(A13 bxor D3, 25),
  BC3_3 = ?ROTL64(A24 bxor D4, 8),
  A5_1  = BC0_3 bxor ?CAN64(BC2_3, BC1_3),
  A16_1 = BC1_3 bxor ?CAN64(BC3_3, BC2_3),
  A2_1  = BC2_3 bxor ?CAN64(BC4_3, BC3_3),
  A13_1 = BC3_3 bxor ?CAN64(BC0_3, BC4_3),
  A24_1 = BC4_3 bxor ?CAN64(BC1_3, BC0_3),

  BC1_4 = ?ROTL64(A20 bxor D0, 36),
  BC2_4 = ?ROTL64(A6 bxor D1, 10),
  BC3_4 = ?ROTL64(A17 bxor D2, 15),
  BC4_4 = ?ROTL64(A3 bxor D3, 56),
  BC0_4 = ?ROTL64(A14 bxor D4, 27),
  A20_1 = BC0_4 bxor ?CAN64(BC2_4, BC1_4),
  A6_1  = BC1_4 bxor ?CAN64(BC3_4, BC2_4),
  A17_1 = BC2_4 bxor ?CAN64(BC4_4, BC3_4),
  A3_1  = BC3_4 bxor ?CAN64(BC0_4, BC4_4),
  A14_1 = BC4_4 bxor ?CAN64(BC1_4, BC0_4),

  BC3_5 = ?ROTL64(A10 bxor D0, 41),
  BC4_5 = ?ROTL64(A21 bxor D1, 2),
  BC0_5 = ?ROTL64(A7 bxor D2, 62),
  BC1_5 = ?ROTL64(A18 bxor D3, 55),
  BC2_5 = ?ROTL64(A4 bxor D4, 39),
  A10_1 = BC0_5 bxor ?CAN64(BC2_5, BC1_5),
  A21_1 = BC1_5 bxor ?CAN64(BC3_5, BC2_5),
  A7_1  = BC2_5 bxor ?CAN64(BC4_5, BC3_5),
  A18_1 = BC3_5 bxor ?CAN64(BC0_5, BC4_5),
  A4_1  = BC4_5 bxor ?CAN64(BC1_5, BC0_5),

  {A0_1, A1_1, A2_1, A3_1, A4_1, A5_1, A6_1, A7_1, A8_1, A9_1, A10_1, A11_1, A12_1, A13_1,
   A14_1, A15_1, A16_1, A17_1, A18_1, A19_1, A20_1, A21_1, A22_1, A23_1, A24_1}.

fast_round4({A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15, A16, A17, A18, A19, A20, A21, A22, A23, A24}, RC3) ->
  %% Round 4
  BC0_0 = A0 bxor A5 bxor A10 bxor A15 bxor A20,
  BC1_0 = A1 bxor A6 bxor A11 bxor A16 bxor A21,
  BC2_0 = A2 bxor A7 bxor A12 bxor A17 bxor A22,
  BC3_0 = A3 bxor A8 bxor A13 bxor A18 bxor A23,
  BC4_0 = A4 bxor A9 bxor A14 bxor A19 bxor A24,
  D0 = BC4_0 bxor ?ROTL64(BC1_0, 1),
  D1 = BC0_0 bxor ?ROTL64(BC2_0, 1),
  D2 = BC1_0 bxor ?ROTL64(BC3_0, 1),
  D3 = BC2_0 bxor ?ROTL64(BC4_0, 1),
  D4 = BC3_0 bxor ?ROTL64(BC0_0, 1),

  BC0_1 = A0 bxor D0,
  BC1_1 = ?ROTL64(A1 bxor D1, 44),
  BC2_1 = ?ROTL64(A2 bxor D2, 43),
  BC3_1 = ?ROTL64(A3 bxor D3, 21),
  BC4_1 = ?ROTL64(A4 bxor D4, 14),
  A0_1 = BC0_1 bxor ?CAN64(BC2_1, BC1_1) bxor RC3,
  A1_1 = BC1_1 bxor ?CAN64(BC3_1, BC2_1),
  A2_1 = BC2_1 bxor ?CAN64(BC4_1, BC3_1),
  A3_1 = BC3_1 bxor ?CAN64(BC0_1, BC4_1),
  A4_1 = BC4_1 bxor ?CAN64(BC1_1, BC0_1),

  BC2_2 = ?ROTL64(A5 bxor D0, 3),
  BC3_2 = ?ROTL64(A6 bxor D1, 45),
  BC4_2 = ?ROTL64(A7 bxor D2, 61),
  BC0_2 = ?ROTL64(A8 bxor D3, 28),
  BC1_2 = ?ROTL64(A9 bxor D4, 20),
  A5_1 = BC0_2 bxor ?CAN64(BC2_2, BC1_2),
  A6_1 = BC1_2 bxor ?CAN64(BC3_2, BC2_2),
  A7_1 = BC2_2 bxor ?CAN64(BC4_2, BC3_2),
  A8_1 = BC3_2 bxor ?CAN64(BC0_2, BC4_2),
  A9_1 = BC4_2 bxor ?CAN64(BC1_2, BC0_2),

  BC4_3 = ?ROTL64(A10 bxor D0, 18),
  BC0_3 = ?ROTL64(A11 bxor D1, 1),
  BC1_3 = ?ROTL64(A12 bxor D2, 6),
  BC2_3 = ?ROTL64(A13 bxor D3, 25),
  BC3_3 = ?ROTL64(A14 bxor D4, 8),
  A10_1 = BC0_3 bxor ?CAN64(BC2_3, BC1_3),
  A11_1 = BC1_3 bxor ?CAN64(BC3_3, BC2_3),
  A12_1 = BC2_3 bxor ?CAN64(BC4_3, BC3_3),
  A13_1 = BC3_3 bxor ?CAN64(BC0_3, BC4_3),
  A14_1 = BC4_3 bxor ?CAN64(BC1_3, BC0_3),

  BC1_4 = ?ROTL64(A15 bxor D0, 36),
  BC2_4 = ?ROTL64(A16 bxor D1, 10),
  BC3_4 = ?ROTL64(A17 bxor D2, 15),
  BC4_4 = ?ROTL64(A18 bxor D3, 56),
  BC0_4 = ?ROTL64(A19 bxor D4, 27),
  A15_1 = BC0_4 bxor ?CAN64(BC2_4, BC1_4),
  A16_1 = BC1_4 bxor ?CAN64(BC3_4, BC2_4),
  A17_1 = BC2_4 bxor ?CAN64(BC4_4, BC3_4),
  A18_1 = BC3_4 bxor ?CAN64(BC0_4, BC4_4),
  A19_1 = BC4_4 bxor ?CAN64(BC1_4, BC0_4),

  BC3_5 = ?ROTL64(A20 bxor D0, 41),
  BC4_5 = ?ROTL64(A21 bxor D1, 2),
  BC0_5 = ?ROTL64(A22 bxor D2, 62),
  BC1_5 = ?ROTL64(A23 bxor D3, 55),
  BC2_5 = ?ROTL64(A24 bxor D4, 39),
  A20_1 = BC0_5 bxor ?CAN64(BC2_5, BC1_5),
  A21_1 = BC1_5 bxor ?CAN64(BC3_5, BC2_5),
  A22_1 = BC2_5 bxor ?CAN64(BC4_5, BC3_5),
  A23_1 = BC3_5 bxor ?CAN64(BC0_5, BC4_5),
  A24_1 = BC4_5 bxor ?CAN64(BC1_5, BC0_5),

  {A0_1, A1_1, A2_1, A3_1, A4_1, A5_1, A6_1, A7_1, A8_1, A9_1, A10_1, A11_1, A12_1, A13_1,
   A14_1, A15_1, A16_1, A17_1, A18_1, A19_1, A20_1, A21_1, A22_1, A23_1, A24_1}.
