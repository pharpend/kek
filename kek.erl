%% @doc
%% References
%% 1. Helpful lecture: https://www.youtube.com/watch?v=JWskjzgiIa4
%%    Notes: https://www.crypto-textbook.com/download/Understanding-Cryptography-Keccak.pdf
%% 2. NIST standard: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
%%    (btw: the double bar notation means "concatenate")
%% 3. https://en.wikipedia.org/wiki/SHA-3
%% @end
-module(kek).

% theta and rho steps are done

-compile(export_all).


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
    ShaMessage = <<Message/bitstring, (2#01):2>>,
    keccak(Capacity, ShaMessage, OutputBitLength).



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
    ShakeMessage = <<Message/bitstring, (2#1111):4>>,
    keccak(Capacity, ShakeMessage, OutputBitLength).



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

-spec keccak(Capacity, Message, OutputBitLength) -> Digest
    when Capacity        :: pos_integer(),
         Message         :: bitstring(),
         OutputBitLength :: pos_integer(),
         Digest          :: bitstring().
%% @doc
%% Note: this is Keccak 1600, the only one used in practice
%%
%% Capacity must be strictly less than 1600
%% @end

keccak(Capacity = _c, Message, OutputBitLength) ->
    BitRate       = 1600 - Capacity,
    PaddedMessage = pad(Message, BitRate),
    InitialSponge = <<0:1600>>,
    WetSponge     = absorb(PaddedMessage, BitRate, Capacity, InitialSponge),
    ResultBits    = squeeze(WetSponge, OutputBitLength, BitRate),
    ResultBits.



-spec pad(Message, BitRate) -> NewMessage
    when Message    :: bitstring(),
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

% note: rem will always return a positive integer because both bit_size
% case when the message bit length is evenly divisible by the bit rate
% in this case we add a whole new r-word
pad(Message, BitRate = _r) when (bit_size(Message) rem BitRate) =:= 0 ->
    % Suppose the BitRate was 8 and we had 0 bits left
    % Input:
    %   Bits: <<>>
    %   Idx1: 12345678
    % Result:
    %   Bits: 10000001
    %   Idx1: 12345678
    % In this case we add a new r-word
    NewRWord   = <<1:1, 0:(BitRate - 2), 1:1>>,
    NewMessage = <<Message/bitstring, NewRWord/bitstring>>,
    NewMessage;
% this is the retarded case, when the bit length of the message is exactly one
% bit less than dividing the BitRate
pad(Message, BitRate = _r) when (bit_size(Message) rem BitRate) =:= (BitRate - 1) ->
    % Suppose the BitRate was 8 and we had 7 bits left
    % Input:
    %   Bits: ABCDEFG
    %   Idx1: 12345678
    % Result:
    %   Bits: ABCDEFG1 00000001
    %   Idx1: 12345678 12345678
    % in this case, we add a 1, (r-1) zeros, and a trailing 1
    NewRWord   = <<1:1, 0:(BitRate - 1), 1:1>>,
    NewMessage = <<Message/bitstring, NewRWord/bitstring>>,
    NewMessage;
% this is the general case, where there are at least 2 bits left in order to
% fill out the r-word
pad(Message, BitRate = _r) ->
    % Suppose the BitRate was 8 and we had 3 bits left
    % Input:
    %   Bits: ABC
    %   Idx1: 12345678
    % Result:
    %   Bits: ABC10001
    %   Idx1: 12345678
    NumberOfMessageBitsInTheLastRWord = bit_size(Message) rem BitRate,
    NumberOfNewBitsNeeded             = BitRate - NumberOfMessageBitsInTheLastRWord,
    NumberOfNewZerosNeeded            = NumberOfNewBitsNeeded - 2,
    NewMessage                        = <<Message/bitstring, 1:1, 0:NumberOfNewZerosNeeded, 1:1>>,
    NewMessage.



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
%%% In "inner keccak", the input array is thought of as a 5x5x64 3D array. The
%%% coordinate system is described in its own section.
%%%
%%% TODO: iota depends on the round index, so this code may need to be altered
%%% slightly.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

-spec inner_keccak(Sponge) -> NewSponge
    when Sponge    :: <<_:1600>>,
         NewSponge :: <<_:1600>>.
%% @private
%% the "inner keccak" function, or the 'f' function
%% a bunch of bit bullshit
%% @end

inner_keccak(Sponge) ->
    rounds(Sponge, 24).


-spec rounds(Sponge, NumRoundsLeft) -> ResultSponge
    when Sponge        :: <<_:1600>>,
         NumRoundsLeft :: non_neg_integer(),
         ResultSponge  :: <<_:1600>>.
%% @private
%% do however many rounds
%% @end

rounds(Sponge, NumRoundsLeft) when 1 =< NumRoundsLeft ->
    NewSponge        = rnd(Sponge),
    NewNumRoundsLeft = NumRoundsLeft - 1,
    rounds(NewSponge, NewNumRoundsLeft);
% no rounds left
rounds(FinalSponge, 0) ->
    FinalSponge.



-spec rnd(Sponge) -> NewSponge
    when Sponge    :: <<_:1600>>,
         NewSponge :: <<_:1600>>.
%% @private
%% do a single round
%% @private

rnd(Sponge) ->
    iota(chi(pi(rho(theta(Sponge))))).



%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% THETA STEP
%%
%% For each bit in the input array,
%% 1. take
%%    - the bit
%%    - the 5-bit column to the left
%%    - the 5-bit column to the front right
%% 2. compute the parity of their concatenation (0 if even# of 1s, 1 if odd# of
%%    1s)
%% 3. set the bit to that parity value
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

-spec theta(Array) -> NewArray
    when Array    :: <<_:1600>>,
         NewArray :: <<_:1600>>.
%% @private
%% the theta step
%% go bit by bit, applying a weird transformation to each bit
%% @end

theta(Array) ->
    theta(Array, 0).



-spec theta(Array, Idx0) -> NewArray
    when Array    :: <<_:1600>>,
         Idx0     :: 0..1599,
         NewArray :: <<_:1600>>.
%% @private
%% the theta step
%% go bit by bit, applying a weird transformation to each bit
%% @end

% done
theta(ResultArray, 1600) ->
    ResultArray;
% do the weird permutation
% x = left/right             -/+
% y = down/up                -/+
% z = outOfScreen/intoScreen -/+
%     front/behind           -/+
% left-handed coordinate system but what can you do
theta(ArrayBits, ThisIdx0) ->
    <<Before:ThisIdx0, ThisBit:1, Rest/bitstring>> = ArrayBits,
    {xyz, ThisX, _ThisY, ThisZ} = idx0_to_xyz(ThisIdx0),
    XToTheLeft                  = left(ThisX),
    XToTheRight                 = right(ThisX),
    ZToTheFront                 = front(ThisZ),
    ColumnToTheLeft             = xzth({xz, XToTheLeft, ThisZ}, ArrayBits),
    ColumnToTheFrontRight       = xzth({xz, XToTheRight, ZToTheFront}, ArrayBits),
    NewBit                      = parity(<<ColumnToTheLeft/bitstring, ColumnToTheFrontRight/bitstring, ThisBit:1>>),
    NewBits                     = <<Before:ThisIdx0, NewBit:1, Rest/bitstring>>,
    NewIdx0                     = ThisIdx0 + 1,
    theta(NewBits, NewIdx0).



-spec parity(Bits) -> Parity
    when Bits   :: bitstring(),
         Parity :: 0 | 1.
%% @private
%% Count the number of 1s in the given bitstring. Return 0 if even, 1 if odd.
%% @end

parity(Bits) ->
    parity(Bits, 0).

parity(<<0:1, Rest/bitstring>>, NOnes) -> parity(Rest, NOnes);
parity(<<1:1, Rest/bitstring>>, NOnes) -> parity(Rest, NOnes + 1);
parity(<<>>                   , NOnes) -> NOnes rem 2.



%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% RHO STEP
%%
%% This step applies an affine shift to each 64-bit "lane" (fixed X,Y; Z ranges
%% from 0 to 63).
%%
%% The amount of the shift is given by the "offset" table.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

-spec rho(Array) -> NewArray
    when    Array :: <<_:1600>>,
         NewArray :: <<_:1600>>.
%% @private
%% do the rho step
%% @end

rho(Array) ->
    rho(Array, {xy, 0, 0}).



-spec rho(Array, LaneXY) -> NewArray
    when Array    :: <<_:1600>>,
         LaneXY   :: {xy, 0..4, 0..4},
         NewArray :: <<_:1600>>.
%% @private
%% do the rho step to each lane
%% @end

% terminal case
rho(Array, XY = {xy, 4, 4}) ->
    Result = rhoxy(Array, XY),
    Result;
% need to reset Y and increment X
rho(Array, XY = {xy, X, 4}) ->
    NewArray = rhoxy(Array, XY),
    NewXY    = {xy, X + 1, 0},
    rho(NewArray, NewXY);
% need to increment Y and leave X
rho(Array, XY = {xy, X, Y}) ->
    NewArray = rhoxy(Array, XY),
    NewXY    = {xy, X, Y + 1},
    rho(NewArray, NewXY).



-spec rhoxy(Array1600, LaneXY) -> NewArray1600
    when Array1600    :: <<_:1600>>,
         LaneXY       :: {xy, 0..4, 0..4},
         NewArray1600 :: <<_:1600>>.
%% @private
%% do the rho step to a given lane
%% @end

rhoxy(Array, ThisXY = {xy, ThisX, ThisY}) ->
    ThisOffset = offset(ThisX, ThisY),
    ThisLane   = xyth(ThisXY, Array),
    % we increase the z coordinate by the offset
    % Suppose the offset is 2
    %      bits = A B C D E
    %         z = 0 1 2 3 4
    %   newbits = D E A B C
    % in other words, we take Offset number of bits off the tail of the lane
    % put them on the front
    <<Foo:(64 - ThisOffset), Bar:ThisOffset>> = ThisLane,
    NewLane  = <<Bar:ThisOffset, Foo:(64 - ThisOffset)>>,
    NewArray = xyset(ThisXY, Array, NewLane),
    NewArray.



-spec offset(X, Y) -> Offset
    when X      :: 0..4,
         Y      :: 0..4,
         Offset :: 0..63.
%% @private
%% See NIST specification, pg. 21
%% @end

offset(3, 2) -> 153 rem 64;
offset(3, 1) ->  55 rem 64;
offset(3, 0) ->  28 rem 64;
offset(3, 4) -> 120 rem 64;
offset(3, 3) ->  21 rem 64;

offset(4, 2) -> 231 rem 64;
offset(4, 1) -> 276 rem 64;
offset(4, 0) ->  91 rem 64;
offset(4, 4) ->  78 rem 64;
offset(4, 3) -> 136 rem 64;


offset(0, 2) ->   3 rem 64;
offset(0, 1) ->  36 rem 64;
offset(0, 0) ->   0 rem 64;
offset(0, 4) -> 210 rem 64;
offset(0, 3) -> 105 rem 64;

offset(1, 2) ->  10 rem 64;
offset(1, 1) -> 300 rem 64;
offset(1, 0) ->   1 rem 64;
offset(1, 4) ->  66 rem 64;
offset(1, 3) ->  45 rem 64;

offset(2, 2) -> 171 rem 64;
offset(2, 1) ->   6 rem 64;
offset(2, 0) -> 190 rem 64;
offset(2, 4) -> 253 rem 64;
offset(2, 3) ->  15 rem 64.



%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% PI STEP
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

-spec pi(Array1600) -> NewArray1600
    when Array1600    :: <<_:1600>>,
         NewArray1600 :: <<_:1600>>.
%% @private
%% The effect of this step is to rearrange the lanes
%%
%% Result[X, Y] = Input[X + 3*Y, X]
%%
%% (mod 5 of course)
%% @end

pi(Array1600) ->
    % what I'm going to make is a map #{{xy, X, Y} := Lane}
    % then make a new map from the which applies the coordinate transformation
    % then convert it back into an array
    OriginalLaneMap = lane_map(Array1600, #{}, {xy, 0, 0}),
    NewLaneMap      = new_lane_map(OriginalLaneMap, #{}, {xy, 0, 0}),
    NewArray1600    = lane_map_to_arr1600(NewLaneMap, <<0:1600>>, {xy, 0, 0}),
    NewArray1600.



-spec lane_map(Array1600, MapAcc, Coord) -> LaneMap
    when Array1600 :: <<_:1600>>,
         MapAcc    :: #{XY := Lane},
         Coord     :: XY,
         LaneMap   :: #{XY := Lane},
         XY        :: {xy, X :: 0..4, Y :: 0..4},
         Lane      :: <<_:64>>.
%% @private
%% Make a map #{XY := Lane}
%% @end

% terminal case, end of array
lane_map(Array1600, MapAcc, ThisXY = {xy, 4, 4}) ->
    ThisLane = xyth(ThisXY, Array1600),
    FinalMap = MapAcc#{ThisXY => ThisLane},
    FinalMap;
% end of Y value, set Y to 0 and increment X
lane_map(Array1600, MapAcc, ThisXY = {xy, X, 4}) ->
    ThisLane  = xyth(ThisXY, Array1600),
    NewMapAcc = MapAcc#{ThisXY => ThisLane},
    NewXY     = {xy, X + 1, 0},
    lane_map(Array1600, NewMapAcc, NewXY);
% general case: increment Y value
lane_map(Array1600, MapAcc, ThisXY = {xy, X, Y}) ->
    ThisLane  = xyth(ThisXY, Array1600),
    NewMapAcc = MapAcc#{ThisXY => ThisLane},
    NewXY     = {xy, X, Y + 1},
    lane_map(Array1600, NewMapAcc, NewXY).



-spec new_lane_map(LaneMap, MapAcc, Coord) -> NewLaneMap
    when LaneMap    :: #{XY := Lane},
         MapAcc     :: LaneMap,
         Coord      :: XY,
         NewLaneMap :: LaneMap,
         XY         :: {xy, X :: 0..4, Y :: 0..4},
         Lane       :: <<_:64>>.
%% @private
%% The effect of this step is to rearrange the lanes
%%
%% Result[X, Y] = Input[X + 3*Y, X]
%%
%% (mod 5 of course)
%% @end

% terminal case, end of array
new_lane_map(OrigLaneMap, MapAcc, ThisXY = {xy, 4, 4}) ->
    OrigXY   = xytrans(ThisXY),
    ThisLane = maps:get(OrigXY, OrigLaneMap),
    FinalMap = MapAcc#{ThisXY => ThisLane},
    FinalMap;
% end of Y value, set Y to 0 and increment X
new_lane_map(OrigLaneMap, MapAcc, ThisXY = {xy, X, 4}) ->
    OrigXY    = xytrans(ThisXY),
    ThisLane  = maps:get(OrigXY, OrigLaneMap),
    NewMapAcc = MapAcc#{ThisXY => ThisLane},
    NewXY     = {xy, X + 1, 0},
    new_lane_map(OrigLaneMap, NewMapAcc, NewXY);
% general case: increment Y value
new_lane_map(OrigLaneMap, MapAcc, ThisXY = {xy, X, Y}) ->
    OrigXY    = xytrans(ThisXY),
    ThisLane  = maps:get(OrigXY, OrigLaneMap),
    NewMapAcc = MapAcc#{ThisXY => ThisLane},
    NewXY     = {xy, X, Y + 1},
    new_lane_map(OrigLaneMap, NewMapAcc, NewXY).



-spec xytrans(ResultXY) -> InputXY
    when ResultXY :: XY,
         InputXY  :: XY,
         XY       :: {xy, X :: 0..4, Y :: 0..4}.
%% @private
%% Result[X, Y] = Input[X + 3*Y, X]
%%
%% See NIST doc, pp. 14

xytrans({xy, X, Y}) ->
    {xy, (X + 3*Y) rem 5, X}.



-spec lane_map_to_arr1600(LaneMap, Array1600Acc, Coord) -> Array1600
    when LaneMap      :: #{XY := Lane},
         Array1600Acc :: Array1600,
         Coord        :: XY,
         Array1600    :: <<_:1600>>,
         XY           :: {xy, X :: 0..4, Y :: 0..4},
         Lane         :: <<_:64>>.
%% @private
%% inverse of lane_map/3
%%
%% it would probably faster to concatenate an accumulator, but that requires
%% iterating in the correct order, and i'm more comfortable calling xyset/3
%% @end

% terminal case, end of array
lane_map_to_arr1600(LaneMap, Array1600Acc, ThisXY = {xy, 4, 4}) ->
    ThisLane          = maps:get(ThisXY, LaneMap),
    FinalArray1600Acc = xyset(ThisXY, Array1600Acc, ThisLane),
    FinalArray1600Acc;
% end of Y value, set Y to 0 and increment X
lane_map_to_arr1600(LaneMap, Array1600Acc, ThisXY = {xy, X, 4}) ->
    ThisLane        = maps:get(ThisXY, LaneMap),
    NewArray1600Acc = xyset(ThisXY, Array1600Acc, ThisLane),
    NewXY           = {xy, X + 1, 0},
    lane_map_to_arr1600(LaneMap, NewArray1600Acc, NewXY);
% general case: increment Y value
lane_map_to_arr1600(LaneMap, Array1600Acc, ThisXY = {xy, X, Y}) ->
    ThisLane        = maps:get(ThisXY, LaneMap),
    NewArray1600Acc = xyset(ThisXY, Array1600Acc, ThisLane),
    NewXY           = {xy, X, Y + 1},
    lane_map_to_arr1600(LaneMap, NewArray1600Acc, NewXY).



%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% CHI STEP
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%


-spec chi(Array1600) -> NewArray1600
    when Array1600    :: <<_:1600>>,
         NewArray1600 :: <<_:1600>>.
%% @private
%% The chi step. The following transformation is applied to each bit
%%
%% NewBit = lxor(Bit,
%%               land(lnot(BitToTheRight),
%%                    Bit2ToTheRight))

chi(Array1600) ->
    chi(Array1600, 0).



-spec chi(Array1600, Idx0) -> NewArray1600
    when Array1600    :: <<_:1600>>,
         Idx0         :: non_neg_integer(),
         NewArray1600 :: <<_:1600>>.
%% @private
%% The chi step. The following transformation is applied to each bit
%%
%% NewBit = lxor(Bit,
%%               land(lnot(BitToTheRight),
%%                    Bit2ToTheRight))
%%
%% FIXME: Could be made more efficient by operating on lanes

chi(Array1600, ThisIdx0) when 0 =< ThisIdx0, ThisIdx0 =< 1599 ->
    ThisXYZ      = {xyz,             ThisX  , ThisY, ThisZ} = idx0_to_xyz(ThisIdx0),
    RightXYZ     = {xyz,       right(ThisX) , ThisY, ThisZ},
    Right2XYZ    = {xyz, right(right(ThisX)), ThisY, ThisZ},
    ThisBit      = xyzth(ThisXYZ  , Array1600),
    RightBit     = xyzth(RightXYZ , Array1600),
    Right2Bit    = xyzth(Right2XYZ, Array1600),
    NewBit       = lxor(ThisBit,
                        land(lnot(RightBit),
                             Right2Bit)),
    NewArray1600 = xyzset(ThisXYZ, Array1600, NewBit),
    NewIdx0      = ThisIdx0 + 1,
    chi(NewArray1600, NewIdx0);
% terminal case
chi(Array1600, 1600) ->
    Array1600.



%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% IOTA STEP
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

iota(_Sponge) ->
    error(nyi).



%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% INNER KECCAK COORDINATE SYSTEM
%%%
%%% Inner Keccak thinks of the 1600-bit input array as a 5x5x64 3D array
%%% (5*5*64).  This section provides a variety of helper functions to talk about
%%% the array using the X,Y,Z coordinate system.
%%%
%%% The coordinate system is toroidal, meaning that each coordinate is "modded
%%% down" to be in the approprate range.  For instance, the X-coordinate "to the
%%% right" of X=4 is X=0. And likewise, the coordinate "behind" Z=63 is Z=0. See
%%% the section on directionality conventions.
%%%
%%% VOCABULARY:
%%%
%%% 3D state:
%%% - The [state] is the entire 5x5x24 array
%%%
%%% 0D subsets of the state:
%%% - A [bit] is a single bit in the array given by an X,Y,Z coordinate triple
%%%   (see xyzth/3).
%%% 
%%% 1D subsets of the state:
%%% - a [row]
%%%   - is a 5-bit array
%%%   - given by a Y,Z coordinate pair in range {0..4, 0..63} (see yzth/2)
%%%   - you should think of a row as being internally indexed with an X
%%%     coordinate ranging in 0..4
%%% - a [column]
%%%   - is a 5-bit array
%%%   - given by an X,Z coordinate pair in range {0..4, 0..63} (see xzth/2)
%%%   - you should think of a column as being internally indexed with a Y
%%%     coordinate ranging in 0..4
%%% - a [lane]
%%%   - is a 64-bit array
%%%   - given by an X,Y coordinate pair in range {0..4, 0..4} (see xyth/2)
%%%   - you should think of a lane as being internally indexed with a Z
%%%     coordinate ranging in 0..63.
%%%
%%% 2D subsets of the state:
%%% - a [sheet]
%%%   - is a 5x64 array
%%%   - given by a single X coordinate ranging in 0..4 (see xth/2)
%%%   - you should think of a sheet as being internally indexed by a Y,Z
%%%     coordinate pair ranging in {0..4, 0..63}.
%%% - a [plane]
%%%   - is a 5x64 array
%%%   - given by a single Y coordinate ranging in 0..4 (see yth/2)
%%%   - you should think of a plane as being internally indexed by a X,Z
%%%     coordinate pair ranging in {0..4, 0..63}.
%%% - a [slice]
%%%   - is a 5x5 array
%%%   - given by a single Z coordinate ranging in 0..63 (see zth/2)
%%%   - you should think of a sheet as being internally indexed by a X,Y
%%%     coordinate pair ranging in {0..4, 0..4}.
%%%
%%% PACKING CONVENTION:
%%%
%%% Each lane (64-bit long bitstring given by an {X,Y} <- {0..4, 0..4} coordinate
%%% pair and indexed by a Z <- 0..63 coordinate.
%%%
%%% DIRECTIONALITY CONVENTION:
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%



%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% CONVERTING BETWEEN XYZ-INDICES AND 0-INDICES
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

-spec idx0_to_xyz(Idx0) -> XYZ
    when Idx0 :: 0..1599,
         XYZ  :: {xyz, X :: 0..4, Y :: 0..4, Z :: 0..63}.
%% @private
%% Convert a 0-index to an XYZ-index
%% @end

idx0_to_xyz(Idx0) ->
    % it's sort of retarded endian notation
    % drunk endian notation
    %   YXZ
    % yes, that order
    % Z is in the range 0..63
    % X is in the range 0..4
    % Y is in the range 0..4
    {Q1, Z} = {Idx0 div 64, Idx0 rem 64},
    {Q2, X} = {  Q1 div  5,   Q1 rem  5},
    { 0, Y} = {  Q2 div  5,   Q2 rem  5},
    {xyz, X, Y, Z}.



-spec xyz_to_idx0(XYZ) -> Idx0
    when XYZ  :: {xyz, X :: 0..4, Y :: 0..4, Z :: 0..63},
         Idx0 :: 0..1599.
%% @private
%% Convert an XYZ-index into a 0-index
%% @end

xyz_to_idx0({xyz, X, Y, Z}) ->
    % reverse of the above
    % drunk endian notation
    %   YXZ
    % to get the "X place", multiply X by 64
    % to get the "Y place", multiply Y by 64*5
    Y*64*5 + X*64 + Z.



%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% DIRECTIONAL TRANSFORMATIONS ON SINGLE COORDINATE VALUES
%%
%% For instance, if you have an X-value and want to get the X-value "to the
%% left", this section contains functions that compute such things.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

-spec left(X) -> XToTheLeft
    when X          :: 0..4,
         XToTheLeft :: 0..4.
%% @private
%% x = left/right
%%        -/+
%% @end

left(0) -> 4;
left(1) -> 0;
left(2) -> 1;
left(3) -> 2;
left(4) -> 3.



-spec right(X) -> XToTheRight
    when X           :: 0..4,
         XToTheRight :: 0..4.
%% @private
%% x = left/right
%%        -/+
%% @end

right(0) -> 1;
right(1) -> 2;
right(2) -> 3;
right(3) -> 4;
right(4) -> 0.



-spec down(Y) -> YBelow
    when Y      :: 0..4,
         YBelow :: 0..4.
%% @private
%% y = down/up
%%        -/+
%% @end

down(0) -> 4;
down(1) -> 0;
down(2) -> 1;
down(3) -> 2;
down(4) -> 3.



-spec up(Y) -> YAbove
    when Y      :: 0..4,
         YAbove :: 0..4.
%% @private
%% y = down/up
%%        -/+
%% @end

up(0) -> 1;
up(1) -> 2;
up(2) -> 3;
up(3) -> 4;
up(4) -> 0.



-spec front(Z) -> ZInFront
    when Z        :: 0..63,
         ZInFront :: 0..63.
%% @private
%% z = front/behind
%%        -/+
%% @end

front(0)                      -> 63;
front(N) when 1 =< N, N =< 63 -> N - 1.



-spec behind(Z) -> ZBehind
    when Z       :: 0..63,
         ZBehind :: 0..63.
%% @private
%% z = front/behind
%%        -/+
%% @end

behind(N) when 0 =< N, N =< 62 -> N + 1;
behind(63)                     -> 0.



%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 0D BIT ACCESSORS
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

-spec xyzth(XYZ, Array1600) -> Bit
    when XYZ       :: {xyz, X, Y, Z},
         Array1600 :: <<_:1600>>,
         Bit       :: 0 | 1,
         X         :: 0..4,
         Y         :: 0..4,
         Z         :: 0..63.
%% @private
%% Fetch the bit at the given X, Y, Z coordinate triple
%% @end

xyzth(XYZ, Array1600) ->
    Idx0 = xyz_to_idx0(XYZ),
    <<_Skip:Idx0, Bit:1, _Rest/bitstring>> = Array1600,
    Bit.



-spec xyzset(XYZ, Array1600, NewBit) -> NewArray1600
    when XYZ          :: {xyz, X, Y, Z},
         Array1600    :: <<_:1600>>,
         NewBit       :: 0 | 1,
         NewArray1600 :: Array1600,
         X            :: 0..4,
         Y            :: 0..4,
         Z            :: 0..63.
%% @private
%% Replace the bit at {X, Y, Z} with the new bit
%% @end

xyzset(XYZ, Array1600, NewBit) ->
    Idx0 = xyz_to_idx0(XYZ),
    <<Pre:Idx0, _Bit:1, Post/bitstring>> = Array1600,
    <<Pre:Idx0, NewBit:1, Post/bitstring>>.



%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% 1D SUBSET ACCESSORS
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

-spec xzth(XZ, Bits) -> Column
    when XZ     :: {xz, X, Z},
         X      :: 0..4,
         Z      :: 0..63,
         Bits   :: <<_:1600>>,
         Column :: <<_:5>>.
%% @private
%% Fetch the column at the given X, Z coordinate pair
%% @end

xzth({xz, X, Z}, Bits) ->
    % just grab them one at a time
    << <<( xyzth({xyz, X, Y, Z}, Bits) ):1>>
    || Y <- lists:seq(0, 4)
    >>.



-spec xyth(XY, Array1600) -> Lane
    when XY        :: {xy, X, Y},
         Array1600 :: <<_:1600>>,
         Lane      :: <<_:64>>,
         X         :: 0..4,
         Y         :: 0..4.
%% @private
%% Grab the lane at the given X, Y coordinate pair.
%% @end

xyth({xy, X, Y}, Array1600) ->
    << <<( xyzth({xyz, X, Y, Z}, Array1600) ):1>>
    || Z <- lists:seq(0, 63)
    >>.



-spec xyset(LaneXY, Array1600, NewLane) -> NewArray1600
    when Array1600    :: <<_:1600>>,
         LaneXY       :: {xy, 0..4, 0..4},
         NewLane      :: <<_:64>>,
         NewArray1600 :: <<_:1600>>.
%% @private
%% Take the original array, and swap out the lane at the given x,y coordinate
%% with the new given lane.
%%
%% The lane will be represented continuously so we can do a hack
%% @end

% special case when it's the last lane
% grab the final 64 bits off the original array and replace them with the new lane
xyset(_LaneXY = {xy, 4, 4}, <<Pre:(1600 - 64), _:64>>, NewLane) ->
    <<Pre:(1600 - 64), NewLane/bitstring>>;
% general case, grab the shit before the lane, grab the shit after the lane
% replace the shit in the middle
xyset(_LaneXY = {xy, LaneX, LaneY}, OriginalArray, NewLane) ->
    FirstBitOfLane_Idx0    = xyz_to_idx0({xyz, LaneX, LaneY, 0}),
    FirstBitAfterLane_Idx0 = xyz_to_idx0({xyz, LaneX, LaneY, 63}) + 1,
    NumberOfBitsBeforeTheLane    = FirstBitOfLane_Idx0,
    NumberOfBitsIncludingTheLane = FirstBitAfterLane_Idx0,
    <<PreLane:NumberOfBitsBeforeTheLane   ,         _/bitstring>> = OriginalArray,
    <<      _:NumberOfBitsIncludingTheLane, AfterLane/bitstring>> = OriginalArray,
    Result = <<PreLane:NumberOfBitsBeforeTheLane, NewLane/bitstring, AfterLane/bitstring>>,
    Result.
