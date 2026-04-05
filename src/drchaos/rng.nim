## Small xorshift-based RNG for mutation decisions.

type
  Rand* = object
    state*: uint64

proc initRand*(seed: uint32): Rand =
  ## Initializes a random generator from `seed`.
  result = Rand(state: uint64(seed) xor 0x9e3779b97f4a7c15'u64)
  if result.state == 0:
    result.state = 0x2545f4914f6cdd1d'u64

proc nextUint64*(r: var Rand): uint64 =
  ## Advances the generator and returns the next 64-bit value.
  var x = r.state
  x = x xor (x shl 13)
  x = x xor (x shr 7)
  x = x xor (x shl 17)
  r.state = x
  result = x

proc randBool*(r: var Rand): bool =
  ## Returns a pseudo-random boolean.
  result = (r.nextUint64() and 1'u64) == 1'u64

proc randInt*(r: var Rand; highInclusive: int): int =
  ## Returns a pseudo-random integer in `0..highInclusive`.
  if highInclusive <= 0:
    result = 0
  else:
    result = int(r.nextUint64() mod uint64(highInclusive + 1))

proc randInt*(r: var Rand; lowInclusive, highInclusive: int): int =
  ## Returns a pseudo-random integer in `lowInclusive..highInclusive`.
  if highInclusive <= lowInclusive:
    result = lowInclusive
  else:
    result = lowInclusive + r.randInt(highInclusive - lowInclusive)
