## Generic harness and LibFuzzer ABI helpers.

import codec, model, mutator, schema

type
  BytePtr* = ptr UncheckedArray[byte]

  FuzzTargetProc*[T] = proc (input: T) {.nimcall.}

  FuzzHarness*[T] = object
    target*: FuzzTargetProc[T]
    config*: FuzzConfig
    schema*: SchemaNode
    cacheBytes*: seq[byte]
    cacheValue*: T
    hasCache*: bool

proc sameBytes(current: seq[byte]; incoming: openArray[byte]): bool =
  if current.len != incoming.len:
    return false
  for i in 0..<current.len:
    if current[i] != incoming[i]:
      return false
  result = true

proc copyBytes(data: openArray[byte]): seq[byte] =
  result = newSeq[byte](data.len)
  for i in 0..<data.len:
    result[i] = data[i]

proc trimBytes(data: var seq[byte]; newLen: int) =
  let limit = min(newLen, data.len)
  var resized = newSeq[byte](limit)
  for i in 0..<limit:
    resized[i] = data[i]
  data = resized

proc bytesFromPtr*(data: BytePtr; len: int): seq[byte] =
  ## Copies `len` bytes from `data` into a Nim sequence.
  result = newSeq[byte](len)
  for i in 0..<len:
    result[i] = data[i]

proc writeBytesToPtr*(dest: BytePtr; data: openArray[byte]): int =
  ## Copies `data` into `dest` and returns the written byte count.
  for i in 0..<data.len:
    dest[i] = data[i]
  result = data.len

proc initHarness*[T](target: FuzzTargetProc[T]; config: FuzzConfig): FuzzHarness[T] {.untyped.} =
  ## Initializes a typed fuzz harness.
  result = FuzzHarness[T](
    target: target,
    config: config,
    schema: schemaFor(T),
    cacheBytes: @[],
    cacheValue: default(T),
    hasCache: false
  )

proc loadCachedOrDecode[T](harness: var FuzzHarness[T]; data: openArray[byte];
    value: var T): bool {.untyped.} =
  if harness.hasCache and sameBytes(harness.cacheBytes, data):
    value = harness.cacheValue
    result = true
  else:
    result = tryDecodeInput(data, value)
    if result:
      harness.cacheBytes = copyBytes(data)
      harness.cacheValue = value
      harness.hasCache = true

proc testOneInput*[T](harness: var FuzzHarness[T]; data: openArray[byte]): cint {.
    untyped.} =
  ## Executes the fuzz target for one encoded structured input.
  var input = default(T)
  if loadCachedOrDecode(harness, data, input):
    harness.target(input)
  result = 0

proc customMutator*[T](harness: var FuzzHarness[T];
    data: openArray[byte]; maxLen: int; seed: uint32): seq[byte] {.untyped.} =
  ## Mutates an encoded structured input and returns the new bytes.
  var current = default(T)
  if not loadCachedOrDecode(harness, data, current):
    current = default(T)
  mutateValue(current, harness.config, [current], seed)
  result = encodeInput(current)
  if result.len > maxLen:
    trimBytes(result, min(data.len, maxLen))
    if data.len > 0 and result.len > 0:
      for i in 0..<result.len:
        result[i] = data[i]
  harness.cacheBytes = copyBytes(result)
  harness.cacheValue = current
  harness.hasCache = true

proc customCrossOver*[T](harness: var FuzzHarness[T]; left, right: openArray[byte];
    maxOutLen: int; seed: uint32): seq[byte] {.untyped.} =
  ## Crosses two encoded structured inputs and returns the encoded result.
  var a = default(T)
  var b = default(T)
  if not tryDecodeInput(left, a):
    a = default(T)
  if not tryDecodeInput(right, b):
    b = default(T)
  crossOverValue(a, harness.config, [b], seed)
  result = encodeInput(a)
  if result.len > maxOutLen:
    trimBytes(result, maxOutLen)
