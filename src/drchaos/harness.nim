## Dynamic harness and LibFuzzer ABI helpers.

import codec, model, mutator

type
  BytePtr* = ptr UncheckedArray[byte]

  FuzzTargetProc* = proc (input: Value) {.nimcall.}

  FuzzHarness* = object
    target*: FuzzTargetProc
    config*: FuzzConfig
    schema*: SchemaNode
    seed*: Value
    cacheBytes*: seq[byte]
    cacheValue*: Value
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

proc initHarness*(target: FuzzTargetProc; seed: Value;
    schema: SchemaNode; config: FuzzConfig): FuzzHarness =
  ## Initializes a value-based fuzz harness.
  result = FuzzHarness(
    target: target,
    config: config,
    schema: schema,
    seed: copyValue(seed),
    cacheBytes: @[],
    cacheValue: copyValue(seed),
    hasCache: false
  )

proc loadCachedOrDecode(harness: var FuzzHarness; data: openArray[byte];
    value: var Value): bool =
  if harness.hasCache and sameBytes(harness.cacheBytes, data):
    value = copyValue(harness.cacheValue)
    result = true
  else:
    result = tryDecodeInput(data, value)
    if result:
      harness.cacheBytes = copyBytes(data)
      harness.cacheValue = copyValue(value)
      harness.hasCache = true

proc testOneInput*(harness: var FuzzHarness; data: openArray[byte]): cint =
  ## Executes the fuzz target for one encoded structured input.
  var input = default(Value)
  if loadCachedOrDecode(harness, data, input):
    harness.target(input)
  result = 0

proc customMutator*(harness: var FuzzHarness;
    data: openArray[byte]; maxLen: int; seed: uint32): seq[byte] =
  ## Mutates an encoded structured input and returns the new bytes.
  var current = default(Value)
  if not loadCachedOrDecode(harness, data, current):
    current = copyValue(harness.seed)
  var sources: seq[Value] = @[]
  sources.add copyValue(current)
  mutateValue(current, harness.schema, harness.config, sources, seed)
  result = encodeInput(current)
  if result.len > maxLen:
    current = copyValue(harness.seed)
    result = encodeInput(current)
    if result.len > maxLen:
      result = copyBytes(data)
      if result.len > maxLen:
        trimBytes(result, maxLen)
  harness.cacheBytes = copyBytes(result)
  harness.cacheValue = copyValue(current)
  harness.hasCache = true

proc customCrossOver*(harness: var FuzzHarness; left, right: openArray[byte];
    maxOutLen: int; seed: uint32): seq[byte] =
  ## Crosses two encoded structured inputs and returns the encoded result.
  var a = default(Value)
  var b = default(Value)
  if not tryDecodeInput(left, a):
    a = copyValue(harness.seed)
  if not tryDecodeInput(right, b):
    b = copyValue(harness.seed)
  var donors: seq[Value] = @[]
  donors.add copyValue(b)
  crossOverValue(a, harness.schema, harness.config, donors, seed)
  result = encodeInput(a)
  if result.len > maxOutLen:
    a = copyValue(harness.seed)
    result = encodeInput(a)
    if result.len > maxOutLen:
      result = copyBytes(left)
      if result.len > maxOutLen:
        trimBytes(result, maxOutLen)
