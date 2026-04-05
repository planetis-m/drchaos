## drchaos wire-format encoding helpers and typed node conversion.

import model, option

const
  wireHeader = ['d'.byte, 'c'.byte, 'h'.byte, 's'.byte, 1.byte, 0.byte]

type
  WireTag = enum
    wtBool
    wtInt
    wtFloat
    wtString
    wtArray
    wtStruct
    wtEndStruct
    wtOption
    wtEnum

proc writeValue(buffer: var seq[byte]; value: bool)
proc writeValue[T: SomeInteger](buffer: var seq[byte]; value: T)
proc writeValue[T: SomeFloat](buffer: var seq[byte]; value: T)
proc writeValue(buffer: var seq[byte]; value: string)
proc writeValue[T: enum](buffer: var seq[byte]; value: T)
proc writeValue[T](buffer: var seq[byte]; value: seq[T]) {.untyped.}
proc writeValue[I, T](buffer: var seq[byte]; value: array[I, T]) {.untyped.}
proc writeValue[T](buffer: var seq[byte]; value: Option[T]) {.untyped.}
proc writeValue[T](buffer: var seq[byte]; value: ref T) {.untyped.}
proc writeValue[T: object](buffer: var seq[byte]; value: T)

proc readValue(data: openArray[byte]; pos: var int; value: var bool): bool
proc readValue[T: SomeInteger](data: openArray[byte]; pos: var int;
    value: var T): bool
proc readValue[T: SomeFloat](data: openArray[byte]; pos: var int;
    value: var T): bool
proc readValue(data: openArray[byte]; pos: var int; value: var string): bool
proc readValue[T: enum](data: openArray[byte]; pos: var int; value: var T): bool
proc readValue[T](data: openArray[byte]; pos: var int; value: var seq[T]): bool {.
    untyped.}
proc readValue[I, T](data: openArray[byte]; pos: var int; value: var array[I, T]): bool {.
    untyped.}
proc readValue[T](data: openArray[byte]; pos: var int; value: var Option[T]): bool {.
    untyped.}
proc readValue[T](data: openArray[byte]; pos: var int; value: var ref T): bool {.
    untyped.}
proc readValue[T: object](data: openArray[byte]; pos: var int; value: var T): bool

proc toFuzzNode(value: bool): FuzzNode
proc toFuzzNode[T: SomeInteger](value: T): FuzzNode
proc toFuzzNode[T: SomeFloat](value: T): FuzzNode
proc toFuzzNode(value: string): FuzzNode
proc toFuzzNode[T: enum](value: T): FuzzNode
proc toFuzzNode[T](value: seq[T]): FuzzNode {.untyped.}
proc toFuzzNode[I, T](value: array[I, T]): FuzzNode {.untyped.}
proc toFuzzNode[T](value: Option[T]): FuzzNode {.untyped.}
proc toFuzzNode[T](value: ref T): FuzzNode {.untyped.}
proc toFuzzNode[T: object](value: T): FuzzNode

proc fromFuzzNode(node: FuzzNode; value: var bool)
proc fromFuzzNode[T: SomeInteger](node: FuzzNode; value: var T)
proc fromFuzzNode[T: SomeFloat](node: FuzzNode; value: var T)
proc fromFuzzNode(node: FuzzNode; value: var string)
proc fromFuzzNode[T: enum](node: FuzzNode; value: var T)
proc fromFuzzNode[T](node: FuzzNode; value: var seq[T]) {.untyped.}
proc fromFuzzNode[I, T](node: FuzzNode; value: var array[I, T]) {.untyped.}
proc fromFuzzNode[T](node: FuzzNode; value: var Option[T]) {.untyped.}
proc fromFuzzNode[T](node: FuzzNode; value: var ref T) {.untyped.}
proc fromFuzzNode[T: object](node: FuzzNode; value: var T)

proc writeByte(buffer: var seq[byte]; value: byte) =
  buffer.add value

proc writeInt32(buffer: var seq[byte]; value: int32) =
  for shift in 0..3:
    buffer.add byte((uint32(value) shr (shift * 8)) and 0xff'u32)

proc writeInt64(buffer: var seq[byte]; value: int64) =
  for shift in 0..7:
    buffer.add byte((uint64(value) shr (shift * 8)) and 0xff'u64)

proc writeStringData(buffer: var seq[byte]; value: string) =
  writeInt32(buffer, int32(value.len))
  for ch in value:
    buffer.add ch.byte

proc tryReadByte(data: openArray[byte]; pos: var int; value: var byte): bool =
  if pos >= data.len:
    return false
  value = data[pos]
  inc pos
  result = true

proc tryReadInt32(data: openArray[byte]; pos: var int; value: var int32): bool =
  var raw = 0'u32
  for shift in 0..3:
    var b = 0.byte
    if not tryReadByte(data, pos, b):
      return false
    raw = raw or (uint32(b) shl (shift * 8))
  value = cast[int32](raw)
  result = true

proc tryReadInt64(data: openArray[byte]; pos: var int; value: var int64): bool =
  var raw = 0'u64
  for shift in 0..7:
    var b = 0.byte
    if not tryReadByte(data, pos, b):
      return false
    raw = raw or (uint64(b) shl (shift * 8))
  value = cast[int64](raw)
  result = true

proc tryReadStringData(data: openArray[byte]; pos: var int; value: var string): bool =
  var length32 = 0'i32
  if not tryReadInt32(data, pos, length32):
    return false
  let length = int(length32)
  if length < 0 or pos + length > data.len:
    return false
  value = newString(length)
  for i in 0..<length:
    value[i] = char(data[pos + i])
  inc pos, length
  result = true

proc expectTag(data: openArray[byte]; pos: var int; expected: WireTag): bool =
  var tag = 0.byte
  if not tryReadByte(data, pos, tag):
    return false
  result = tag == expected.byte

proc boxed(node: FuzzNode): ref FuzzNode =
  new(result)
  result[] = node

proc writeObjectLike[T: object](buffer: var seq[byte]; value: T) =
  writeByte(buffer, wtStruct.byte)
  for fieldName, field in fieldPairs(value):
    writeStringData(buffer, fieldName)
    writeValue(buffer, field)
  writeByte(buffer, wtEndStruct.byte)

proc readObjectLike[T: object](data: openArray[byte]; pos: var int;
    value: var T): bool {.untyped.} =
  if not expectTag(data, pos, wtStruct):
    return false
  value = default(T)
  while true:
    var tag = 0.byte
    if not tryReadByte(data, pos, tag):
      return false
    if tag == wtEndStruct.byte:
      return true
    dec pos
    var fieldName = ""
    if not tryReadStringData(data, pos, fieldName):
      return false
    var matched = false
    for existingName, field in fieldPairs(value):
      if existingName == fieldName:
        if not readValue(data, pos, field):
          return false
        matched = true
        break
    if not matched:
      return false

proc writeValue(buffer: var seq[byte]; value: bool) =
  writeByte(buffer, wtBool.byte)
  writeByte(buffer, byte(ord(value)))

proc writeValue[T: SomeInteger](buffer: var seq[byte]; value: T) =
  writeByte(buffer, wtInt.byte)
  writeInt64(buffer, int64(value))

proc writeValue[T: SomeFloat](buffer: var seq[byte]; value: T) =
  writeByte(buffer, wtFloat.byte)
  writeInt64(buffer, cast[int64](float64(value)))

proc writeValue(buffer: var seq[byte]; value: string) =
  writeByte(buffer, wtString.byte)
  writeStringData(buffer, value)

proc writeValue[T: enum](buffer: var seq[byte]; value: T) =
  writeByte(buffer, wtEnum.byte)
  writeInt64(buffer, int64(value.ord))

proc writeValue[T](buffer: var seq[byte]; value: seq[T]) {.untyped.} =
  writeByte(buffer, wtArray.byte)
  writeInt32(buffer, int32(value.len))
  for item in value:
    writeValue(buffer, item)

proc writeValue[I, T](buffer: var seq[byte]; value: array[I, T]) {.untyped.} =
  writeByte(buffer, wtArray.byte)
  writeInt32(buffer, int32(value.len))
  for item in value:
    writeValue(buffer, item)

proc writeValue[T](buffer: var seq[byte]; value: Option[T]) {.untyped.} =
  writeByte(buffer, wtOption.byte)
  if value.hasValue:
    writeByte(buffer, 1)
    writeValue(buffer, value.value)
  else:
    writeByte(buffer, 0)

proc writeValue[T](buffer: var seq[byte]; value: ref T) {.untyped.} =
  writeByte(buffer, wtOption.byte)
  if value != nil:
    writeByte(buffer, 1)
    writeValue(buffer, value[])
  else:
    writeByte(buffer, 0)

proc writeValue[T: object](buffer: var seq[byte]; value: T) =
  writeObjectLike(buffer, value)

proc readValue(data: openArray[byte]; pos: var int; value: var bool): bool =
  if not expectTag(data, pos, wtBool):
    return false
  var b = 0.byte
  if not tryReadByte(data, pos, b):
    return false
  value = b != 0
  result = true

proc readValue[T: SomeInteger](data: openArray[byte]; pos: var int;
    value: var T): bool =
  if not expectTag(data, pos, wtInt):
    return false
  var raw = 0'i64
  if not tryReadInt64(data, pos, raw):
    return false
  value = T(raw)
  result = true

proc readValue[T: SomeFloat](data: openArray[byte]; pos: var int;
    value: var T): bool =
  if not expectTag(data, pos, wtFloat):
    return false
  var raw = 0'i64
  if not tryReadInt64(data, pos, raw):
    return false
  value = T(cast[float64](raw))
  result = true

proc readValue(data: openArray[byte]; pos: var int; value: var string): bool =
  if not expectTag(data, pos, wtString):
    return false
  result = tryReadStringData(data, pos, value)

proc readValue[T: enum](data: openArray[byte]; pos: var int; value: var T): bool =
  if not expectTag(data, pos, wtEnum):
    return false
  var ordinal64 = 0'i64
  if not tryReadInt64(data, pos, ordinal64):
    return false
  let ordinal = int(ordinal64)
  if ordinal < low(T).ord:
    value = low(T)
  elif ordinal > high(T).ord:
    value = high(T)
  else:
    value = T(ordinal)
  result = true

proc readValue[T](data: openArray[byte]; pos: var int; value: var seq[T]): bool {.
    untyped.} =
  if not expectTag(data, pos, wtArray):
    return false
  var length32 = 0'i32
  if not tryReadInt32(data, pos, length32):
    return false
  let length = int(length32)
  if length < 0:
    return false
  value = newSeq[T](length)
  for i in 0..<length:
    if not readValue(data, pos, value[i]):
      return false
  result = true

proc readValue[I, T](data: openArray[byte]; pos: var int; value: var array[I, T]): bool {.
    untyped.} =
  if not expectTag(data, pos, wtArray):
    return false
  var length32 = 0'i32
  if not tryReadInt32(data, pos, length32):
    return false
  let length = int(length32)
  if length < 0:
    return false
  var i = 0
  while i < value.len and i < length:
    if not readValue(data, pos, value[i]):
      return false
    inc i
  while i < length:
    var ignored: T
    if not readValue(data, pos, ignored):
      return false
    inc i
  result = true

proc readValue[T](data: openArray[byte]; pos: var int; value: var Option[T]): bool {.
    untyped.} =
  if not expectTag(data, pos, wtOption):
    return false
  var present = 0.byte
  if not tryReadByte(data, pos, present):
    return false
  if present == 0:
    value = none[T]()
    return true
  var item = default(T)
  if not readValue(data, pos, item):
    return false
  value = some(item)
  result = true

proc readValue[T](data: openArray[byte]; pos: var int; value: var ref T): bool {.
    untyped.} =
  if not expectTag(data, pos, wtOption):
    return false
  var present = 0.byte
  if not tryReadByte(data, pos, present):
    return false
  if present == 0:
    value = nil
    return true
  new(value)
  result = readValue(data, pos, value[])

proc readValue[T: object](data: openArray[byte]; pos: var int; value: var T): bool =
  result = readObjectLike(data, pos, value)

proc toFuzzNode(value: bool): FuzzNode =
  result = FuzzNode(kind: nkBool, boolVal: value)

proc toFuzzNode[T: SomeInteger](value: T): FuzzNode =
  result = FuzzNode(kind: nkInt, intVal: int64(value))

proc toFuzzNode[T: SomeFloat](value: T): FuzzNode =
  result = FuzzNode(kind: nkFloat, floatVal: float64(value))

proc toFuzzNode(value: string): FuzzNode =
  result = FuzzNode(kind: nkString, stringVal: value)

proc toFuzzNode[T: enum](value: T): FuzzNode =
  result = FuzzNode(kind: nkEnum, intVal: int64(value.ord))

proc toFuzzNode[T](value: seq[T]): FuzzNode {.untyped.} =
  result = FuzzNode(kind: nkSeq, elems: @[])
  for item in value:
    result.elems.add toFuzzNode(item)

proc toFuzzNode[I, T](value: array[I, T]): FuzzNode {.untyped.} =
  result = FuzzNode(kind: nkSeq, elems: @[])
  for item in value:
    result.elems.add toFuzzNode(item)

proc toFuzzNode[T](value: Option[T]): FuzzNode {.untyped.} =
  if value.hasValue:
    result = FuzzNode(kind: nkOption, optVal: some(boxed(toFuzzNode(value.value))))
  else:
    result = FuzzNode(kind: nkOption, optVal: none[ref FuzzNode]())

proc toFuzzNode[T](value: ref T): FuzzNode {.untyped.} =
  if value != nil:
    result = FuzzNode(kind: nkOption, optVal: some(boxed(toFuzzNode(value[]))))
  else:
    result = FuzzNode(kind: nkOption, optVal: none[ref FuzzNode]())

proc toFuzzNode[T: object](value: T): FuzzNode =
  result = FuzzNode(kind: nkObject, fields: @[])
  for fieldName, field in fieldPairs(value):
    result.fields.add FieldNode(name: fieldName, value: toFuzzNode(field))

proc fromFuzzNode(node: FuzzNode; value: var bool) =
  if node.kind == nkBool:
    value = node.boolVal

proc fromFuzzNode[T: SomeInteger](node: FuzzNode; value: var T) =
  if node.kind == nkInt or node.kind == nkEnum:
    value = T(node.intVal)

proc fromFuzzNode[T: SomeFloat](node: FuzzNode; value: var T) =
  if node.kind == nkFloat:
    value = T(node.floatVal)

proc fromFuzzNode(node: FuzzNode; value: var string) =
  if node.kind == nkString:
    value = node.stringVal

proc fromFuzzNode[T: enum](node: FuzzNode; value: var T) =
  if node.kind == nkEnum or node.kind == nkInt:
    let ordinal = int(node.intVal)
    if ordinal < low(T).ord:
      value = low(T)
    elif ordinal > high(T).ord:
      value = high(T)
    else:
      value = T(ordinal)

proc fromFuzzNode[T](node: FuzzNode; value: var seq[T]) {.untyped.} =
  if node.kind != nkSeq:
    return
  value = newSeq[T](node.elems.len)
  for i in 0..<node.elems.len:
    fromFuzzNode(node.elems[i], value[i])

proc fromFuzzNode[I, T](node: FuzzNode; value: var array[I, T]) {.untyped.} =
  if node.kind != nkSeq:
    return
  let limit = min(node.elems.len, value.len)
  for i in 0..<limit:
    fromFuzzNode(node.elems[i], value[i])

proc fromFuzzNode[T](node: FuzzNode; value: var Option[T]) {.untyped.} =
  if node.kind != nkOption:
    return
  if node.optVal.hasValue:
    var item: T
    fromFuzzNode(node.optVal.value[], item)
    value = some(item)
  else:
    value = none[T]()

proc fromFuzzNode[T](node: FuzzNode; value: var ref T) {.untyped.} =
  if node.kind != nkOption:
    return
  if node.optVal.hasValue:
    new(value)
    fromFuzzNode(node.optVal.value[], value[])
  else:
    value = nil

proc fromFuzzNode[T: object](node: FuzzNode; value: var T) =
  if node.kind != nkObject:
    return
  var zero: T
  value = zero
  for inputField in node.fields:
    for fieldName, field in fieldPairs(value):
      if fieldName == inputField.name:
        fromFuzzNode(inputField.value, field)
        break

proc encodeInput*[T](value: T): seq[byte] {.untyped.} =
  ## Encodes `value` into the drchaos wire format used by this fuzzer.
  result = @[]
  for item in wireHeader:
    result.add item
  writeValue(result, value)

proc tryDecodeInput*[T](data: openArray[byte]; value: var T): bool {.untyped.} =
  ## Decodes `data` into `value`, returning false for malformed input.
  if data.len < wireHeader.len:
    return false
  for i in 0..<wireHeader.len:
    if data[i] != wireHeader[i]:
      return false
  var pos = wireHeader.len
  if not readValue(data, pos, value):
    return false
  result = pos == data.len

proc decodeInput*[T](data: openArray[byte]): T {.untyped.} =
  ## Decodes `data` and returns `default(T)` when decoding fails.
  result = default(T)
  discard tryDecodeInput(data, result)
