## drchaos wire-format encoding helpers for dynamic values.

import model

const
  wireHeader = ['d'.byte, 'c'.byte, 'h'.byte, 's'.byte, 2.byte, 0.byte]
  tagBool = 0.byte
  tagInt = 1.byte
  tagFloat = 2.byte
  tagString = 3.byte
  tagArray = 4.byte
  tagStruct = 5.byte
  tagEndStruct = 6.byte
  tagOption = 7.byte
  tagEnum = 8.byte

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

proc expectTag(data: openArray[byte]; pos: var int; expected: byte): bool =
  var tag = 0.byte
  if not tryReadByte(data, pos, tag):
    return false
  result = tag == expected

proc writeValue(buffer: var seq[byte]; value: Value)

proc writeValue(buffer: var seq[byte]; value: Value) =
  case nodeKind(value)
  of nkBool:
    writeByte(buffer, tagBool)
    writeByte(buffer, byte(ord(value.boolVal)))
  of nkInt:
    writeByte(buffer, tagInt)
    writeInt64(buffer, value.intVal)
  of nkFloat:
    writeByte(buffer, tagFloat)
    writeInt64(buffer, cast[int64](value.floatVal))
  of nkString:
    writeByte(buffer, tagString)
    writeStringData(buffer, value.stringVal)
  of nkEnum:
    writeByte(buffer, tagEnum)
    writeInt64(buffer, value.enumVal)
  of nkSeq:
    writeByte(buffer, tagArray)
    writeInt32(buffer, int32(value.elems.len))
    for item in value.elems:
      writeValue(buffer, item[])
  of nkObject:
    writeByte(buffer, tagStruct)
    for i in 0..<min(value.fieldNames.len, value.fieldValues.len):
      writeByte(buffer, tagString)
      writeStringData(buffer, value.fieldNames[i])
      writeValue(buffer, value.fieldValues[i][])
    writeByte(buffer, tagEndStruct)
  of nkOption:
    writeByte(buffer, tagOption)
    if value.optVal != nil:
      writeByte(buffer, 1)
      writeValue(buffer, value.optVal[])
    else:
      writeByte(buffer, 0)

proc readValue(data: openArray[byte]; pos: var int; value: var Value): bool =
  var tag = 0.byte
  if not tryReadByte(data, pos, tag):
    return false
  case tag
  of tagBool:
    var b = 0.byte
    if not tryReadByte(data, pos, b):
      return false
    value = boolValue(b != 0)
  of tagInt:
    var raw = 0'i64
    if not tryReadInt64(data, pos, raw):
      return false
    value = intValue(raw)
  of tagFloat:
    var raw = 0'i64
    if not tryReadInt64(data, pos, raw):
      return false
    value = floatValue(cast[float64](raw))
  of tagString:
    var text = ""
    if not tryReadStringData(data, pos, text):
      return false
    value = stringValue(text)
  of tagEnum:
    var ordinal = 0'i64
    if not tryReadInt64(data, pos, ordinal):
      return false
    value = enumValue(ordinal)
  of tagArray:
    var length32 = 0'i32
    if not tryReadInt32(data, pos, length32):
      return false
    let length = int(length32)
    if length < 0:
      return false
    var items: seq[Value] = @[]
    for _ in 0..<length:
      var item = default(Value)
      if not readValue(data, pos, item):
        return false
      items.add item
    value = arrayValue(items)
  of tagStruct:
    value = objectValue()
    while true:
      var next = 0.byte
      if not tryReadByte(data, pos, next):
        return false
      if next == tagEndStruct:
        break
      if next != tagString:
        return false
      var name = ""
      if not tryReadStringData(data, pos, name):
        return false
      var child = default(Value)
      if not readValue(data, pos, child):
        return false
      addField(value, name, child)
  of tagOption:
    var present = 0.byte
    if not tryReadByte(data, pos, present):
      return false
    if present == 0:
      value = noneValue()
    else:
      var child = default(Value)
      if not readValue(data, pos, child):
        return false
      value = someValue(child)
  else:
    return false
  result = true

proc encodeInput*(value: Value): seq[byte] =
  ## Encodes a dynamic value into the drchaos wire format.
  result = @[]
  for item in wireHeader:
    result.add item
  writeValue(result, value)

proc tryDecodeInput*(data: openArray[byte]; value: var Value): bool =
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

proc decodeInput*(data: openArray[byte]): Value =
  ## Decodes `data` and returns a default value on failure.
  var decoded = default(Value)
  if tryDecodeInput(data, decoded):
    result = decoded
  else:
    result = default(Value)
