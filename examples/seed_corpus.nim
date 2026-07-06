import std/syncio
import ".." / "src" / drchaos

type
  CorpusMessage = object
    route: string
    payload: seq[byte]
    hasPriority: bool
    priority: uint8

proc decodePayload(value: Value; outp: var seq[byte]): bool =
  var items: seq[Value] = @[]
  if not getArray(value, items):
    return false
  outp = @[]
  for item in items:
    var raw = 0'i64
    if not getInt(item, raw):
      return false
    if raw < 0 or raw > high(byte).int64:
      return false
    outp.add byte(raw)
  result = true

proc decodePriority(value: Value; hasPriority: var bool; priority: var uint8): bool =
  if nodeKind(value) != nkOption:
    return false
  if not isSome(value):
    hasPriority = false
    priority = 0'u8
    return true
  var inner = default(Value)
  var raw = 0'i64
  if not getOption(value, inner):
    return false
  if not getInt(inner, raw):
    return false
  if raw < 0 or raw > high(uint8).int64:
    return false
  hasPriority = true
  priority = uint8(raw)
  result = true

proc decodeCorpusMessage(value: Value; outp: var CorpusMessage): bool =
  var fieldValue = default(Value)
  if not findField(value, "route", fieldValue):
    return false
  if not getString(fieldValue, outp.route):
    return false
  if not findField(value, "payload", fieldValue):
    return false
  if not decodePayload(fieldValue, outp.payload):
    return false
  if not findField(value, "priority", fieldValue):
    return false
  result = decodePriority(fieldValue, outp.hasPriority, outp.priority)

var payload = arrayValue(@[
  intValue(1),
  intValue(2),
  intValue(3)
])
var seed = objectValue()
addField(seed, "route", stringValue("/health"))
addField(seed, "payload", payload)
addField(seed, "priority", someValue(intValue(1)))

var bytes = encodeInput(seed)
var decodedValue = default(Value)
if not tryDecodeInput(bytes, decodedValue):
  quit(1)

var decoded = CorpusMessage()
if not decodeCorpusMessage(decodedValue, decoded):
  quit(1)
echo decoded.route & " priority=" & $decoded.priority
