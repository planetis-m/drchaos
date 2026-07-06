import ".." / "src" / drchaos

proc crashNow() {.importc: "abort", header: "<stdlib.h>".}

type
  MessageKind = enum
    mkPing
    mkSync
    mkCommand

  Message = object
    kind: MessageKind
    header: string
    values: seq[int32]
    retry: bool
    retryValue: int16

proc decodeKind(value: Value; outp: var MessageKind): bool =
  var text = ""
  if not getString(value, text):
    return false
  case text
  of "ping":
    outp = mkPing
  of "sync":
    outp = mkSync
  of "command":
    outp = mkCommand
  else:
    return false
  result = true

proc decodeValues(value: Value; outp: var seq[int32]): bool =
  var items: seq[Value] = @[]
  if not getArray(value, items):
    return false
  outp = @[]
  for item in items:
    var raw = 0'i64
    if not getInt(item, raw):
      return false
    outp.add int32(raw)
  result = true

proc decodeRetry(value: Value; enabled: var bool; retryValue: var int16): bool =
  if nodeKind(value) != nkOption:
    return false
  if not isSome(value):
    enabled = false
    retryValue = 0
    return true
  var inner = default(Value)
  if not getOption(value, inner):
    return false
  var raw = 0'i64
  if not getInt(inner, raw):
    return false
  enabled = true
  retryValue = int16(raw)
  result = true

proc decodeMessage(value: Value; outp: var Message): bool =
  var fieldValue = default(Value)
  if not findField(value, "kind", fieldValue):
    return false
  if not decodeKind(fieldValue, outp.kind):
    return false
  if not findField(value, "header", fieldValue):
    return false
  if not getString(fieldValue, outp.header):
    return false
  if not findField(value, "values", fieldValue):
    return false
  if not decodeValues(fieldValue, outp.values):
    return false
  if not findField(value, "retry", fieldValue):
    return false
  result = decodeRetry(fieldValue, outp.retry, outp.retryValue)

fuzzTarget:
  var drChaosSchema = objectSchema(@[
    fieldSchema("kind", stringSchema()),
    fieldSchema("header", stringSchema()),
    fieldSchema("values", seqSchema(intSchema())),
    fieldSchema("retry", optionSchema(intSchema()))
  ])

  var drChaosSeed = objectValue()
  addField(drChaosSeed, "kind", stringValue("ping"))
  addField(drChaosSeed, "header", stringValue(""))
  addField(drChaosSeed, "values", arrayValue(newSeq[Value](0)))
  addField(drChaosSeed, "retry", noneValue())

  proc fuzzMessage(input: Value) =
    var message = Message()
    if not decodeMessage(input, message):
      return
    if message.kind == mkCommand and message.header == "panic":
      if message.values.len == 3 and message.retry:
        if message.retryValue == 7'i16:
          crashNow()
