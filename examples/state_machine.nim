import ".." / "src" / drchaos

proc crashNow() {.importc: "abort", header: "<stdlib.h>".}

type
  StepKind = enum
    skOpen
    skWrite
    skCommit
    skRollback

  Snapshot = object
    checksum: uint32
    label: string

  Step = object
    kind: StepKind
    resource: string
    hasSnapshot: bool
    snapshot: Snapshot

  Program = object
    dryRun: bool
    steps: seq[Step]
    hasTicket: bool
    ticket: string

proc decodeStepKind(value: Value; outp: var StepKind): bool =
  var text = ""
  if not getString(value, text):
    return false
  case text
  of "open":
    outp = skOpen
  of "write":
    outp = skWrite
  of "commit":
    outp = skCommit
  of "rollback":
    outp = skRollback
  else:
    return false
  result = true

proc decodeSnapshot(value: Value; hasSnapshot: var bool; outp: var Snapshot): bool =
  if nodeKind(value) != nkOption:
    return false
  if not isSome(value):
    hasSnapshot = false
    outp = Snapshot()
    return true
  var inner = default(Value)
  var fieldValue = default(Value)
  var raw = 0'i64
  if not getOption(value, inner):
    return false
  if not findField(inner, "checksum", fieldValue):
    return false
  if not getInt(fieldValue, raw):
    return false
  outp.checksum = uint32(raw)
  if not findField(inner, "label", fieldValue):
    return false
  if not getString(fieldValue, outp.label):
    return false
  hasSnapshot = true
  result = true

proc decodeStep(value: Value; outp: var Step): bool =
  var fieldValue = default(Value)
  if not findField(value, "kind", fieldValue):
    return false
  if not decodeStepKind(fieldValue, outp.kind):
    return false
  if not findField(value, "resource", fieldValue):
    return false
  if not getString(fieldValue, outp.resource):
    return false
  if not findField(value, "snapshot", fieldValue):
    return false
  result = decodeSnapshot(fieldValue, outp.hasSnapshot, outp.snapshot)

proc decodeSteps(value: Value; outp: var seq[Step]): bool =
  var items: seq[Value] = @[]
  if not getArray(value, items):
    return false
  outp = @[]
  for item in items:
    var step = Step()
    if not decodeStep(item, step):
      return false
    outp.add step
  result = true

proc decodeTicket(value: Value; hasTicket: var bool; ticket: var string): bool =
  if nodeKind(value) != nkOption:
    return false
  if not isSome(value):
    hasTicket = false
    ticket = ""
    return true
  var inner = default(Value)
  if not getOption(value, inner):
    return false
  if not getString(inner, ticket):
    return false
  hasTicket = true
  result = true

proc decodeProgram(value: Value; outp: var Program): bool =
  var fieldValue = default(Value)
  if not findField(value, "dryRun", fieldValue):
    return false
  if not getBool(fieldValue, outp.dryRun):
    return false
  if not findField(value, "steps", fieldValue):
    return false
  if not decodeSteps(fieldValue, outp.steps):
    return false
  if not findField(value, "ticket", fieldValue):
    return false
  result = decodeTicket(fieldValue, outp.hasTicket, outp.ticket)

fuzzTarget:
  var drChaosSchema = objectSchema(@[
    fieldSchema("dryRun", boolSchema()),
    fieldSchema("steps", seqSchema(objectSchema(@[
      fieldSchema("kind", stringSchema()),
      fieldSchema("resource", stringSchema()),
      fieldSchema("snapshot", optionSchema(objectSchema(@[
        fieldSchema("checksum", intSchema()),
        fieldSchema("label", stringSchema())
      ])))
    ]))),
    fieldSchema("ticket", optionSchema(stringSchema()))
  ])

  var drChaosSeed = objectValue()
  addField(drChaosSeed, "dryRun", boolValue(true))
  addField(drChaosSeed, "steps", arrayValue(newSeq[Value](0)))
  addField(drChaosSeed, "ticket", noneValue())

  proc fuzzProgram(input: Value) =
    var program = Program()
    if not decodeProgram(input, program):
      return
    if program.dryRun:
      return
    if not program.hasTicket or program.ticket != "T-9000":
      return
    if program.steps.len < 3:
      return

    let first = program.steps[0]
    let second = program.steps[1]
    let third = program.steps[2]

    if first.kind == skOpen and first.resource == "/secure":
      if second.kind == skWrite and second.hasSnapshot:
        if second.snapshot.checksum == 0x41424344'u32:
          if third.kind == skCommit and third.resource == "shadow":
            crashNow()
