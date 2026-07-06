import std/syncio
import ".." / "src" / drchaos

type
  GraphHit = distinct int32

  Guard = object
    opcode: string
    level: uint8

  Node = object
    label: string
    edges: seq[uint8]
    hasGuard: bool
    guard: Guard

  GraphInput = object
    version: uint16
    entry: uint8
    hasTicket: bool
    ticket: string
    nodes: seq[Node]

proc exactEdges(node: Node; expected: openArray[uint8]): bool =
  if node.edges.len != expected.len:
    return false
  for i in 0..<expected.len:
    if node.edges[i] != expected[i]:
      return false
  result = true

proc isGuard(node: Node; opcode: string; level: uint8): bool =
  result = node.hasGuard and
    node.guard.opcode == opcode and
    node.guard.level == level

proc hasNode(input: GraphInput; label: string; expectedEdges: openArray[uint8];
    opcode = ""; level = 0'u8): bool =
  for node in input.nodes:
    if node.label == label and exactEdges(node, expectedEdges):
      if opcode.len == 0:
        return not node.hasGuard
      return isGuard(node, opcode, level)
  result = false

proc checkGraph(input: GraphInput) {.raises: GraphHit.} =
  if input.version != 7'u16 or input.entry != 0'u8:
    return
  if not input.hasTicket or input.ticket != "graph-7":
    return
  if input.nodes.len < 4:
    return

  if hasNode(input, "root", [1'u8, 2'u8]) and
      hasNode(input, "auth", [3'u8], "open", 3'u8) and
      hasNode(input, "log", []) and
      hasNode(input, "vault", [], "seal", 7'u8):
    raise GraphHit(1)

proc decodeByteArray(value: Value; outp: var seq[uint8]): bool =
  var items: seq[Value] = @[]
  if not getArray(value, items):
    return false
  outp = @[]
  for item in items:
    var raw = 0'i64
    if not getInt(item, raw):
      return false
    if raw < 0 or raw > high(uint8).int64:
      return false
    outp.add uint8(raw)
  result = true

proc decodeGuard(value: Value; hasGuard: var bool; outp: var Guard): bool =
  if nodeKind(value) != nkOption:
    return false
  if not isSome(value):
    hasGuard = false
    outp = Guard()
    return true
  var inner = default(Value)
  var fieldValue = default(Value)
  var raw = 0'i64
  if not getOption(value, inner):
    return false
  if not findField(inner, "opcode", fieldValue):
    return false
  if not getString(fieldValue, outp.opcode):
    return false
  if not findField(inner, "level", fieldValue):
    return false
  if not getInt(fieldValue, raw):
    return false
  if raw < 0 or raw > high(uint8).int64:
    return false
  outp.level = uint8(raw)
  hasGuard = true
  result = true

proc decodeNode(value: Value; outp: var Node): bool =
  var fieldValue = default(Value)
  if not findField(value, "label", fieldValue):
    return false
  if not getString(fieldValue, outp.label):
    return false
  if not findField(value, "edges", fieldValue):
    return false
  if not decodeByteArray(fieldValue, outp.edges):
    return false
  if not findField(value, "guard", fieldValue):
    return false
  result = decodeGuard(fieldValue, outp.hasGuard, outp.guard)

proc decodeNodes(value: Value; outp: var seq[Node]): bool =
  var items: seq[Value] = @[]
  if not getArray(value, items):
    return false
  outp = @[]
  for item in items:
    var node = Node()
    if not decodeNode(item, node):
      return false
    outp.add node
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

proc decodeGraphInput(value: Value; outp: var GraphInput): bool =
  var fieldValue = default(Value)
  var raw = 0'i64
  if not findField(value, "version", fieldValue):
    return false
  if not getInt(fieldValue, raw):
    return false
  if raw < 0 or raw > high(uint16).int64:
    return false
  outp.version = uint16(raw)
  if not findField(value, "entry", fieldValue):
    return false
  if not getInt(fieldValue, raw):
    return false
  if raw < 0 or raw > high(uint8).int64:
    return false
  outp.entry = uint8(raw)
  if not findField(value, "ticket", fieldValue):
    return false
  if not decodeTicket(fieldValue, outp.hasTicket, outp.ticket):
    return false
  if not findField(value, "nodes", fieldValue):
    return false
  result = decodeNodes(fieldValue, outp.nodes)

proc byteArrayValue(values: openArray[uint8]): Value =
  var items: seq[Value] = @[]
  for item in values:
    items.add intValue(item.int64)
  result = arrayValue(items)

proc guardValue(opcode: string; level: uint8): Value =
  var inner = objectValue()
  addField(inner, "opcode", stringValue(opcode))
  addField(inner, "level", intValue(level.int64))
  result = someValue(inner)

proc graphSchema(): SchemaNode =
  result = objectSchema(@[
    fieldSchema("version", intSchema()),
    fieldSchema("entry", intSchema()),
    fieldSchema("ticket", optionSchema(stringSchema())),
    fieldSchema("nodes", seqSchema(objectSchema(@[
      fieldSchema("label", stringSchema()),
      fieldSchema("edges", seqSchema(intSchema())),
      fieldSchema("guard", optionSchema(objectSchema(@[
        fieldSchema("opcode", stringSchema()),
        fieldSchema("level", intSchema())
      ])))
    ])))
  ])

proc seedGraph(label: string; edges: openArray[uint8]; opcode = "";
    level = 0'u8; withTicket = false): Value =
  var node = objectValue()
  addField(node, "label", stringValue(label))
  addField(node, "edges", byteArrayValue(edges))
  if opcode.len > 0:
    addField(node, "guard", guardValue(opcode, level))
  else:
    addField(node, "guard", noneValue())
  var nodes = arrayValue(@[])
  addElem(nodes, node)
  result = objectValue()
  addField(result, "version", intValue(7))
  addField(result, "entry", intValue(0))
  addField(result, "ticket",
    if withTicket: someValue(stringValue("graph-7")) else: noneValue())
  addField(result, "nodes", nodes)

proc addCorpus(corpus: var seq[seq[byte]]; data: seq[byte]; slot: int): bool =
  if data.len == 0:
    return false
  var decoded = default(Value)
  if not tryDecodeInput(data, decoded):
    return false
  if corpus.len < 128:
    corpus.add data
  else:
    corpus[slot mod corpus.len] = data
  result = true

proc fuzzGraph(input: Value) =
  discard input

proc tryInput(harness: var FuzzHarness; data: openArray[byte]): bool =
  discard testOneInput(harness, data)
  var decodedValue = default(Value)
  if not tryDecodeInput(data, decodedValue):
    return false
  var decoded = GraphInput()
  if not decodeGraphInput(decodedValue, decoded):
    return false
  try:
    checkGraph(decoded)
  except GraphHit:
    return true
  result = false

when isMainModule:
  var config = defaultFuzzConfig()
  config.maxDepth = 8
  config.maxBytes = 2048
  config.maxSeqLen = 8
  config.maxStringLen = 32
  config.dictionary = @["graph-7", "root", "auth", "log", "vault", "open", "seal"]

  var schema = graphSchema()
  var seed = seedGraph("root", [1'u8, 2'u8])
  var harness = initHarness(fuzzGraph, seed, schema, config)
  var corpus: seq[seq[byte]] = @[]
  corpus.add encodeInput(seedGraph("root", [1'u8, 2'u8]))
  corpus.add encodeInput(seedGraph("auth", [3'u8], "open", 3'u8))
  corpus.add encodeInput(seedGraph("log", []))
  corpus.add encodeInput(seedGraph("vault", [], "seal", 7'u8))
  corpus.add encodeInput(seedGraph("root", [1'u8, 2'u8], withTicket = true))

  for i in 0..<corpus.len:
    var decodedValue = default(Value)
    if not tryDecodeInput(corpus[i], decodedValue):
      echo "seed decode failed idx=", i, " len=", corpus[i].len
      quit(2)

  var hit = false
  var iteration = 0
  var seedValue = 1'u32

  while iteration < 20000 and not hit:
    let parentIndex = iteration mod corpus.len
    let donorIndex = (iteration * 5 + 3) mod corpus.len

    let mutated = customMutator(harness, corpus[parentIndex], config.maxBytes, seedValue)
    if tryInput(harness, mutated):
      hit = true
      break
    discard addCorpus(corpus, mutated, iteration)

    let crossed = customCrossOver(harness, corpus[parentIndex], corpus[donorIndex],
      config.maxBytes, seedValue xor 0x9e3779b9'u32)
    if tryInput(harness, crossed):
      hit = true
      break
    discard addCorpus(corpus, crossed, iteration + 17)

    inc iteration
    inc seedValue

  if hit:
    echo "graph smoke test reached the target in ", iteration, " iterations"
  else:
    quit(1)
