## Core runtime data structures for the drchaos structured fuzzing engine.

type
  NodeKind* = enum
    nkBool
    nkInt
    nkFloat
    nkString
    nkEnum
    nkSeq
    nkObject
    nkOption

  SchemaKind* = enum
    skBool
    skInt
    skFloat
    skString
    skEnum
    skSeq
    skObject
    skOption

  MutationKind* = enum
    mkNone
    mkAdd
    mkMutate
    mkDelete
    mkCopy
    mkClone

  FuzzNode* = object
    case
    of BoolNode:
      boolVal*: bool
    of IntNode:
      intVal*: int64
    of FloatNode:
      floatVal*: float64
    of StringNode:
      stringVal*: string
    of EnumNode:
      enumVal*: int64
    of SeqNode:
      elems*: seq[ref FuzzNode]
    of ObjectNode:
      fieldNames*: seq[string]
      fieldValues*: seq[ref FuzzNode]
    of OptionNode:
      optVal*: ref FuzzNode

  Value* = FuzzNode

  SchemaNode* = ref object
    kind*: SchemaKind
    mutationWeight*: Positive
    fields*: seq[FieldSchema]
    elem*: SchemaNode
    enumNames*: seq[string]

  FieldSchema* = object
    name*: string
    node*: SchemaNode

  FuzzConfig* = object
    maxDepth*: Positive
    maxBytes*: Positive
    maxSeqLen*: Positive
    maxStringLen*: Positive
    dictionary*: seq[string]

  MutationCandidate* = object
    op*: MutationKind
    path*: seq[int]
    weight*: int

proc defaultFuzzConfig*(): FuzzConfig =
  ## Returns the default configuration used by generated harnesses.
  result = FuzzConfig(
    maxDepth: 32,
    maxBytes: 4096,
    maxSeqLen: 32,
    maxStringLen: 256,
    dictionary: @[]
  )

func default*(_: typedesc[FuzzNode]): FuzzNode =
  ## Returns the default zero-like node used for seq allocation and resets.
  return BoolNode(boolVal: false)

proc boolValue*(value: bool): Value =
  ## Constructs a boolean fuzz value.
  return BoolNode(boolVal: value)

proc intValue*(value: int64): Value =
  ## Constructs an integer fuzz value.
  return IntNode(intVal: value)

proc floatValue*(value: float64): Value =
  ## Constructs a floating-point fuzz value.
  return FloatNode(floatVal: value)

proc stringValue*(value: string): Value =
  ## Constructs a string fuzz value.
  return StringNode(stringVal: value)

proc enumValue*(value: int64): Value =
  ## Constructs an enum-like fuzz value.
  return EnumNode(enumVal: value)

proc arrayValue*(items: seq[Value]): Value =
  ## Constructs an array fuzz value.
  var elems: seq[ref FuzzNode] = @[]
  for item in items:
    var child: ref FuzzNode
    new child
    child[] = item
    elems.add child
  return SeqNode(elems: elems)

proc objectValue*(): Value =
  ## Constructs an empty object fuzz value.
  return ObjectNode(fieldNames: @[], fieldValues: @[])

proc noneValue*(): Value =
  ## Constructs an empty option fuzz value.
  return OptionNode(optVal: nil)

proc someValue*(value: Value): Value =
  ## Constructs a present option fuzz value.
  var child: ref FuzzNode
  new child
  child[] = value
  return OptionNode(optVal: child)

proc addElem*(value: var Value; item: Value) =
  ## Appends `item` to an array fuzz value.
  if nodeKind(value) == nkSeq:
    var child: ref FuzzNode
    new child
    child[] = item
    value.elems.add child

proc addField*(value: var Value; name: string; item: Value) =
  ## Appends `name = item` to an object fuzz value.
  if nodeKind(value) == nkObject:
    var child: ref FuzzNode
    new child
    child[] = item
    value.fieldNames.add name
    value.fieldValues.add child

proc isSome*(value: Value): bool =
  ## Returns true when `value` is a present option.
  result = nodeKind(value) == nkOption and value.optVal != nil

proc getBool*(value: Value; outp: var bool): bool =
  ## Extracts a boolean payload.
  if nodeKind(value) != nkBool:
    return false
  outp = value.boolVal
  result = true

proc getInt*(value: Value; outp: var int64): bool =
  ## Extracts an integer payload.
  if nodeKind(value) == nkInt:
    outp = value.intVal
    return true
  if nodeKind(value) == nkEnum:
    outp = value.enumVal
    return true
  result = false

proc getFloat*(value: Value; outp: var float64): bool =
  ## Extracts a floating-point payload.
  if nodeKind(value) != nkFloat:
    return false
  outp = value.floatVal
  result = true

proc getString*(value: Value; outp: var string): bool =
  ## Extracts a string payload.
  if nodeKind(value) != nkString:
    return false
  outp = value.stringVal
  result = true

proc getArray*(value: Value; outp: var seq[Value]): bool =
  ## Extracts an array payload.
  if nodeKind(value) != nkSeq:
    return false
  outp = @[]
  for item in value.elems:
    outp.add item[]
  result = true

proc getOption*(value: Value; outp: var Value): bool =
  ## Extracts the payload from a present option.
  if nodeKind(value) != nkOption or value.optVal == nil:
    return false
  outp = value.optVal[]
  result = true

proc findField*(value: Value; name: string; outp: var Value): bool =
  ## Looks up `name` in an object value.
  if nodeKind(value) != nkObject:
    return false
  for i in 0..<min(value.fieldNames.len, value.fieldValues.len):
    if value.fieldNames[i] == name:
      outp = value.fieldValues[i][]
      return true
  result = false

proc nodeKind*(node: FuzzNode): NodeKind =
  ## Returns the runtime variant tag for `node`.
  case node
  of BoolNode:
    result = nkBool
  of IntNode:
    result = nkInt
  of FloatNode:
    result = nkFloat
  of StringNode:
    result = nkString
  of EnumNode:
    result = nkEnum
  of SeqNode:
    result = nkSeq
  of ObjectNode:
    result = nkObject
  of OptionNode:
    result = nkOption

proc schemaKind*(schema: SchemaNode): SchemaKind =
  ## Returns the runtime variant tag for `schema`.
  result = schema.kind
