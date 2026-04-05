## Core runtime data structures for the drchaos structured fuzzing engine.

type
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
      elems*: seq[FuzzNode]
    of ObjectNode:
      fields*: seq[FieldNode]
    of OptionNode:
      optVal*: seq[FuzzNode]

  FieldNode* = object
    name*: string
    value*: FuzzNode

  SchemaNode* = ref object
    mutationWeight*: Positive
    case
    of BoolSchema, IntSchema, FloatSchema, StringSchema:
      discard
    of EnumSchema:
      enumNames*: seq[string]
    of SeqSchema, OptionSchema:
      elem*: SchemaNode
    of ObjectSchema:
      fields*: seq[FieldSchema]

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

proc default*(_: typedesc[FuzzNode]): FuzzNode =
  ## Returns the default zero-like node used for seq allocation and resets.
  result = BoolNode(boolVal: false)
