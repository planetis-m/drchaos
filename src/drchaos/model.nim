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

  FieldNode* = object
    name*: string
    value*: FuzzNode

  FieldSchema* = object
    name*: string
    node*: SchemaNode

  FuzzNode* = object
    case kind*: NodeKind
    of nkBool:
      boolVal*: bool
    of nkInt:
      intVal*: int64
    of nkFloat:
      floatVal*: float64
    of nkString:
      stringVal*: string
    of nkEnum:
      enumVal*: int64
    of nkSeq:
      elems*: seq[FuzzNode]
    of nkObject:
      fields*: seq[FieldNode]
    of nkOption:
      optVal*: seq[FuzzNode]

  SchemaNode* = ref object
    kind*: SchemaKind
    mutationWeight*: Positive
    fields*: seq[FieldSchema]
    elem*: SchemaNode
    enumNames*: seq[string]

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
