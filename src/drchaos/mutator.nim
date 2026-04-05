## LPM-style structure-aware mutator over decoded structured node trees.

import model, option, rng, schema

proc defaultNode(schema: SchemaNode): FuzzNode
proc clampInt(value, lowValue, highValue: int): int
proc nodeFromValue(value: bool): FuzzNode
proc nodeFromValue[T: SomeInteger](value: T): FuzzNode
proc nodeFromValue[T: SomeFloat](value: T): FuzzNode
proc nodeFromValue(value: string): FuzzNode
proc nodeFromValue[T: enum](value: T): FuzzNode
proc nodeFromValue[T](value: seq[T]): FuzzNode {.untyped.}
proc nodeFromValue[I, T](value: array[I, T]): FuzzNode {.untyped.}
proc nodeFromValue[T](value: Option[T]): FuzzNode {.untyped.}
proc nodeFromValue[T](value: ref T): FuzzNode {.untyped.}
proc nodeFromValue[T: object](value: T): FuzzNode
proc valueFromNode(node: FuzzNode; value: var bool)
proc valueFromNode[T: SomeInteger](node: FuzzNode; value: var T)
proc valueFromNode[T: SomeFloat](node: FuzzNode; value: var T)
proc valueFromNode(node: FuzzNode; value: var string)
proc valueFromNode[T: enum](node: FuzzNode; value: var T)
proc valueFromNode[T](node: FuzzNode; value: var seq[T]) {.untyped.}
proc valueFromNode[I, T](node: FuzzNode; value: var array[I, T]) {.untyped.}
proc valueFromNode[T](node: FuzzNode; value: var Option[T]) {.untyped.}
proc valueFromNode[T](node: FuzzNode; value: var ref T) {.untyped.}
proc valueFromNode[T: object](node: FuzzNode; value: var T)

proc deepCopyNode(node: FuzzNode): FuzzNode =
  case node
  of BoolNode:
    result = BoolNode(boolVal: node.boolVal)
  of IntNode:
    result = IntNode(intVal: node.intVal)
  of FloatNode:
    result = FloatNode(floatVal: node.floatVal)
  of StringNode:
    result = StringNode(stringVal: node.stringVal)
  of EnumNode:
    result = EnumNode(enumVal: node.enumVal)
  of SeqNode:
    result = SeqNode(elems: @[])
    for item in node.elems:
      result.elems.add deepCopyNode(item)
  of ObjectNode:
    result = ObjectNode(fields: @[])
    for field in node.fields:
      result.fields.add FieldNode(name: field.name, value: deepCopyNode(field.value))
  of OptionNode:
    result = OptionNode(optVal: @[])
    if node.optVal.len > 0:
      result.optVal.add deepCopyNode(node.optVal[0])

proc appendIndex(path: seq[int]; index: int): seq[int] =
  result = newSeq[int](path.len + 1)
  for i in 0..<path.len:
    result[i] = path[i]
  result[path.len] = index

proc trimNodes(items: var seq[FuzzNode]; newLen: int) =
  let limit = clampInt(newLen, 0, items.len)
  var resized: seq[FuzzNode] = @[]
  for i in 0..<limit:
    resized.add items[i]
  items = resized

proc removeNodeAt(items: var seq[FuzzNode]; index: int) =
  if items.len == 0:
    return
  let at = clampInt(index, 0, items.high)
  var resized: seq[FuzzNode] = @[]
  for i in 0..<items.len:
    if i != at:
      resized.add items[i]
  items = resized

proc insertNodeAt(items: var seq[FuzzNode]; index: int; item: FuzzNode) =
  let at = clampInt(index, 0, items.len)
  var resized: seq[FuzzNode] = @[]
  for i in 0..<at:
    resized.add items[i]
  resized.add item
  for i in at..<items.len:
    resized.add items[i]
  items = resized

proc nodeFromSeq[T](value: seq[T]): FuzzNode {.untyped.} =
  result = SeqNode(elems: @[])
  for item in value:
    result.elems.add nodeFromValue(item)

proc nodeFromArray[I, T](value: array[I, T]): FuzzNode {.untyped.} =
  result = SeqNode(elems: @[])
  for item in value:
    result.elems.add nodeFromValue(item)

proc nodeFromOption[T](value: Option[T]): FuzzNode {.untyped.} =
  if value.hasValue:
    result = OptionNode(optVal: @[nodeFromValue(value.value)])
  else:
    result = OptionNode(optVal: @[])

proc nodeFromRef[T](value: ref T): FuzzNode {.untyped.} =
  if value != nil:
    result = OptionNode(optVal: @[nodeFromValue(value[])])
  else:
    result = OptionNode(optVal: @[])

proc nodeFromObject[T: object](value: T): FuzzNode =
  result = ObjectNode(fields: @[])
  for fieldName, field in fieldPairs(value):
    result.fields.add FieldNode(name: fieldName, value: nodeFromValue(field))

proc nodeFromValue(value: bool): FuzzNode =
  result = BoolNode(boolVal: value)

proc nodeFromValue[T: SomeInteger](value: T): FuzzNode =
  result = IntNode(intVal: int64(value))

proc nodeFromValue[T: SomeFloat](value: T): FuzzNode =
  result = FloatNode(floatVal: float64(value))

proc nodeFromValue(value: string): FuzzNode =
  result = StringNode(stringVal: value)

proc nodeFromValue[T: enum](value: T): FuzzNode =
  result = EnumNode(enumVal: int64(value.ord))

proc nodeFromValue[T](value: seq[T]): FuzzNode {.untyped.} =
  result = nodeFromSeq(value)

proc nodeFromValue[I, T](value: array[I, T]): FuzzNode {.untyped.} =
  result = nodeFromArray(value)

proc nodeFromValue[T](value: Option[T]): FuzzNode {.untyped.} =
  result = nodeFromOption(value)

proc nodeFromValue[T](value: ref T): FuzzNode {.untyped.} =
  result = nodeFromRef(value)

proc nodeFromValue[T: object](value: T): FuzzNode =
  result = nodeFromObject(value)

proc valueFromSeq[T](node: FuzzNode; value: var seq[T]) {.untyped.} =
  case node
  of SeqNode:
    value = newSeq[T](node.elems.len)
    for i in 0..<node.elems.len:
      valueFromNode(node.elems[i], value[i])
  else:
    discard

proc valueFromArray[I, T](node: FuzzNode; value: var array[I, T]) {.untyped.} =
  case node
  of SeqNode:
    let limit = min(node.elems.len, value.len)
    for i in 0..<limit:
      valueFromNode(node.elems[i], value[i])
  else:
    discard

proc valueFromOption[T](node: FuzzNode; value: var Option[T]) {.untyped.} =
  case node
  of OptionNode:
    if node.optVal.len > 0:
      var item = default(T)
      valueFromNode(node.optVal[0], item)
      value = some(item)
    else:
      value = none[T]()
  else:
    discard

proc valueFromRef[T](node: FuzzNode; value: var ref T) {.untyped.} =
  case node
  of OptionNode:
    if node.optVal.len > 0:
      new(value)
      valueFromNode(node.optVal[0], value[])
    else:
      value = nil
  else:
    discard

proc valueFromObject[T: object](node: FuzzNode; outp: var T) {.untyped.} =
  case node
  of ObjectNode:
    outp = default(T)
    for inputField in node.fields:
      for fieldName, field in fieldPairs(outp):
        if fieldName == inputField.name:
          valueFromNode(inputField.value, field)
          break
  else:
    discard

proc valueFromNode(node: FuzzNode; value: var bool) =
  case node
  of BoolNode:
    value = node.boolVal
  else:
    discard

proc valueFromNode[T: SomeInteger](node: FuzzNode; value: var T) =
  case node
  of IntNode:
    value = T(node.intVal)
  of EnumNode:
    value = T(node.enumVal)
  else:
    discard

proc valueFromNode[T: SomeFloat](node: FuzzNode; value: var T) =
  case node
  of FloatNode:
    value = T(node.floatVal)
  else:
    discard

proc valueFromNode(node: FuzzNode; value: var string) =
  case node
  of StringNode:
    value = node.stringVal
  else:
    discard

proc valueFromNode[T: enum](node: FuzzNode; value: var T) =
  var ordinal = 0
  case node
  of EnumNode:
    ordinal = int(node.enumVal)
  of IntNode:
    ordinal = int(node.intVal)
  else:
    return

  if ordinal < low(T).ord:
    value = low(T)
  elif ordinal > high(T).ord:
    value = high(T)
  else:
    value = T(ordinal)

proc valueFromNode[T](node: FuzzNode; value: var seq[T]) {.untyped.} =
  valueFromSeq(node, value)

proc valueFromNode[I, T](node: FuzzNode; value: var array[I, T]) {.untyped.} =
  valueFromArray(node, value)

proc valueFromNode[T](node: FuzzNode; value: var Option[T]) {.untyped.} =
  valueFromOption(node, value)

proc valueFromNode[T](node: FuzzNode; value: var ref T) {.untyped.} =
  valueFromRef(node, value)

proc valueFromNode[T: object](node: FuzzNode; value: var T) =
  valueFromObject(node, value)

proc approxSize(node: FuzzNode): int =
  result = 0
  case node
  of BoolNode:
    result = 1
  of IntNode:
    result = 8
  of FloatNode:
    result = 8
  of EnumNode:
    result = 8
  of StringNode:
    result = node.stringVal.len
  of SeqNode:
    for item in node.elems:
      result.inc approxSize(item)
  of ObjectNode:
    for field in node.fields:
      result.inc field.name.len
      result.inc approxSize(field.value)
  of OptionNode:
    if node.optVal.len > 0:
      result = 1 + approxSize(node.optVal[0])
    else:
      result = 1

proc defaultNode(schema: SchemaNode): FuzzNode =
  case schema
  of BoolSchema:
    result = BoolNode(boolVal: false)
  of IntSchema:
    result = IntNode(intVal: 0)
  of FloatSchema:
    result = FloatNode(floatVal: 0.0)
  of StringSchema:
    result = StringNode(stringVal: "")
  of EnumSchema:
    result = EnumNode(enumVal: 0)
  of SeqSchema:
    result = SeqNode(elems: @[])
  of ObjectSchema:
    result = ObjectNode(fields: @[])
    for field in schema.fields:
      result.fields.add FieldNode(name: field.name, value: defaultNode(field.node))
  of OptionSchema:
    result = OptionNode(optVal: @[])

proc mutateInt(value: int64; r: var Rand): int64 =
  let bit = r.randInt(0, 62)
  result = value xor (1'i64 shl bit)

proc mutateFloat(value: float64; r: var Rand): float64 =
  result = value + float64(r.randInt(-1000, 1000)) / 100.0

proc mutateString(value: string; config: FuzzConfig; r: var Rand): string =
  result = value
  if config.dictionary.len > 0 and r.randInt(0, 4) == 0:
    result.add config.dictionary[r.randInt(config.dictionary.high)]
  elif result.len == 0:
    result.add char(r.randInt(32, 126))
  elif r.randBool:
    let at = r.randInt(0, result.high)
    result[at] = char(r.randInt(32, 126))
  else:
    result.add char(r.randInt(32, 126))
  if result.len > config.maxStringLen:
    result.setLen(config.maxStringLen)

proc clampInt(value, lowValue, highValue: int): int =
  if value < lowValue:
    result = lowValue
  elif value > highValue:
    result = highValue
  else:
    result = value

proc mutateLeaf(node: var FuzzNode; schema: SchemaNode; config: FuzzConfig;
    r: var Rand) =
  case node
  of BoolNode:
    node = BoolNode(boolVal: not node.boolVal)
  of IntNode:
    node = IntNode(intVal: mutateInt(node.intVal, r))
  of EnumNode:
    case schema
    of EnumSchema:
      if schema.enumNames.len > 1:
        let current = clampInt(node.enumVal.int, 0, schema.enumNames.high)
        var next = current
        while next == current:
          next = r.randInt(0, schema.enumNames.high)
        node = EnumNode(enumVal: next)
    else:
      discard
  of FloatNode:
    node = FloatNode(floatVal: mutateFloat(node.floatVal, r))
  of StringNode:
    node = StringNode(stringVal: mutateString(node.stringVal, config, r))
  of SeqNode, ObjectNode, OptionNode:
    discard

proc seedNode(node: var FuzzNode; schema: SchemaNode; config: FuzzConfig;
    r: var Rand; depth = 0) =
  case node
  of BoolNode, IntNode, FloatNode, StringNode, EnumNode:
    mutateLeaf(node, schema, config, r)
  of SeqNode:
    case schema
    of SeqSchema:
      if depth < config.maxDepth and node.elems.len < config.maxSeqLen:
        let additions = 1 + r.randInt(min(1, config.maxSeqLen - 1))
        for _ in 0..<additions:
          var child = defaultNode(schema.elem)
          if depth + 1 < config.maxDepth:
            seedNode(child, schema.elem, config, r, depth + 1)
          node.elems.add child
    else:
      discard
  of ObjectNode:
    case schema
    of ObjectSchema:
      for i in 0..<min(node.fields.len, schema.fields.len):
        if r.randBool:
          seedNode(node.fields[i].value, schema.fields[i].node, config, r, depth + 1)
    else:
      discard
  of OptionNode:
    case schema
    of OptionSchema:
      if node.optVal.len == 0 and depth < config.maxDepth:
        var child = defaultNode(schema.elem)
        if depth + 1 < config.maxDepth:
          seedNode(child, schema.elem, config, r, depth + 1)
        node.optVal = @[child]
    else:
      discard

proc schemaAtPath(schema: SchemaNode; path: openArray[int]; depth = 0): SchemaNode =
  if depth >= path.len:
    return schema
  let index = path[depth]
  case schema
  of SeqSchema:
    result = schemaAtPath(schema.elem, path, depth + 1)
  of OptionSchema:
    result = schemaAtPath(schema.elem, path, depth + 1)
  of ObjectSchema:
    if index < schema.fields.len:
      result = schemaAtPath(schema.fields[index].node, path, depth + 1)
    else:
      result = schema
  else:
    result = schema

proc mutateAtPath(node: var FuzzNode; schema: SchemaNode; path: openArray[int];
    config: FuzzConfig; r: var Rand; depth = 0) =
  if depth >= path.len:
    mutateLeaf(node, schema, config, r)
    return
  let index = path[depth]
  case node
  of SeqNode:
    case schema
    of SeqSchema:
      if index < node.elems.len:
        mutateAtPath(node.elems[index], schema.elem, path, config, r, depth + 1)
    else:
      discard
  of ObjectNode:
    case schema
    of ObjectSchema:
      if index < node.fields.len and index < schema.fields.len:
        mutateAtPath(node.fields[index].value, schema.fields[index].node, path, config, r, depth + 1)
    else:
      discard
  of OptionNode:
    case schema
    of OptionSchema:
      if node.optVal.len > 0:
        mutateAtPath(node.optVal[0], schema.elem, path, config, r, depth + 1)
    else:
      discard
  else:
    discard

proc addAtPath(node: var FuzzNode; schema: SchemaNode; path: openArray[int];
    config: FuzzConfig; r: var Rand; depth = 0) =
  if depth >= path.len:
    case node
    of SeqNode:
      case schema
      of SeqSchema:
        if node.elems.len < config.maxSeqLen:
          var child = defaultNode(schema.elem)
          seedNode(child, schema.elem, config, r, depth + 1)
          insertNodeAt(node.elems, r.randInt(0, node.elems.len), child)
      else:
        discard
    of OptionNode:
      case schema
      of OptionSchema:
        if node.optVal.len == 0:
          var child = defaultNode(schema.elem)
          seedNode(child, schema.elem, config, r, depth + 1)
          node.optVal = @[child]
      else:
        discard
    else:
      discard
    return

  let index = path[depth]
  case node
  of SeqNode:
    case schema
    of SeqSchema:
      if index < node.elems.len:
        addAtPath(node.elems[index], schema.elem, path, config, r, depth + 1)
    else:
      discard
  of ObjectNode:
    case schema
    of ObjectSchema:
      if index < node.fields.len and index < schema.fields.len:
        addAtPath(node.fields[index].value, schema.fields[index].node, path, config, r, depth + 1)
    else:
      discard
  of OptionNode:
    case schema
    of OptionSchema:
      if node.optVal.len > 0:
        addAtPath(node.optVal[0], schema.elem, path, config, r, depth + 1)
    else:
      discard
  else:
    discard

proc deleteAtPath(node: var FuzzNode; path: openArray[int]; r: var Rand;
    depth = 0) =
  if depth >= path.len:
    case node
    of SeqNode:
      if node.elems.len > 0:
        removeNodeAt(node.elems, r.randInt(node.elems.high))
    of OptionNode:
      node.optVal = @[]
    else:
      discard
    return

  let index = path[depth]
  case node
  of SeqNode:
    if index < node.elems.len:
      deleteAtPath(node.elems[index], path, r, depth + 1)
  of ObjectNode:
    if index < node.fields.len:
      deleteAtPath(node.fields[index].value, path, r, depth + 1)
  of OptionNode:
    if node.optVal.len > 0:
      deleteAtPath(node.optVal[0], path, r, depth + 1)
  else:
    discard

proc assignAtPath(node: var FuzzNode; path: openArray[int]; donor: FuzzNode;
    config: FuzzConfig; isClone: bool; r: var Rand; depth = 0) =
  if depth >= path.len:
    case node
    of SeqNode:
      if isClone:
        if node.elems.len < config.maxSeqLen:
          insertNodeAt(node.elems, r.randInt(0, node.elems.len), donor)
      else:
        node = donor
    of OptionNode:
      if isClone:
        node.optVal = @[donor]
      else:
        node = donor
    else:
      node = donor
    return

  let index = path[depth]
  case node
  of SeqNode:
    if index < node.elems.len:
      assignAtPath(node.elems[index], path, donor, config, isClone, r, depth + 1)
  of ObjectNode:
    if index < node.fields.len:
      assignAtPath(node.fields[index].value, path, donor, config, isClone, r, depth + 1)
  of OptionNode:
    if node.optVal.len > 0:
      assignAtPath(node.optVal[0], path, donor, config, isClone, r, depth + 1)
  else:
    discard

proc candidateWeight(schema: SchemaNode; op: MutationKind): int =
  let baseWeight = int(schema.mutationWeight)
  case op
  of mkMutate:
    result = baseWeight * 4
  of mkAdd, mkClone:
    result = baseWeight * 3
  of mkCopy:
    result = baseWeight * 2
  of mkDelete:
    result = baseWeight
  of mkNone:
    result = 0

proc addCandidate(outp: var seq[MutationCandidate]; op: MutationKind; path: seq[int];
    schema: SchemaNode) =
  let weight = candidateWeight(schema, op)
  if weight > 0:
    outp.add MutationCandidate(op: op, path: path, weight: weight)

proc collectCandidates(node: FuzzNode; schema: SchemaNode; path: seq[int];
    config: FuzzConfig; outp: var seq[MutationCandidate]) =
  case node
  of BoolNode, IntNode, FloatNode, StringNode, EnumNode:
    addCandidate(outp, mkMutate, path, schema)
  of SeqNode:
    addCandidate(outp, mkCopy, path, schema)
    if node.elems.len < config.maxSeqLen:
      addCandidate(outp, mkAdd, path, schema)
      addCandidate(outp, mkClone, path, schema)
    if node.elems.len > 0:
      addCandidate(outp, mkDelete, path, schema)
    case schema
    of SeqSchema:
      for i in 0..<node.elems.len:
        let childPath = appendIndex(path, i)
        collectCandidates(node.elems[i], schema.elem, childPath, config, outp)
    else:
      discard
  of ObjectNode:
    addCandidate(outp, mkCopy, path, schema)
    case schema
    of ObjectSchema:
      for i in 0..<min(node.fields.len, schema.fields.len):
        let childPath = appendIndex(path, i)
        collectCandidates(node.fields[i].value, schema.fields[i].node, childPath, config, outp)
    else:
      discard
  of OptionNode:
    if node.optVal.len > 0:
      addCandidate(outp, mkDelete, path, schema)
      addCandidate(outp, mkCopy, path, schema)
      case schema
      of OptionSchema:
        let childPath = appendIndex(path, 0)
        collectCandidates(node.optVal[0], schema.elem, childPath, config, outp)
      else:
        discard
    else:
      addCandidate(outp, mkAdd, path, schema)
      addCandidate(outp, mkClone, path, schema)

proc collectCrossOverCandidates(node: FuzzNode; schema: SchemaNode; path: seq[int];
    config: FuzzConfig; outp: var seq[MutationCandidate]) =
  addCandidate(outp, mkCopy, path, schema)
  case node
  of SeqNode:
    if node.elems.len < config.maxSeqLen:
      addCandidate(outp, mkClone, path, schema)
    case schema
    of SeqSchema:
      for i in 0..<node.elems.len:
        let childPath = appendIndex(path, i)
        collectCrossOverCandidates(node.elems[i], schema.elem, childPath, config, outp)
    else:
      discard
  of ObjectNode:
    case schema
    of ObjectSchema:
      for i in 0..<min(node.fields.len, schema.fields.len):
        let childPath = appendIndex(path, i)
        collectCrossOverCandidates(node.fields[i].value, schema.fields[i].node, childPath, config, outp)
    else:
      discard
  of OptionNode:
    case schema
    of OptionSchema:
      if node.optVal.len > 0:
        let childPath = appendIndex(path, 0)
        collectCrossOverCandidates(node.optVal[0], schema.elem, childPath, config, outp)
      else:
        addCandidate(outp, mkClone, path, schema)
    else:
      discard
  else:
    discard

proc schemaCompatible(target, donor: SchemaNode): bool =
  if target == nil or donor == nil:
    return false

  case target
  of BoolSchema:
    case donor
    of BoolSchema:
      result = true
    else:
      result = false
  of IntSchema:
    case donor
    of IntSchema:
      result = true
    else:
      result = false
  of FloatSchema:
    case donor
    of FloatSchema:
      result = true
    else:
      result = false
  of StringSchema:
    case donor
    of StringSchema:
      result = true
    else:
      result = false
  of EnumSchema:
    case donor
    of EnumSchema:
      result = target.enumNames == donor.enumNames
    else:
      result = false
  of SeqSchema:
    case donor
    of SeqSchema:
      result = schemaCompatible(target.elem, donor.elem)
    else:
      result = false
  of OptionSchema:
    case donor
    of OptionSchema:
      result = schemaCompatible(target.elem, donor.elem)
    else:
      result = false
  of ObjectSchema:
    case donor
    of ObjectSchema:
      if target.fields.len != donor.fields.len:
        return false
      result = true
      for i in 0..<target.fields.len:
        if target.fields[i].name != donor.fields[i].name:
          return false
        if not schemaCompatible(target.fields[i].node, donor.fields[i].node):
          return false
    else:
      result = false

proc collectCompatibleSources(targetSchema: SchemaNode; sourceNode: FuzzNode;
    sourceSchema: SchemaNode; outp: var seq[FuzzNode]) =
  if schemaCompatible(targetSchema, sourceSchema):
    outp.add deepCopyNode(sourceNode)

  case sourceNode
  of SeqNode:
    case sourceSchema
    of SeqSchema:
      for child in sourceNode.elems:
        collectCompatibleSources(targetSchema, child, sourceSchema.elem, outp)
    else:
      discard
  of ObjectNode:
    case sourceSchema
    of ObjectSchema:
      for i in 0..<min(sourceNode.fields.len, sourceSchema.fields.len):
        collectCompatibleSources(targetSchema, sourceNode.fields[i].value, sourceSchema.fields[i].node, outp)
    else:
      discard
  of OptionNode:
    case sourceSchema
    of OptionSchema:
      if sourceNode.optVal.len > 0:
        collectCompatibleSources(targetSchema, sourceNode.optVal[0], sourceSchema.elem, outp)
    else:
      discard
  else:
    discard

proc pickWeightedIndex(candidates: seq[MutationCandidate]; r: var Rand): int =
  var total = 0'u64
  for candidate in candidates:
    total = total + uint64(max(candidate.weight, 1))
  if total == 0'u64:
    return 0
  let target = r.nextUint64() mod total
  var cursor = 0'u64
  for i in 0..<candidates.len:
    cursor = cursor + uint64(max(candidates[i].weight, 1))
    if target < cursor:
      return i
  result = candidates.high

proc removeCandidateAt(candidates: var seq[MutationCandidate]; index: int) =
  if candidates.len == 0:
    return
  let at = clampInt(index, 0, candidates.high)
  var resized = newSeq[MutationCandidate](candidates.len - 1)
  var dst = 0
  for i in 0..<candidates.len:
    if i != at:
      resized[dst] = candidates[i]
      inc dst
  candidates = resized

proc donorSchemaFor(schema: SchemaNode; choice: MutationCandidate): SchemaNode =
  let targetSchema = schemaAtPath(schema, choice.path)
  case choice.op
  of mkClone:
    case targetSchema
    of SeqSchema:
      result = targetSchema.elem
    of OptionSchema:
      result = targetSchema.elem
    else:
      result = targetSchema
  else:
    result = targetSchema

proc shrinkToBudget(node: var FuzzNode; schema: SchemaNode; config: FuzzConfig) =
  while approxSize(node) > config.maxBytes:
    case node
    of StringNode:
      if node.stringVal.len == 0:
        break
      node.stringVal.setLen(node.stringVal.len div 2)
    of SeqNode:
      if node.elems.len == 0:
        break
      trimNodes(node.elems, node.elems.len - 1)
    of OptionNode:
      if node.optVal.len > 0:
        node.optVal = @[]
      else:
        break
    of ObjectNode:
      case schema
      of ObjectSchema:
        if node.fields.len == 0:
          break
        let last = node.fields.high
        node.fields[last].value = defaultNode(schema.fields[last].node)
        break
      else:
        break
    else:
      break

proc fixNode(node: var FuzzNode; schema: SchemaNode; config: FuzzConfig;
    depth = 0) =
  ## Trims node contents to the configured depth and size limits.
  if depth >= config.maxDepth:
    node = defaultNode(schema)
    return

  case node
  of StringNode:
    if node.stringVal.len > config.maxStringLen:
      node.stringVal.setLen(config.maxStringLen)
  of SeqNode:
    case schema
    of SeqSchema:
      if node.elems.len > config.maxSeqLen:
        trimNodes(node.elems, config.maxSeqLen)
      for i in 0..<node.elems.len:
        fixNode(node.elems[i], schema.elem, config, depth + 1)
    else:
      node = defaultNode(schema)
  of ObjectNode:
    case schema
    of ObjectSchema:
      var normalized: seq[FieldNode] = @[]
      for i in 0..<schema.fields.len:
        var fieldValue = defaultNode(schema.fields[i].node)
        var found = false
        if i < node.fields.len and node.fields[i].name == schema.fields[i].name:
          fieldValue = node.fields[i].value
          found = true
        if not found:
          for field in node.fields:
            if field.name == schema.fields[i].name:
              fieldValue = field.value
              found = true
              break
        fixNode(fieldValue, schema.fields[i].node, config, depth + 1)
        normalized.add FieldNode(name: schema.fields[i].name, value: fieldValue)
      node.fields = normalized
    else:
      node = defaultNode(schema)
  of OptionNode:
    case schema
    of OptionSchema:
      if node.optVal.len > 1:
        trimNodes(node.optVal, 1)
      if node.optVal.len > 0:
        fixNode(node.optVal[0], schema.elem, config, depth + 1)
    else:
      node = defaultNode(schema)
  of BoolNode:
    case schema
    of BoolSchema:
      discard
    else:
      node = defaultNode(schema)
  of IntNode:
    case schema
    of IntSchema:
      discard
    else:
      node = defaultNode(schema)
  of FloatNode:
    case schema
    of FloatSchema:
      discard
    else:
      node = defaultNode(schema)
  of EnumNode:
    case schema
    of EnumSchema:
      if node.enumVal < 0:
        node.enumVal = 0
      elif schema.enumNames.len > 0 and node.enumVal.int > schema.enumNames.high:
        node.enumVal = int64(schema.enumNames.high)
    else:
      node = defaultNode(schema)

  shrinkToBudget(node, schema, config)

proc tryApplyDonor(node: var FuzzNode; schema: SchemaNode; config: FuzzConfig;
    choice: MutationCandidate; sources: openArray[FuzzNode]; r: var Rand): bool =
  let targetSchema = donorSchemaFor(schema, choice)
  var donors: seq[FuzzNode] = @[]
  for source in sources:
    collectCompatibleSources(targetSchema, source, schema, donors)
  if donors.len == 0:
    return false
  let donor = donors[r.randInt(donors.high)]
  assignAtPath(node, choice.path, donor, config, choice.op == mkClone, r)
  result = true

proc mutateNode(node: var FuzzNode; schema: SchemaNode; config: FuzzConfig;
    sources: openArray[FuzzNode]; seed: uint32) =
  ## Applies one structure-aware mutation to `node`.
  var r = initRand(seed)
  var candidates: seq[MutationCandidate] = @[]
  collectCandidates(node, schema, @[], config, candidates)
  while candidates.len > 0:
    let index = pickWeightedIndex(candidates, r)
    let choice = candidates[index]
    case choice.op
    of mkAdd:
      addAtPath(node, schema, choice.path, config, r)
      break
    of mkMutate:
      mutateAtPath(node, schema, choice.path, config, r)
      break
    of mkDelete:
      deleteAtPath(node, choice.path, r)
      break
    of mkCopy, mkClone:
      if tryApplyDonor(node, schema, config, choice, sources, r):
        break
      removeCandidateAt(candidates, index)
    of mkNone:
      removeCandidateAt(candidates, index)
  fixNode(node, schema, config)

proc crossOverNode(node: var FuzzNode; schema: SchemaNode; config: FuzzConfig;
    donors: openArray[FuzzNode]; seed: uint32) =
  ## Applies one copy/clone-only crossover step to `node`.
  var r = initRand(seed)
  var candidates: seq[MutationCandidate] = @[]
  collectCrossOverCandidates(node, schema, @[], config, candidates)
  while candidates.len > 0:
    let index = pickWeightedIndex(candidates, r)
    let choice = candidates[index]
    if tryApplyDonor(node, schema, config, choice, donors, r):
      break
    removeCandidateAt(candidates, index)
  fixNode(node, schema, config)

proc mutateValue*[T](value: var T; config: FuzzConfig; sources: openArray[T];
    seed: uint32) {.untyped.} =
  ## Converts `value` to a node tree, mutates it, and decodes it back.
  var node = nodeFromValue(value)
  let typeSchema = schemaFor(T)
  var sourceNodes: seq[FuzzNode] = @[]
  for item in sources:
    sourceNodes.add nodeFromValue(item)
  mutateNode(node, typeSchema, config, sourceNodes, seed)
  valueFromNode(node, value)

proc crossOverValue*[T](value: var T; config: FuzzConfig; donors: openArray[T];
    seed: uint32) {.untyped.} =
  ## Converts `value` to a node tree, performs copy/clone-only crossover, and decodes it back.
  var node = nodeFromValue(value)
  let typeSchema = schemaFor(T)
  var donorNodes: seq[FuzzNode] = @[]
  for item in donors:
    donorNodes.add nodeFromValue(item)
  crossOverNode(node, typeSchema, config, donorNodes, seed)
  valueFromNode(node, value)
