## LPM-style structure-aware mutator over decoded structured node trees.

import codec, model, option, rng, schema

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

proc boxed(node: FuzzNode): ref FuzzNode =
  new(result)
  result[] = node

proc appendIndex(path: seq[int]; index: int): seq[int] =
  result = newSeq[int](path.len + 1)
  for i in 0..<path.len:
    result[i] = path[i]
  result[path.len] = index

proc trimNodes(items: var seq[FuzzNode]; newLen: int) =
  let limit = clampInt(newLen, 0, items.len)
  var resized = newSeq[FuzzNode](limit)
  for i in 0..<limit:
    resized[i] = items[i]
  items = resized

proc removeNodeAt(items: var seq[FuzzNode]; index: int) =
  if items.len == 0:
    return
  let at = clampInt(index, 0, items.high)
  var resized = newSeq[FuzzNode](items.len - 1)
  var dst = 0
  for i in 0..<items.len:
    if i != at:
      resized[dst] = items[i]
      inc dst
  items = resized

proc insertNodeAt(items: var seq[FuzzNode]; index: int; item: FuzzNode) =
  let at = clampInt(index, 0, items.len)
  var resized = newSeq[FuzzNode](items.len + 1)
  for i in 0..<at:
    resized[i] = items[i]
  resized[at] = item
  for i in at..<items.len:
    resized[i + 1] = items[i]
  items = resized

proc nodeFromSeq[T](value: seq[T]): FuzzNode {.untyped.} =
  result = FuzzNode(kind: nkSeq, elems: @[])
  for item in value:
    result.elems.add nodeFromValue(item)

proc nodeFromArray[I, T](value: array[I, T]): FuzzNode {.untyped.} =
  result = FuzzNode(kind: nkSeq, elems: @[])
  for item in value:
    result.elems.add nodeFromValue(item)

proc nodeFromOption[T](value: Option[T]): FuzzNode {.untyped.} =
  if value.hasValue:
    result = FuzzNode(kind: nkOption, optVal: some(boxed(nodeFromValue(value.value))))
  else:
    result = FuzzNode(kind: nkOption, optVal: none[ref FuzzNode]())

proc nodeFromRef[T](value: ref T): FuzzNode {.untyped.} =
  if value != nil:
    result = FuzzNode(kind: nkOption, optVal: some(boxed(nodeFromValue(value[]))))
  else:
    result = FuzzNode(kind: nkOption, optVal: none[ref FuzzNode]())

proc nodeFromObject[T: object](value: T): FuzzNode =
  result = FuzzNode(kind: nkObject, fields: @[])
  for fieldName, field in fieldPairs(value):
    result.fields.add FieldNode(name: fieldName, value: nodeFromValue(field))

proc nodeFromValue(value: bool): FuzzNode =
  result = FuzzNode(kind: nkBool, boolVal: value)

proc nodeFromValue[T: SomeInteger](value: T): FuzzNode =
  result = FuzzNode(kind: nkInt, intVal: int64(value))

proc nodeFromValue[T: SomeFloat](value: T): FuzzNode =
  result = FuzzNode(kind: nkFloat, floatVal: float64(value))

proc nodeFromValue(value: string): FuzzNode =
  result = FuzzNode(kind: nkString, stringVal: value)

proc nodeFromValue[T: enum](value: T): FuzzNode =
  result = FuzzNode(kind: nkEnum, intVal: int64(value.ord))

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
  if node.kind != nkSeq:
    return
  value = newSeq[T](node.elems.len)
  for i in 0..<node.elems.len:
    valueFromNode(node.elems[i], value[i])

proc valueFromArray[I, T](node: FuzzNode; value: var array[I, T]) {.untyped.} =
  if node.kind != nkSeq:
    return
  let limit = min(node.elems.len, value.len)
  for i in 0..<limit:
    valueFromNode(node.elems[i], value[i])

proc valueFromOption[T](node: FuzzNode; value: var Option[T]) {.untyped.} =
  if node.kind != nkOption:
    return
  if node.optVal.hasValue:
    var item = default(T)
    valueFromNode(node.optVal.value[], item)
    value = some(item)
  else:
    value = none[T]()

proc valueFromRef[T](node: FuzzNode; value: var ref T) {.untyped.} =
  if node.kind != nkOption:
    return
  if node.optVal.hasValue:
    new(value)
    valueFromNode(node.optVal.value[], value[])
  else:
    value = nil

proc valueFromObject[T: object](node: FuzzNode; value: var T) {.untyped.} =
  if node.kind != nkObject:
    return
  value = default(T)
  for inputField in node.fields:
    for fieldName, field in fieldPairs(value):
      if fieldName == inputField.name:
        valueFromNode(inputField.value, field)
        break

proc valueFromNode(node: FuzzNode; value: var bool) =
  if node.kind == nkBool:
    value = node.boolVal

proc valueFromNode[T: SomeInteger](node: FuzzNode; value: var T) =
  if node.kind == nkInt or node.kind == nkEnum:
    value = T(node.intVal)

proc valueFromNode[T: SomeFloat](node: FuzzNode; value: var T) =
  if node.kind == nkFloat:
    value = T(node.floatVal)

proc valueFromNode(node: FuzzNode; value: var string) =
  if node.kind == nkString:
    value = node.stringVal

proc valueFromNode[T: enum](node: FuzzNode; value: var T) =
  if node.kind == nkEnum or node.kind == nkInt:
    let ordinal = int(node.intVal)
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
  case node.kind
  of nkBool:
    result = 1
  of nkInt, nkEnum, nkFloat:
    result = 8
  of nkString:
    result = node.stringVal.len
  of nkSeq:
    for item in node.elems:
      result.inc approxSize(item)
  of nkObject:
    for field in node.fields:
      result.inc field.name.len
      result.inc approxSize(field.value)
  of nkOption:
    if node.optVal.hasValue:
      result = 1 + approxSize(node.optVal.value[])
    else:
      result = 1

proc defaultNode(schema: SchemaNode): FuzzNode =
  case schema.kind
  of skBool:
    result = FuzzNode(kind: nkBool, boolVal: false)
  of skInt:
    result = FuzzNode(kind: nkInt, intVal: 0)
  of skFloat:
    result = FuzzNode(kind: nkFloat, floatVal: 0.0)
  of skString:
    result = FuzzNode(kind: nkString, stringVal: "")
  of skEnum:
    result = FuzzNode(kind: nkEnum, intVal: 0)
  of skSeq:
    result = FuzzNode(kind: nkSeq, elems: @[])
  of skObject:
    result = FuzzNode(kind: nkObject, fields: @[])
    for field in schema.fields:
      result.fields.add FieldNode(name: field.name, value: defaultNode(field.node))
  of skOption:
    result = FuzzNode(kind: nkOption, optVal: none[ref FuzzNode]())

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
  case node.kind
  of nkBool:
    node.boolVal = not node.boolVal
  of nkInt:
    node.intVal = mutateInt(node.intVal, r)
  of nkEnum:
    if schema.enumNames.len > 1:
      let current = clampInt(node.intVal.int, 0, schema.enumNames.high)
      var next = current
      while next == current:
        next = r.randInt(0, schema.enumNames.high)
      node.intVal = next
  of nkFloat:
    node.floatVal = mutateFloat(node.floatVal, r)
  of nkString:
    node.stringVal = mutateString(node.stringVal, config, r)
  of nkSeq, nkObject, nkOption:
    discard

proc schemaAtPath(schema: SchemaNode; path: openArray[int]; depth = 0): SchemaNode =
  if depth >= path.len:
    return schema
  let index = path[depth]
  case schema.kind
  of skSeq, skOption:
    result = schemaAtPath(schema.elem, path, depth + 1)
  of skObject:
    if index < schema.fields.len:
      result = schemaAtPath(schema.fields[index].node, path, depth + 1)
    else:
      result = schema
  else:
    result = schema

proc readPath(node: FuzzNode; path: openArray[int]; target: var FuzzNode;
    depth = 0): bool =
  if depth >= path.len:
    target = node
    return true
  let index = path[depth]
  case node.kind
  of nkSeq:
    if index < node.elems.len:
      result = readPath(node.elems[index], path, target, depth + 1)
  of nkObject:
    if index < node.fields.len:
      result = readPath(node.fields[index].value, path, target, depth + 1)
  of nkOption:
    if node.optVal.hasValue:
      result = readPath(node.optVal.value[], path, target, depth + 1)
  else:
    discard

proc mutateAtPath(node: var FuzzNode; schema: SchemaNode; path: openArray[int];
    config: FuzzConfig; r: var Rand; depth = 0) =
  if depth >= path.len:
    mutateLeaf(node, schema, config, r)
    return
  let index = path[depth]
  case node.kind
  of nkSeq:
    if index < node.elems.len:
      mutateAtPath(node.elems[index], schema.elem, path, config, r, depth + 1)
  of nkObject:
    if index < node.fields.len:
      mutateAtPath(node.fields[index].value, schema.fields[index].node, path,
          config, r, depth + 1)
  of nkOption:
    if node.optVal.hasValue:
      mutateAtPath(node.optVal.value[], schema.elem, path, config, r, depth + 1)
  else:
    discard

proc addAtPath(node: var FuzzNode; schema: SchemaNode; path: openArray[int];
    depth = 0) =
  if depth >= path.len:
    if node.kind == nkOption:
      node.optVal = some(boxed(defaultNode(schema.elem)))
    return
  let index = path[depth]
  case node.kind
  of nkSeq:
    if index < node.elems.len:
      addAtPath(node.elems[index], schema.elem, path, depth + 1)
  of nkObject:
    if index < node.fields.len:
      addAtPath(node.fields[index].value, schema.fields[index].node, path, depth + 1)
  of nkOption:
    if node.optVal.hasValue:
      addAtPath(node.optVal.value[], schema.elem, path, depth + 1)
  else:
    discard

proc deleteAtPath(node: var FuzzNode; path: openArray[int]; r: var Rand;
    depth = 0) =
  if depth >= path.len:
    case node.kind
    of nkSeq:
      if node.elems.len > 0:
        removeNodeAt(node.elems, r.randInt(node.elems.high))
    of nkOption:
      node.optVal = none[ref FuzzNode]()
    else:
      discard
    return
  let index = path[depth]
  case node.kind
  of nkSeq:
    if index < node.elems.len:
      deleteAtPath(node.elems[index], path, r, depth + 1)
  of nkObject:
    if index < node.fields.len:
      deleteAtPath(node.fields[index].value, path, r, depth + 1)
  of nkOption:
    if node.optVal.hasValue:
      deleteAtPath(node.optVal.value[], path, r, depth + 1)
  else:
    discard

proc assignAtPath(node: var FuzzNode; path: openArray[int]; donor: FuzzNode;
    config: FuzzConfig; isClone: bool; r: var Rand; depth = 0) =
  if depth >= path.len:
    if isClone and node.kind == nkSeq:
      if node.elems.len < config.maxSeqLen:
        insertNodeAt(node.elems, r.randInt(0, node.elems.len), donor)
    elif isClone and node.kind == nkOption:
      node.optVal = some(boxed(donor))
    else:
      node = donor
    return
  let index = path[depth]
  case node.kind
  of nkSeq:
    if index < node.elems.len:
      assignAtPath(node.elems[index], path, donor, config, isClone, r, depth + 1)
  of nkObject:
    if index < node.fields.len:
      assignAtPath(node.fields[index].value, path, donor, config, isClone, r,
          depth + 1)
  of nkOption:
    if node.optVal.hasValue:
      assignAtPath(node.optVal.value[], path, donor, config, isClone, r, depth + 1)
  else:
    discard

proc collectCandidates(node: FuzzNode; schema: SchemaNode; path: seq[int];
    config: FuzzConfig; outp: var seq[MutationCandidate]) =
  case node.kind
  of nkBool, nkInt, nkFloat, nkString, nkEnum:
    outp.add MutationCandidate(op: mkMutate, path: path)
  of nkSeq:
    outp.add MutationCandidate(op: mkClone, path: path)
    if node.elems.len > 0:
      outp.add MutationCandidate(op: mkDelete, path: path)
      outp.add MutationCandidate(op: mkCopy, path: path)
    for i in 0..<node.elems.len:
      let childPath = appendIndex(path, i)
      collectCandidates(node.elems[i], schema.elem, childPath, config, outp)
  of nkObject:
    outp.add MutationCandidate(op: mkCopy, path: path)
    for i in 0..<node.fields.len:
      let childPath = appendIndex(path, i)
      collectCandidates(node.fields[i].value, schema.fields[i].node, childPath, config, outp)
  of nkOption:
    if node.optVal.hasValue:
      outp.add MutationCandidate(op: mkDelete, path: path)
      outp.add MutationCandidate(op: mkCopy, path: path)
      let childPath = appendIndex(path, 0)
      collectCandidates(node.optVal.value[], schema.elem, childPath, config, outp)
    else:
      outp.add MutationCandidate(op: mkAdd, path: path)

proc compatible(a, b: FuzzNode): bool =
  result = false
  if a.kind == b.kind:
    result = true
  elif a.kind == nkInt and b.kind == nkEnum:
    result = true
  elif a.kind == nkEnum and b.kind == nkInt:
    result = true

proc collectCompatibleSources(target: FuzzNode; source: FuzzNode;
    outp: var seq[FuzzNode]) =
  if compatible(target, source):
    outp.add source
  case source.kind
  of nkSeq:
    for child in source.elems:
      collectCompatibleSources(target, child, outp)
  of nkObject:
    for field in source.fields:
      collectCompatibleSources(target, field.value, outp)
  of nkOption:
    if source.optVal.hasValue:
      collectCompatibleSources(target, source.optVal.value[], outp)
  else:
    discard

proc pickWeighted(candidates: seq[MutationCandidate]; r: var Rand): MutationCandidate =
  result = candidates[r.randInt(candidates.high)]

proc shrinkToBudget(node: var FuzzNode; schema: SchemaNode; config: FuzzConfig) =
  while approxSize(node) > config.maxBytes:
    case node.kind
    of nkString:
      if node.stringVal.len == 0:
        break
      node.stringVal.setLen(node.stringVal.len div 2)
    of nkSeq:
      if node.elems.len == 0:
        break
      trimNodes(node.elems, node.elems.len - 1)
    of nkOption:
      if node.optVal.hasValue:
        node.optVal = none[ref FuzzNode]()
      else:
        break
    of nkObject:
      if node.fields.len == 0:
        break
      node.fields[node.fields.high].value = defaultNode(schema.fields[node.fields.high].node)
      break
    of nkBool, nkInt, nkFloat, nkEnum:
      break

proc fixNode(node: var FuzzNode; schema: SchemaNode; config: FuzzConfig;
    depth = 0) =
  ## Trims node contents to the configured depth and size limits.
  if depth >= config.maxDepth:
    node = defaultNode(schema)
    return
  case node.kind
  of nkString:
    if node.stringVal.len > config.maxStringLen:
      node.stringVal.setLen(config.maxStringLen)
  of nkSeq:
    if node.elems.len > config.maxSeqLen:
      trimNodes(node.elems, config.maxSeqLen)
    for i in 0..<node.elems.len:
      fixNode(node.elems[i], schema.elem, config, depth + 1)
  of nkObject:
    for i in 0..<min(node.fields.len, schema.fields.len):
      fixNode(node.fields[i].value, schema.fields[i].node, config, depth + 1)
  of nkOption:
    if node.optVal.hasValue:
      var child = node.optVal.value[]
      fixNode(child, schema.elem, config, depth + 1)
      node.optVal.value[] = child
  of nkBool, nkInt, nkFloat, nkEnum:
    discard
  shrinkToBudget(node, schema, config)

proc mutateNode(node: var FuzzNode; schema: SchemaNode; config: FuzzConfig;
    sources: openArray[FuzzNode]; seed: uint32) =
  ## Applies one LPM-style structural mutation to `node`.
  var r = initRand(seed)
  var candidates: seq[MutationCandidate] = @[]
  collectCandidates(node, schema, @[], config, candidates)
  if candidates.len == 0:
    return
  let choice = pickWeighted(candidates, r)
  case choice.op
  of mkAdd:
    addAtPath(node, schema, choice.path)
  of mkMutate:
    mutateAtPath(node, schema, choice.path, config, r)
  of mkDelete:
    deleteAtPath(node, choice.path, r)
  of mkCopy, mkClone:
    var target = node
    var donors: seq[FuzzNode] = @[]
    if readPath(node, choice.path, target):
      for source in sources:
        collectCompatibleSources(target, source, donors)
    if donors.len > 0:
      let donor = donors[r.randInt(donors.high)]
      assignAtPath(node, choice.path, donor, config, choice.op == mkClone, r)
  of mkNone:
    discard
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
