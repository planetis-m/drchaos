## LPM-style structure-aware mutator over dynamic value trees.

import model, rng, schema

proc defaultNode(schema: SchemaNode): Value
proc clampInt(value, lowValue, highValue: int): int

proc newChild(value: Value): ref FuzzNode =
  new result
  result[] = value

proc copyValue*(value: Value): Value =
  ## Performs a deep copy of a dynamic value tree.
  case nodeKind(value)
  of nkBool:
    return BoolNode(boolVal: value.boolVal)
  of nkInt:
    return IntNode(intVal: value.intVal)
  of nkFloat:
    return FloatNode(floatVal: value.floatVal)
  of nkString:
    return StringNode(stringVal: value.stringVal)
  of nkEnum:
    return EnumNode(enumVal: value.enumVal)
  of nkSeq:
    var copied: Value = SeqNode(elems: @[])
    for item in value.elems:
      copied.elems.add newChild(copyValue(item[]))
    return copied
  of nkObject:
    var copied: Value = ObjectNode(fieldNames: @[], fieldValues: @[])
    for i in 0..<min(value.fieldNames.len, value.fieldValues.len):
      copied.fieldNames.add value.fieldNames[i]
      copied.fieldValues.add newChild(copyValue(value.fieldValues[i][]))
    return copied
  of nkOption:
    var copied: Value = OptionNode(optVal: nil)
    if value.optVal != nil:
      copied.optVal = newChild(copyValue(value.optVal[]))
    return copied

proc appendIndex(path: seq[int]; index: int): seq[int] =
  result = newSeq[int](path.len + 1)
  for i in 0..<path.len:
    result[i] = path[i]
  result[path.len] = index

proc trimNodes(items: var seq[ref FuzzNode]; newLen: int) =
  let limit = clampInt(newLen, 0, items.len)
  var resized: seq[ref FuzzNode] = @[]
  for i in 0..<limit:
    resized.add items[i]
  items = resized

proc trimStrings(items: var seq[string]; newLen: int) =
  let limit = clampInt(newLen, 0, items.len)
  var resized: seq[string] = @[]
  for i in 0..<limit:
    resized.add items[i]
  items = resized

proc removeNodeAt(items: var seq[ref FuzzNode]; index: int) =
  if items.len == 0:
    return
  let at = clampInt(index, 0, items.high)
  var resized: seq[ref FuzzNode] = @[]
  for i in 0..<items.len:
    if i != at:
      resized.add items[i]
  items = resized

proc insertNodeAt(items: var seq[ref FuzzNode]; index: int; item: ref FuzzNode) =
  let at = clampInt(index, 0, items.len)
  var resized: seq[ref FuzzNode] = @[]
  for i in 0..<at:
    resized.add items[i]
  resized.add item
  for i in at..<items.len:
    resized.add items[i]
  items = resized

proc emptySeqNode(): Value =
  return SeqNode(elems: @[])

proc emptyObjectNode(): Value =
  return ObjectNode(fieldNames: @[], fieldValues: @[])

proc emptyOptionNode(): Value =
  return OptionNode(optVal: nil)

proc someOptionNode(value: Value): Value =
  return OptionNode(optVal: newChild(value))

proc approxSize(value: Value): int =
  result = 0
  case nodeKind(value)
  of nkBool:
    result = 1
  of nkInt, nkEnum, nkFloat:
    result = 8
  of nkString:
    result = value.stringVal.len
  of nkSeq:
    for item in value.elems:
      result.inc approxSize(item[])
  of nkObject:
    for i in 0..<min(value.fieldNames.len, value.fieldValues.len):
      result.inc value.fieldNames[i].len
      result.inc approxSize(value.fieldValues[i][])
  of nkOption:
    if value.optVal != nil:
      result = 1 + approxSize(value.optVal[])
    else:
      result = 1

proc defaultNode(schema: SchemaNode): Value =
  case schema.kind
  of skBool:
    return BoolNode(boolVal: false)
  of skInt:
    return IntNode(intVal: 0)
  of skFloat:
    return FloatNode(floatVal: 0.0)
  of skString:
    return StringNode(stringVal: "")
  of skEnum:
    return EnumNode(enumVal: 0)
  of skSeq:
    return SeqNode(elems: @[])
  of skObject:
    var built: Value = ObjectNode(fieldNames: @[], fieldValues: @[])
    for item in schema.fields:
      built.fieldNames.add item.name
      built.fieldValues.add newChild(defaultNode(item.node))
    return built
  of skOption:
    return OptionNode(optVal: nil)

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

proc mutateLeaf(value: var Value; schema: SchemaNode; config: FuzzConfig;
    r: var Rand) =
  case nodeKind(value)
  of nkBool:
    value = BoolNode(boolVal: not value.boolVal)
  of nkInt:
    value = IntNode(intVal: mutateInt(value.intVal, r))
  of nkEnum:
    if schema.enumNames.len > 1:
      let current = clampInt(value.enumVal.int, 0, schema.enumNames.high)
      var next = current
      while next == current:
        next = r.randInt(0, schema.enumNames.high)
      value = EnumNode(enumVal: next)
    else:
      value = EnumNode(enumVal: mutateInt(value.enumVal, r))
  of nkFloat:
    value = FloatNode(floatVal: mutateFloat(value.floatVal, r))
  of nkString:
    value = StringNode(stringVal: mutateString(value.stringVal, config, r))
  of nkSeq, nkObject, nkOption:
    discard

proc seedNode(value: var Value; schema: SchemaNode; config: FuzzConfig;
    r: var Rand; depth = 0) =
  case nodeKind(value)
  of nkBool, nkInt, nkFloat, nkString, nkEnum:
    mutateLeaf(value, schema, config, r)
  of nkSeq:
    if depth < config.maxDepth and value.elems.len < config.maxSeqLen:
      let additions = 1 + r.randInt(min(1, config.maxSeqLen - 1))
      for _ in 0..<additions:
        var child = defaultNode(schema.elem)
        if depth + 1 < config.maxDepth:
          seedNode(child, schema.elem, config, r, depth + 1)
        value.elems.add newChild(child)
  of nkObject:
    for i in 0..<min(value.fieldValues.len, schema.fields.len):
      if r.randBool:
        seedNode(value.fieldValues[i][], schema.fields[i].node, config, r, depth + 1)
  of nkOption:
    if value.optVal == nil and depth < config.maxDepth:
      var child = defaultNode(schema.elem)
      if depth + 1 < config.maxDepth:
        seedNode(child, schema.elem, config, r, depth + 1)
      value.optVal = newChild(child)

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

proc mutateAtPath(value: var Value; schema: SchemaNode; path: openArray[int];
    config: FuzzConfig; r: var Rand; depth = 0) =
  if depth >= path.len:
    mutateLeaf(value, schema, config, r)
    return
  let index = path[depth]
  case nodeKind(value)
  of nkSeq:
    if index < value.elems.len:
      mutateAtPath(value.elems[index][], schema.elem, path, config, r, depth + 1)
  of nkObject:
    if index < value.fieldValues.len:
      mutateAtPath(value.fieldValues[index][], schema.fields[index].node, path, config, r, depth + 1)
  of nkOption:
    if value.optVal != nil:
      mutateAtPath(value.optVal[], schema.elem, path, config, r, depth + 1)
  else:
    discard

proc addAtPath(value: var Value; schema: SchemaNode; path: openArray[int];
    config: FuzzConfig; r: var Rand; depth = 0) =
  if depth >= path.len:
    case nodeKind(value)
    of nkSeq:
      if value.elems.len < config.maxSeqLen:
        var child = defaultNode(schema.elem)
        seedNode(child, schema.elem, config, r, depth + 1)
        insertNodeAt(value.elems, r.randInt(0, value.elems.len), newChild(child))
    of nkOption:
      if value.optVal == nil:
        var child = defaultNode(schema.elem)
        seedNode(child, schema.elem, config, r, depth + 1)
        value.optVal = newChild(child)
    else:
      discard
    return
  let index = path[depth]
  case nodeKind(value)
  of nkSeq:
    if index < value.elems.len:
      addAtPath(value.elems[index][], schema.elem, path, config, r, depth + 1)
  of nkObject:
    if index < value.fieldValues.len:
      addAtPath(value.fieldValues[index][], schema.fields[index].node, path, config, r, depth + 1)
  of nkOption:
    if value.optVal != nil:
      addAtPath(value.optVal[], schema.elem, path, config, r, depth + 1)
  else:
    discard

proc deleteAtPath(value: var Value; path: openArray[int]; r: var Rand;
    depth = 0) =
  if depth >= path.len:
    case nodeKind(value)
    of nkSeq:
      if value.elems.len > 0:
        removeNodeAt(value.elems, r.randInt(value.elems.high))
    of nkOption:
      value.optVal = nil
    else:
      discard
    return
  let index = path[depth]
  case nodeKind(value)
  of nkSeq:
    if index < value.elems.len:
      deleteAtPath(value.elems[index][], path, r, depth + 1)
  of nkObject:
    if index < value.fieldValues.len:
      deleteAtPath(value.fieldValues[index][], path, r, depth + 1)
  of nkOption:
    if value.optVal != nil:
      deleteAtPath(value.optVal[], path, r, depth + 1)
  else:
    discard

proc assignAtPath(value: var Value; path: openArray[int]; donor: Value;
    config: FuzzConfig; isClone: bool; r: var Rand; depth = 0) =
  if depth >= path.len:
    if isClone and nodeKind(value) == nkSeq:
      if value.elems.len < config.maxSeqLen:
        insertNodeAt(value.elems, r.randInt(0, value.elems.len), newChild(copyValue(donor)))
    elif isClone and nodeKind(value) == nkOption:
      value.optVal = newChild(copyValue(donor))
    else:
      value = copyValue(donor)
    return
  let index = path[depth]
  case nodeKind(value)
  of nkSeq:
    if index < value.elems.len:
      assignAtPath(value.elems[index][], path, donor, config, isClone, r, depth + 1)
  of nkObject:
    if index < value.fieldValues.len:
      assignAtPath(value.fieldValues[index][], path, donor, config, isClone, r, depth + 1)
  of nkOption:
    if value.optVal != nil:
      assignAtPath(value.optVal[], path, donor, config, isClone, r, depth + 1)
  else:
    discard

proc candidateWeight(schema: SchemaNode; op: MutationKind): int =
  let baseWeight = int(schema.mutationWeight)
  case op
  of mkMutate:
    result = baseWeight * 4
  of mkAdd:
    result = baseWeight * 3
  of mkClone:
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

proc collectCandidates(value: Value; schema: SchemaNode; path: seq[int];
    config: FuzzConfig; outp: var seq[MutationCandidate]) =
  case nodeKind(value)
  of nkBool, nkInt, nkFloat, nkString, nkEnum:
    addCandidate(outp, mkMutate, path, schema)
  of nkSeq:
    addCandidate(outp, mkCopy, path, schema)
    if value.elems.len < config.maxSeqLen:
      addCandidate(outp, mkAdd, path, schema)
      addCandidate(outp, mkClone, path, schema)
    if value.elems.len > 0:
      addCandidate(outp, mkDelete, path, schema)
    for i in 0..<value.elems.len:
      collectCandidates(value.elems[i][], schema.elem, appendIndex(path, i), config, outp)
  of nkObject:
    addCandidate(outp, mkCopy, path, schema)
    for i in 0..<value.fieldValues.len:
      collectCandidates(value.fieldValues[i][], schema.fields[i].node, appendIndex(path, i), config, outp)
  of nkOption:
    if value.optVal != nil:
      addCandidate(outp, mkDelete, path, schema)
      addCandidate(outp, mkCopy, path, schema)
      collectCandidates(value.optVal[], schema.elem, appendIndex(path, 0), config, outp)
    else:
      addCandidate(outp, mkAdd, path, schema)
      addCandidate(outp, mkClone, path, schema)

proc collectCrossOverCandidates(value: Value; schema: SchemaNode; path: seq[int];
    config: FuzzConfig; outp: var seq[MutationCandidate]) =
  addCandidate(outp, mkCopy, path, schema)
  case nodeKind(value)
  of nkSeq:
    if value.elems.len < config.maxSeqLen:
      addCandidate(outp, mkClone, path, schema)
    for i in 0..<value.elems.len:
      collectCrossOverCandidates(value.elems[i][], schema.elem, appendIndex(path, i), config, outp)
  of nkObject:
    for i in 0..<value.fieldValues.len:
      collectCrossOverCandidates(value.fieldValues[i][], schema.fields[i].node, appendIndex(path, i), config, outp)
  of nkOption:
    if value.optVal != nil:
      collectCrossOverCandidates(value.optVal[], schema.elem, appendIndex(path, 0), config, outp)
    else:
      addCandidate(outp, mkClone, path, schema)
  else:
    discard

proc schemaCompatible(target, donor: SchemaNode): bool =
  if target.kind != donor.kind:
    return false
  case target.kind
  of skBool, skInt, skFloat, skString:
    result = true
  of skEnum:
    result = target.enumNames == donor.enumNames
  of skSeq, skOption:
    result = schemaCompatible(target.elem, donor.elem)
  of skObject:
    if target.fields.len != donor.fields.len:
      return false
    result = true
    for i in 0..<target.fields.len:
      if target.fields[i].name != donor.fields[i].name:
        return false
      if not schemaCompatible(target.fields[i].node, donor.fields[i].node):
        return false

proc collectCompatibleSources(targetSchema: SchemaNode; sourceValue: Value;
    sourceSchema: SchemaNode; outp: var seq[Value]) =
  if schemaCompatible(targetSchema, sourceSchema):
    outp.add copyValue(sourceValue)
  case nodeKind(sourceValue)
  of nkSeq:
    for child in sourceValue.elems:
      collectCompatibleSources(targetSchema, child[], sourceSchema.elem, outp)
  of nkObject:
    for i in 0..<min(sourceValue.fieldValues.len, sourceSchema.fields.len):
      collectCompatibleSources(targetSchema, sourceValue.fieldValues[i][], sourceSchema.fields[i].node, outp)
  of nkOption:
    if sourceValue.optVal != nil:
      collectCompatibleSources(targetSchema, sourceValue.optVal[], sourceSchema.elem, outp)
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
    if targetSchema.kind in {skSeq, skOption}:
      result = targetSchema.elem
    else:
      result = targetSchema
  else:
    result = targetSchema

proc shrinkToBudget(value: var Value; schema: SchemaNode; config: FuzzConfig) =
  while approxSize(value) > config.maxBytes:
    case nodeKind(value)
    of nkString:
      if value.stringVal.len == 0:
        break
      value.stringVal.setLen(value.stringVal.len div 2)
    of nkSeq:
      if value.elems.len == 0:
        break
      trimNodes(value.elems, value.elems.len - 1)
    of nkOption:
      if value.optVal != nil:
        value.optVal = nil
      else:
        break
    of nkObject:
      if value.fieldValues.len == 0 or schema.fields.len == 0:
        break
      let last = min(value.fieldValues.high, schema.fields.high)
      value.fieldValues[last] = newChild(defaultNode(schema.fields[last].node))
      break
    else:
      break

proc fixNode(value: var Value; schema: SchemaNode; config: FuzzConfig;
    depth = 0) =
  if depth >= config.maxDepth:
    value = defaultNode(schema)
    return
  case nodeKind(value)
  of nkString:
    if schema.kind != skString:
      value = defaultNode(schema)
    elif value.stringVal.len > config.maxStringLen:
      value.stringVal.setLen(config.maxStringLen)
  of nkSeq:
    if schema.kind != skSeq:
      value = defaultNode(schema)
    else:
      if value.elems.len > config.maxSeqLen:
        trimNodes(value.elems, config.maxSeqLen)
      for i in 0..<value.elems.len:
        fixNode(value.elems[i][], schema.elem, config, depth + 1)
  of nkObject:
    if schema.kind != skObject:
      value = defaultNode(schema)
    else:
      if value.fieldNames.len > schema.fields.len:
        trimStrings(value.fieldNames, schema.fields.len)
      if value.fieldValues.len > schema.fields.len:
        trimNodes(value.fieldValues, schema.fields.len)
      while value.fieldNames.len < schema.fields.len:
        value.fieldNames.add schema.fields[value.fieldNames.len].name
      while value.fieldValues.len < schema.fields.len:
        value.fieldValues.add newChild(defaultNode(schema.fields[value.fieldValues.len].node))
      for i in 0..<schema.fields.len:
        value.fieldNames[i] = schema.fields[i].name
        fixNode(value.fieldValues[i][], schema.fields[i].node, config, depth + 1)
  of nkOption:
    if schema.kind != skOption:
      value = defaultNode(schema)
    else:
      if value.optVal != nil:
        fixNode(value.optVal[], schema.elem, config, depth + 1)
  of nkEnum:
    if schema.kind != skEnum:
      value = defaultNode(schema)
    elif value.enumVal < 0:
      value = EnumNode(enumVal: 0)
    elif schema.enumNames.len > 0 and value.enumVal.int > schema.enumNames.high:
      value = EnumNode(enumVal: int64(schema.enumNames.high))
  of nkBool:
    if schema.kind != skBool:
      value = defaultNode(schema)
  of nkInt:
    if schema.kind != skInt:
      value = defaultNode(schema)
  of nkFloat:
    if schema.kind != skFloat:
      value = defaultNode(schema)
  shrinkToBudget(value, schema, config)

proc tryApplyDonor(value: var Value; schema: SchemaNode; config: FuzzConfig;
    choice: MutationCandidate; sources: openArray[Value]; r: var Rand): bool =
  let targetSchema = donorSchemaFor(schema, choice)
  var donors: seq[Value] = @[]
  for sourceValue in sources:
    collectCompatibleSources(targetSchema, sourceValue, schema, donors)
  if donors.len == 0:
    return false
  let donor = donors[r.randInt(donors.high)]
  assignAtPath(value, choice.path, donor, config, choice.op == mkClone, r)
  result = true

proc mutateNode(value: var Value; schema: SchemaNode; config: FuzzConfig;
    sources: openArray[Value]; seed: uint32) =
  var r = initRand(seed)
  var candidates: seq[MutationCandidate] = @[]
  collectCandidates(value, schema, @[], config, candidates)
  while candidates.len > 0:
    let index = pickWeightedIndex(candidates, r)
    let choice = candidates[index]
    case choice.op
    of mkAdd:
      addAtPath(value, schema, choice.path, config, r)
      break
    of mkMutate:
      mutateAtPath(value, schema, choice.path, config, r)
      break
    of mkDelete:
      deleteAtPath(value, choice.path, r)
      break
    of mkCopy, mkClone:
      if tryApplyDonor(value, schema, config, choice, sources, r):
        break
      removeCandidateAt(candidates, index)
    of mkNone:
      removeCandidateAt(candidates, index)
  fixNode(value, schema, config)

proc crossOverNode(value: var Value; schema: SchemaNode; config: FuzzConfig;
    donors: openArray[Value]; seed: uint32) =
  var r = initRand(seed)
  var candidates: seq[MutationCandidate] = @[]
  collectCrossOverCandidates(value, schema, @[], config, candidates)
  while candidates.len > 0:
    let index = pickWeightedIndex(candidates, r)
    let choice = candidates[index]
    if tryApplyDonor(value, schema, config, choice, donors, r):
      break
    removeCandidateAt(candidates, index)
  fixNode(value, schema, config)

proc mutateValue*(value: var Value; schema: SchemaNode; config: FuzzConfig;
    sources: openArray[Value]; seed: uint32) =
  ## Applies one structure-aware mutation to `value`.
  var sourceNodes: seq[Value] = @[]
  for item in sources:
    sourceNodes.add copyValue(item)
  mutateNode(value, schema, config, sourceNodes, seed)

proc crossOverValue*(value: var Value; schema: SchemaNode; config: FuzzConfig;
    donors: openArray[Value]; seed: uint32) =
  ## Applies one copy/clone-only crossover step to `value`.
  var donorNodes: seq[Value] = @[]
  for item in donors:
    donorNodes.add copyValue(item)
  crossOverNode(value, schema, config, donorNodes, seed)
