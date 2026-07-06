import nimonyplugins

proc fail(msg: string; at: Node): Tree =
  errorTree("[drchaos] " & msg, at)

proc findTargetProc(root: Node): Node =
  if root.stmtKind == StmtsS:
    var n = root
    inc n
    while n.kind != ParRi and n.kind != EofToken:
      var stmt = n
      if stmt.stmtKind == ProcS:
        return stmt
      if stmt.stmtKind == StmtsS:
        let nested = findTargetProc(stmt)
        if nested.stmtKind == ProcS:
          return nested
      skip n
  elif root.stmtKind == ProcS:
    return root
  result = root

proc extractProcName(procNode: Node): string =
  result = ""
  var n = procNode
  inc n
  while n.kind notin {ParLe, ParRi, EofToken}:
    case n.kind
    of Ident:
      return n.identText
    of Symbol, SymbolDef:
      return n.symText
    else:
      inc n

proc emitParam(dest: var Tree; name, typeName: string) =
  dest.withTree ParamU, NoLineInfo:
    dest.addIdent(name)
    dest.addEmptyNode2()
    dest.addIdent(typeName)
    dest.addEmptyNode()

proc emitVarInitCall(dest: var Tree; name, typeName, callee: string;
    args: openArray[string]) =
  dest.withTree VarS, NoLineInfo:
    dest.addIdent(name)
    dest.addEmptyNode2()
    if typeName.len > 0:
      dest.addIdent(typeName)
    else:
      dest.addEmptyNode()
    dest.withTree CallX, NoLineInfo:
      dest.addIdent(callee)
      for arg in args:
        dest.addIdent(arg)

proc emitVarInitBytes(dest: var Tree; name, ptrName, lenName: string) =
  dest.withTree VarS, NoLineInfo:
    dest.addIdent(name)
    dest.addEmptyNode2()
    dest.addEmptyNode()
    dest.withTree CallX, NoLineInfo:
      dest.addIdent("bytesFromPtr")
      dest.addIdent(ptrName)
      dest.withTree CallX, NoLineInfo:
        dest.addIdent("int")
        dest.addIdent(lenName)

proc emitAsgnCallWithCast(dest: var Tree; lhs, castName, callee: string;
    args: openArray[string]) =
  dest.withTree AsgnS, NoLineInfo:
    dest.addIdent(lhs)
    dest.withTree CallX, NoLineInfo:
      dest.addIdent(castName)
      dest.withTree CallX, NoLineInfo:
        dest.addIdent(callee)
        for arg in args:
          dest.addIdent(arg)

proc emitConfigVar(dest: var Tree) =
  emitVarInitCall(dest, "drChaosConfig", "FuzzConfig", "defaultFuzzConfig", [])

proc emitTestOneInput(dest: var Tree) =
  dest.withTree ProcS, NoLineInfo:
    dest.addIdent("LLVMFuzzerTestOneInput")
    dest.addEmptyNode3()
    dest.withTree ParamsU, NoLineInfo:
      emitParam(dest, "data", "BytePtr")
      emitParam(dest, "len", "csize_t")
    dest.addIdent("cint")
    dest.withTree PragmasS, NoLineInfo:
      dest.addIdent("exportc")
    dest.addEmptyNode()
    dest.withTree StmtsS, NoLineInfo:
      emitVarInitBytes(dest, "inputBytes", "data", "len")
      dest.withTree AsgnS, NoLineInfo:
        dest.addIdent("result")
        dest.withTree CallX, NoLineInfo:
          dest.addIdent("testOneInput")
          dest.addIdent("drChaosHarness")
          dest.addIdent("inputBytes")

proc emitCustomMutator(dest: var Tree) =
  dest.withTree ProcS, NoLineInfo:
    dest.addIdent("LLVMFuzzerCustomMutator")
    dest.addEmptyNode3()
    dest.withTree ParamsU, NoLineInfo:
      emitParam(dest, "data", "BytePtr")
      emitParam(dest, "len", "csize_t")
      emitParam(dest, "maxLen", "csize_t")
      emitParam(dest, "seed", "cuint")
    dest.addIdent("csize_t")
    dest.withTree PragmasS, NoLineInfo:
      dest.addIdent("exportc")
    dest.addEmptyNode()
    dest.withTree StmtsS, NoLineInfo:
      emitVarInitBytes(dest, "inputBytes", "data", "len")
      dest.withTree VarS, NoLineInfo:
        dest.addIdent("mutated")
        dest.addEmptyNode2()
        dest.addEmptyNode()
        dest.withTree CallX, NoLineInfo:
          dest.addIdent("customMutator")
          dest.addIdent("drChaosHarness")
          dest.addIdent("inputBytes")
          dest.withTree CallX, NoLineInfo:
            dest.addIdent("int")
            dest.addIdent("maxLen")
          dest.withTree CallX, NoLineInfo:
            dest.addIdent("uint32")
            dest.addIdent("seed")
      emitAsgnCallWithCast(dest, "result", "csize_t", "writeBytesToPtr",
        ["data", "mutated"])

proc emitCustomCrossOver(dest: var Tree) =
  dest.withTree ProcS, NoLineInfo:
    dest.addIdent("LLVMFuzzerCustomCrossOver")
    dest.addEmptyNode3()
    dest.withTree ParamsU, NoLineInfo:
      emitParam(dest, "data1", "BytePtr")
      emitParam(dest, "size1", "csize_t")
      emitParam(dest, "data2", "BytePtr")
      emitParam(dest, "size2", "csize_t")
      emitParam(dest, "out", "BytePtr")
      emitParam(dest, "maxOutSize", "csize_t")
      emitParam(dest, "seed", "cuint")
    dest.addIdent("csize_t")
    dest.withTree PragmasS, NoLineInfo:
      dest.addIdent("exportc")
    dest.addEmptyNode()
    dest.withTree StmtsS, NoLineInfo:
      emitVarInitBytes(dest, "leftBytes", "data1", "size1")
      emitVarInitBytes(dest, "rightBytes", "data2", "size2")
      dest.withTree VarS, NoLineInfo:
        dest.addIdent("mutated")
        dest.addEmptyNode2()
        dest.addEmptyNode()
        dest.withTree CallX, NoLineInfo:
          dest.addIdent("customCrossOver")
          dest.addIdent("drChaosHarness")
          dest.addIdent("leftBytes")
          dest.addIdent("rightBytes")
          dest.withTree CallX, NoLineInfo:
            dest.addIdent("int")
            dest.addIdent("maxOutSize")
          dest.withTree CallX, NoLineInfo:
            dest.addIdent("uint32")
            dest.addIdent("seed")
      emitAsgnCallWithCast(dest, "result", "csize_t", "writeBytesToPtr",
        ["out", "mutated"])

proc emitOriginalBlock(dest: var Tree; root: Node) =
  if root.stmtKind == StmtsS:
    var n = root
    inc n
    while n.kind != ParRi and n.kind != EofToken:
      var stmt = n
      if stmt.stmtKind == StmtsS:
        emitOriginalBlock(dest, stmt)
        skip n
      else:
        dest.takeTree(n)
  else:
    dest.addSubtree(root)

proc generate(root: Node): Tree =
  let procNode = findTargetProc(root)
  if procNode.kind == EofToken:
    return fail("fuzzTarget expects exactly one proc declaration", root)
  let procName = extractProcName(procNode)
  if procName.len == 0:
    return fail("unable to extract fuzz target proc name", procNode)

  result = createTree()
  result.withTree StmtsS, root.info:
    emitOriginalBlock(result, root)
    emitConfigVar(result)
    emitVarInitCall(result, "drChaosHarness", "", "initHarness",
      [procName, "drChaosSeed", "drChaosSchema", "drChaosConfig"])
    emitTestOneInput(result)
    emitCustomMutator(result)
    emitCustomCrossOver(result)

let input = loadPluginInput()
saveTree generate(input)
