import ".." / "src" / drchaos

proc crashNow() {.importc: "abort", header: "<stdlib.h>".}

type
  HttpMethod = enum
    hmGet
    hmPost
    hmPut
    hmDelete

  Header = object
    name: string
    value: string

  Auth = object
    scheme: string
    token: string

  Request = object
    httpMethod: HttpMethod
    path: string
    headers: seq[Header]
    body: string
    hasAuth: bool
    auth: Auth

proc decodeMethod(value: Value; outp: var HttpMethod): bool =
  var text = ""
  if not getString(value, text):
    return false
  case text
  of "GET":
    outp = hmGet
  of "POST":
    outp = hmPost
  of "PUT":
    outp = hmPut
  of "DELETE":
    outp = hmDelete
  else:
    return false
  result = true

proc decodeHeader(value: Value; outp: var Header): bool =
  var fieldValue = default(Value)
  if not findField(value, "name", fieldValue):
    return false
  if not getString(fieldValue, outp.name):
    return false
  if not findField(value, "value", fieldValue):
    return false
  result = getString(fieldValue, outp.value)

proc decodeHeaders(value: Value; outp: var seq[Header]): bool =
  var items: seq[Value] = @[]
  if not getArray(value, items):
    return false
  outp = @[]
  for item in items:
    var header = Header()
    if not decodeHeader(item, header):
      return false
    outp.add header
  result = true

proc decodeAuth(value: Value; hasAuth: var bool; outp: var Auth): bool =
  if nodeKind(value) != nkOption:
    return false
  if not isSome(value):
    hasAuth = false
    outp = Auth()
    return true
  var inner = default(Value)
  var fieldValue = default(Value)
  if not getOption(value, inner):
    return false
  if not findField(inner, "scheme", fieldValue):
    return false
  if not getString(fieldValue, outp.scheme):
    return false
  if not findField(inner, "token", fieldValue):
    return false
  if not getString(fieldValue, outp.token):
    return false
  hasAuth = true
  result = true

proc decodeRequest(value: Value; outp: var Request): bool =
  var fieldValue = default(Value)
  if not findField(value, "method", fieldValue):
    return false
  if not decodeMethod(fieldValue, outp.httpMethod):
    return false
  if not findField(value, "path", fieldValue):
    return false
  if not getString(fieldValue, outp.path):
    return false
  if not findField(value, "headers", fieldValue):
    return false
  if not decodeHeaders(fieldValue, outp.headers):
    return false
  if not findField(value, "body", fieldValue):
    return false
  if not getString(fieldValue, outp.body):
    return false
  if not findField(value, "auth", fieldValue):
    return false
  result = decodeAuth(fieldValue, outp.hasAuth, outp.auth)

fuzzTarget:
  var drChaosSchema = objectSchema(@[
    fieldSchema("method", stringSchema()),
    fieldSchema("path", stringSchema()),
    fieldSchema("headers", seqSchema(objectSchema(@[
      fieldSchema("name", stringSchema()),
      fieldSchema("value", stringSchema())
    ]))),
    fieldSchema("body", stringSchema()),
    fieldSchema("auth", optionSchema(objectSchema(@[
      fieldSchema("scheme", stringSchema()),
      fieldSchema("token", stringSchema())
    ])))
  ])

  var drChaosSeed = objectValue()
  addField(drChaosSeed, "method", stringValue("GET"))
  addField(drChaosSeed, "path", stringValue("/"))
  addField(drChaosSeed, "headers", arrayValue(newSeq[Value](0)))
  addField(drChaosSeed, "body", stringValue(""))
  addField(drChaosSeed, "auth", noneValue())

  proc fuzzRequest(input: Value) =
    var request = Request()
    if not decodeRequest(input, request):
      return
    if request.httpMethod != hmPost or request.path != "/admin/upload":
      return
    if not request.hasAuth:
      return

    var hasContentType = false
    var hasMode = false
    for header in request.headers:
      if header.name == "content-type" and header.value == "application/x-chaos":
        hasContentType = true
      elif header.name == "x-mode" and header.value == "replay":
        hasMode = true

    if hasContentType and hasMode:
      if request.auth.scheme == "Bearer" and request.auth.token == "root":
        if request.body == "BOOM":
          crashNow()
