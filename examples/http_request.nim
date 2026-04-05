import drchaos

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
    auth: Option[Auth]

fuzzTarget:
  proc fuzzRequest(input: Request) =
    if input.httpMethod != hmPost or input.path != "/admin/upload":
      return
    if not input.auth.hasValue:
      return

    var hasContentType = false
    var hasMode = false
    for header in input.headers:
      if header.name == "content-type" and header.value == "application/x-chaos":
        hasContentType = true
      elif header.name == "x-mode" and header.value == "replay":
        hasMode = true

    let auth = input.auth.value
    if hasContentType and hasMode:
      if auth.scheme == "Bearer" and auth.token == "root":
        if input.body == "BOOM":
          crashNow()
