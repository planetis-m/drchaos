import ".." / "src" / drchaos

proc crashNow() {.importc: "abort", header: "<stdlib.h>".}

type
  MessageKind = enum
    mkPing
    mkSync
    mkCommand

  Message = object
    kind: MessageKind
    header: string
    values: seq[int32]
    retry: Option[int16]

fuzzTarget:
  proc fuzzMessage(input: Message) =
    if input.kind == mkCommand and input.header == "panic":
      if input.values.len == 3 and input.retry.hasValue:
        if input.retry.value == 7'i16:
          crashNow()
