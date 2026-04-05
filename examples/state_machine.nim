import drchaos

proc crashNow() {.importc: "abort", header: "<stdlib.h>".}

type
  StepKind = enum
    skOpen
    skWrite
    skCommit
    skRollback

  Snapshot = object
    checksum: uint32
    label: string

  Step = object
    kind: StepKind
    resource: string
    snapshot: ref Snapshot

  Program = object
    dryRun: bool
    steps: seq[Step]
    ticket: Option[string]

fuzzTarget:
  proc fuzzProgram(input: Program) =
    if input.dryRun:
      return
    if not input.ticket.hasValue or input.ticket.value != "T-9000":
      return
    if input.steps.len < 3:
      return

    let first = input.steps[0]
    let second = input.steps[1]
    let third = input.steps[2]

    if first.kind == skOpen and first.resource == "/secure":
      if second.kind == skWrite and second.snapshot != nil:
        if second.snapshot[].checksum == 0x41424344'u32:
          if third.kind == skCommit and third.resource == "shadow":
            crashNow()
