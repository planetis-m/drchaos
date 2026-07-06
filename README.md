# drchaos

`drchaos` is a Nimony plugin and runtime for structure-aware fuzzing. It generates LibFuzzer entrypoints, mutates a dynamic `Value` tree, and leaves domain conversion in user code.

The design is intentionally non-generic at the API edge:

- `drchaos` knows a fixed set of container/value shapes: `bool`, `int`, `float`, `string`, `seq`, object fields, and optional values.
- You describe the fuzzable shape explicitly with `drChaosSchema`.
- You provide a matching seed with `drChaosSeed`.
- Your target takes `Value` and converts it into your own domain type with ordinary Nim procs.

That keeps the runtime simple and makes custom formats straightforward: write a converter once, then fuzz your real type.

## Quick start

```nim
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
    retry: bool
    retryValue: int16

proc decodeMessage(value: Value; outp: var Message): bool =
  discard

fuzzTarget:
  var drChaosSchema = objectSchema(@[
    fieldSchema("kind", stringSchema()),
    fieldSchema("header", stringSchema()),
    fieldSchema("values", seqSchema(intSchema())),
    fieldSchema("retry", optionSchema(intSchema()))
  ])

  var drChaosSeed = objectValue(@[
    field("kind", stringValue("ping")),
    field("header", stringValue("")),
    field("values", arrayValue(newSeq[Value](0))),
    field("retry", noneValue())
  ])

  proc fuzzMessage(input: Value) =
    var message = Message()
    if not decodeMessage(input, message):
      return
    if message.kind == mkCommand and message.header == "panic":
      if message.values.len == 3 and message.retry and message.retryValue == 7'i16:
        crashNow()
```

Compile it from the repo root:

```bash
nimony c examples/simple.nim
```

## How it works

1. `fuzzTarget:` expands to `LLVMFuzzerTestOneInput`, `LLVMFuzzerCustomMutator`, and `LLVMFuzzerCustomCrossOver`.
2. Corpus bytes decode into `Value`.
3. The mutator performs structural operations on that tree.
4. Your target converts `Value` into a domain object and checks interesting behavior.

## Value model

The public runtime builders are:

- `boolValue`
- `intValue`
- `floatValue`
- `stringValue`
- `arrayValue`
- `objectValue`
- `noneValue`
- `someValue`
- `field`

The matching schema builders are:

- `boolSchema`
- `intSchema`
- `floatSchema`
- `stringSchema`
- `enumSchema`
- `seqSchema`
- `optionSchema`
- `fieldSchema`
- `objectSchema`

## Example set

- `examples/simple.nim`: smallest end-to-end target with enum-like strings, arrays, and an optional field.
- `examples/http_request.nim`: nested request/auth/header shape with field-by-field decoding.
- `examples/state_machine.nim`: ordered workflow input with optional snapshots.
- `examples/seed_corpus.nim`: building corpus bytes from `Value` and decoding them back into a domain object.
- `examples/graph_smoke.nim`: heavier stress target used to exercise mutation and crossover on a more connected shape.

## Corpus helpers

- `encodeInput(value)` serializes a `Value`.
- `tryDecodeInput(data, value)` decodes into an existing `Value` and returns `false` on malformed input.
- `decodeInput(data)` returns a decoded `Value` or `default(Value)` on failure.

## Run the examples

```bash
nimony c examples/simple.nim
nimony c examples/http_request.nim
nimony c examples/state_machine.nim
nimony c examples/seed_corpus.nim
nimony c examples/graph_smoke.nim
```
