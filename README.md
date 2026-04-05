# drchaos

`drchaos` turns a typed Nim proc into a LibFuzzer target with structure-aware mutation and generated `LLVMFuzzer*` entrypoints.

It is aimed at `nimony` projects that want libprotobuf-mutator-style shape-aware fuzzing without writing fuzz glue by hand.

## Why try it?

- Your input type is the schema. Objects, enums, `seq`, `ref`, and `Option[T]` become mutation-aware immediately.
- The harness is generated for you. `fuzzTarget:` emits `LLVMFuzzerTestOneInput`, `LLVMFuzzerCustomMutator`, and `LLVMFuzzerCustomCrossOver`.
- Mutations are structural, not just byte flips. The engine can add, delete, copy, clone, and recursively mutate nested fields.
- Corpus data stays typed. The mutator works on structured nodes and only serializes at the input boundary.

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
    retry: Option[int16]

fuzzTarget:
  proc fuzzMessage(input: Message) =
    if input.kind == mkCommand and input.header == "panic":
      if input.values.len == 3 and input.retry.hasValue:
        if input.retry.value == 7'i16:
          crashNow()
```

Compile it from the repo root:

```bash
nimony c examples/simple.nim
```

## Example set

- `examples/simple.nim` shows the smallest useful target with enum, sequence, and optional-field mutations.
- `examples/http_request.nim` models a nested request object with headers, auth, and body fields.
- `examples/state_machine.nim` focuses on ordered steps plus `ref` children, which is useful for workflow and parser-state targets.
- `examples/graph_smoke.nim` is the harder example. It uses a graph-shaped input and a small corpus-evolution loop to exercise mutation, crossover, and target execution together.
- `examples/seed_corpus.nim` shows how to turn typed values into corpus bytes and decode them back.

## Writing targets

The target proc takes one typed input. That type becomes the shape the mutator explores.

Good target shapes:

- Request or command objects with enums, repeated fields, and optional sub-objects.
- Stateful programs represented as `seq[Step]`.
- Parsers that naturally map to nested objects instead of raw strings.

Less useful target shapes:

- A single `string` or `seq[byte]` when you already know the grammar and want structural mutation.
- Flat objects with only one or two scalar fields.

## Corpus helpers

`drchaos` includes a small wire format for corpus materialization:

- `encodeInput(value)` serializes a typed value.
- `tryDecodeInput(data, value)` decodes into an existing variable and returns `false` on malformed input.
- `decodeInput[T](data)` returns a decoded value or `default(T)` on failure.

The corpus helper example is in `examples/seed_corpus.nim`.

## What you get

- `fuzzTarget`: plugin entrypoint for declaring a harness.
- `Option[T]`: small option type used by the examples and runtime.
- `encodeInput` / `tryDecodeInput` / `decodeInput`: corpus helpers.
- `customMutator` / `customCrossOver` / `testOneInput`: runtime glue used by generated harnesses.

## Run the examples

```bash
nimony c examples/simple.nim
nimony c examples/http_request.nim
nimony c examples/state_machine.nim
nimony c examples/graph_smoke.nim
nimony c examples/seed_corpus.nim
```

To run the graph smoke test as an executable:

```bash
nimony c -r examples/graph_smoke.nim
```
