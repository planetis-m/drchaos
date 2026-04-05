# drchaos

`drchaos` is a Nimony plugin that turns a typed Nim proc into a LibFuzzer-compatible fuzz target using a compact structured corpus format.

## What it provides

- `fuzzTarget` plugin syntax for declaring a fuzz harness without Nim macros
- a structure-aware mutator with `Add`, `Delete`, `Mutate`, `Copy`, and `Clone` style operations
- wire-format encoding and decoding helpers for corpus materialization
- generated `LLVMFuzzerTestOneInput`, `LLVMFuzzerCustomMutator`, and `LLVMFuzzerCustomCrossOver` exports

## Writing a fuzz target

```nim
import drchaos

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

The input type is the schema. Nested objects, sequences, refs, and `Option[T]` values become mutable structured nodes in the corpus and mutator.

## Example set

- `examples/simple.nim`: smallest useful target that still exercises enum, sequence, and option mutation.
- `examples/http_request.nim`: realistic request-shaped input with nested objects and field-level header mutations.
- `examples/state_machine.nim`: sequence-heavy state machine using `ref` children to exercise presence toggling and subtree copy/clone.
- `examples/seed_corpus.nim`: minimal corpus materialization example using `encodeInput` and `tryDecodeInput`.

## Wire Format

`drchaos` stores corpus entries in its own compact wire format with a fixed header plus typed field tags. Public helpers:

- `encodeInput(value)` serializes a typed value
- `tryDecodeInput(data, value)` decodes without raising
- `decodeInput[T](data)` decodes or returns `default(T)` on malformed input

The mutator always works on typed structured nodes, not raw byte slices, and only re-encodes to the wire format at the corpus boundary.

## Building

Current Nimony builds are most reliable with an explicit source path:

```bash
nimony c --path:/home/ageralis/Projects/drchaos/src examples/simple.nim
```

Other examples compile the same way:

```bash
nimony c --path:/home/ageralis/Projects/drchaos/src examples/http_request.nim
nimony c --path:/home/ageralis/Projects/drchaos/src examples/state_machine.nim
nimony c --path:/home/ageralis/Projects/drchaos/src examples/seed_corpus.nim
```

For LibFuzzer integration, compile the generated C output with your usual sanitizer and `-fsanitize=fuzzer` toolchain flags.

## Layout

- `src/drchaos.nim`: public API surface
- `src/drchaosplugin.nim`: Nimony plugin lowering
- `src/drchaos/harness.nim`: harness state and LibFuzzer ABI helpers
- `src/drchaos/mutator.nim`: structure-aware mutation engine
- `src/drchaos/codec.nim`: wire-format encoding and decoding
- `src/drchaos/schema.nim`: runtime schema inference
- `examples/`: end-to-end fuzz targets and corpus examples
