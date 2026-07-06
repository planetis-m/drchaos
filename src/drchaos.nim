## Structure-aware fuzzing helpers for Nimony.
##
## Import this module and wrap a fuzz target proc with `fuzzTarget`.
## The runtime mutates dynamic `Value` trees; user code converts them to and
## from domain-specific types explicitly.

import drchaos/[codec, harness, model, mutator, schema]

export codec, harness, model, mutator, schema

template fuzzTarget*(spec: untyped): untyped {.plugin: "drchaosplugin".}
  ## Declares a single `Value` fuzz target proc and expands it into a
  ## LibFuzzer harness through the `drchaosplugin` Nimony plugin.
