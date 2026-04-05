## Structure-aware fuzzing helpers for Nimony.
##
## Import this module and wrap a fuzz target proc with `fuzzTarget`.

import drchaos/[codec, harness, model, mutator, option, schema]

export codec, harness, model, mutator, option, schema

template fuzzTarget*(spec: untyped): untyped {.plugin: "drchaosplugin".}
  ## Declares a single typed fuzz target proc and expands it into a LibFuzzer
  ## harness through the `drchaosplugin` Nimony plugin.
