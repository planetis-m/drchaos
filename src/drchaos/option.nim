## Minimal option type for Nimony-compatible code.

type
  Option*[T] = object
    hasValue*: bool
    value*: T

proc some*[T](value: sink T): Option[T] =
  ## Wraps `value` in an option.
  result = Option[T](hasValue: true, value: value)

proc none*[T](): Option[T] {.untyped.} =
  ## Returns an empty option.
  result = default(Option[T])

proc isSome*[T](opt: Option[T]): bool {.inline.} =
  ## Returns true when `opt` contains a value.
  result = opt.hasValue
