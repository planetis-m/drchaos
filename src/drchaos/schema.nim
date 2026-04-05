## Generic schema construction for supported Nim input types.

import model, option

proc buildSchema(value: bool): SchemaNode
proc buildSchema[T: SomeInteger](value: T): SchemaNode
proc buildSchema[T: SomeFloat](value: T): SchemaNode
proc buildSchema(value: string): SchemaNode
proc buildSchema[T: enum](value: T): SchemaNode
proc buildSchema[T](value: seq[T]): SchemaNode {.untyped.}
proc buildSchema[I, T](value: array[I, T]): SchemaNode {.untyped.}
proc buildSchema[T](value: Option[T]): SchemaNode {.untyped.}
proc buildSchema[T](value: ref T): SchemaNode {.untyped.}
proc buildSchema[T: object](value: T): SchemaNode

proc newSchema(kind: SchemaKind): SchemaNode =
  result = SchemaNode(kind: kind, mutationWeight: 1)

proc buildSchema(value: bool): SchemaNode =
  result = newSchema(skBool)

proc buildSchema[T: SomeInteger](value: T): SchemaNode =
  result = newSchema(skInt)

proc buildSchema[T: SomeFloat](value: T): SchemaNode =
  result = newSchema(skFloat)

proc buildSchema(value: string): SchemaNode =
  result = newSchema(skString)

proc buildSchema[T: enum](value: T): SchemaNode =
  result = newSchema(skEnum)
  var ordinal = low(T).ord
  while ordinal <= high(T).ord:
    result.enumNames.add $T(ordinal)
    inc ordinal

proc buildSchema[T](value: seq[T]): SchemaNode {.untyped.} =
  result = newSchema(skSeq)
  result.elem = buildSchema(default(T))

proc buildSchema[I, T](value: array[I, T]): SchemaNode {.untyped.} =
  result = newSchema(skSeq)
  result.elem = buildSchema(default(T))

proc buildSchema[T](value: Option[T]): SchemaNode {.untyped.} =
  result = newSchema(skOption)
  result.elem = buildSchema(default(T))

proc buildSchema[T](value: ref T): SchemaNode {.untyped.} =
  result = newSchema(skOption)
  result.elem = buildSchema(default(T))

proc buildSchema[T: object](value: T): SchemaNode =
  result = newSchema(skObject)
  for fieldName, field in fieldPairs(value):
    result.fields.add FieldSchema(name: fieldName, node: buildSchema(field))

proc schemaFor*[T](_: typedesc[T]): SchemaNode {.untyped.} =
  ## Builds a runtime schema for `T`.
  result = buildSchema(default(T))
