## Dynamic schema builders for the drchaos value model.

import model

proc newSchema(kind: SchemaKind): SchemaNode =
  result = SchemaNode(kind: kind, mutationWeight: 1)

proc boolSchema*(): SchemaNode =
  ## Constructs a boolean schema node.
  result = newSchema(skBool)

proc intSchema*(): SchemaNode =
  ## Constructs an integer schema node.
  result = newSchema(skInt)

proc floatSchema*(): SchemaNode =
  ## Constructs a floating-point schema node.
  result = newSchema(skFloat)

proc stringSchema*(): SchemaNode =
  ## Constructs a string schema node.
  result = newSchema(skString)

proc enumSchema*(names: seq[string]): SchemaNode =
  ## Constructs an enum schema node.
  result = newSchema(skEnum)
  result.enumNames = names

proc seqSchema*(elem: SchemaNode): SchemaNode =
  ## Constructs a repeated-field schema node.
  result = newSchema(skSeq)
  result.elem = elem

proc optionSchema*(elem: SchemaNode): SchemaNode =
  ## Constructs an optional-field schema node.
  result = newSchema(skOption)
  result.elem = elem

proc fieldSchema*(name: string; node: SchemaNode): FieldSchema =
  ## Constructs an object field schema.
  result = FieldSchema(name: name, node: node)

proc objectSchema*(fields: seq[FieldSchema]): SchemaNode =
  ## Constructs an object schema node.
  result = newSchema(skObject)
  result.fields = fields

proc schemaFromValue*(value: Value): SchemaNode =
  ## Infers a schema from a fully materialized value.
  case nodeKind(value)
  of nkBool:
    result = boolSchema()
  of nkInt:
    result = intSchema()
  of nkFloat:
    result = floatSchema()
  of nkString:
    result = stringSchema()
  of nkEnum:
    result = enumSchema(newSeq[string](0))
  of nkSeq:
    result = newSchema(skSeq)
    if value.elems.len > 0:
      result.elem = schemaFromValue(value.elems[0][])
    else:
      result.elem = boolSchema()
  of nkObject:
    result = newSchema(skObject)
    result.fields = @[]
    for i in 0..<min(value.fieldNames.len, value.fieldValues.len):
      result.fields.add fieldSchema(value.fieldNames[i], schemaFromValue(value.fieldValues[i][]))
  of nkOption:
    result = newSchema(skOption)
    if value.optVal != nil:
      result.elem = schemaFromValue(value.optVal[])
    else:
      result.elem = boolSchema()
