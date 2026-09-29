from auditor.engine.openapi import OpenApiParser

SPEC = """
openapi: 3.0.3
info: {title: Test, version: '1'}
components:
  securitySchemes:
    BearerAuth: {type: http, scheme: bearer}
paths:
  /users/{id}:
    get:
      security: [{BearerAuth: []}]
      parameters:
        - {name: id, in: path, required: true, schema: {type: integer, example: 7}}
      responses: {'200': {description: OK}}
"""


def test_parser_extracts_operation_and_parameter():
    parser = OpenApiParser.from_text(SPEC)
    ops = parser.operations()
    assert len(ops) == 1
    assert ops[0].method == "GET"
    assert ops[0].path == "/users/{id}"
    assert ops[0].security_required is True
    assert ops[0].parameters[0].name == "id"
