from __future__ import annotations

import json
from copy import deepcopy
from typing import Any

import yaml

from .models import Operation, ParameterSpec

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}


class SpecError(ValueError):
    pass


class OpenApiParser:
    def __init__(self, document: dict[str, Any]):
        self.document = document
        if not isinstance(document, dict) or not (document.get("openapi") or document.get("swagger")):
            raise SpecError("Document is not an OpenAPI 3.x or Swagger 2.0 specification")

    @classmethod
    def from_text(cls, text: str) -> "OpenApiParser":
        try:
            document = json.loads(text)
        except json.JSONDecodeError:
            try:
                document = yaml.safe_load(text)
            except yaml.YAMLError as exc:
                raise SpecError(f"Unable to parse JSON/YAML: {exc}") from exc
        return cls(document)

    def resolve_ref(self, value: Any, depth: int = 0) -> Any:
        if depth > 12:
            return value
        if isinstance(value, dict) and "$ref" in value:
            ref = value["$ref"]
            if not isinstance(ref, str) or not ref.startswith("#/"):
                return value
            node: Any = self.document
            for part in ref[2:].split("/"):
                part = part.replace("~1", "/").replace("~0", "~")
                node = node.get(part) if isinstance(node, dict) else None
                if node is None:
                    return value
            return self.resolve_ref(deepcopy(node), depth + 1)
        if isinstance(value, dict):
            return {k: self.resolve_ref(v, depth + 1) for k, v in value.items()}
        if isinstance(value, list):
            return [self.resolve_ref(v, depth + 1) for v in value]
        return value

    def _parameter(self, raw: dict[str, Any]) -> ParameterSpec:
        raw = self.resolve_ref(raw)
        schema = raw.get("schema") or {}
        if not schema and "type" in raw:  # Swagger 2 parameter form
            schema = {k: raw[k] for k in ("type", "format", "enum", "default") if k in raw}
        example = raw.get("example")
        if example is None:
            example = schema.get("example", schema.get("default"))
        return ParameterSpec(
            name=str(raw.get("name", "parameter")),
            location=str(raw.get("in", "query")),
            required=bool(raw.get("required", False)),
            schema=self.resolve_ref(schema),
            example=example,
        )

    def operations(self) -> list[Operation]:
        result: list[Operation] = []
        paths = self.document.get("paths") or {}
        root_security = self.document.get("security")
        for path, path_item_raw in paths.items():
            path_item = self.resolve_ref(path_item_raw)
            if not isinstance(path_item, dict):
                continue
            common_params = [self._parameter(p) for p in path_item.get("parameters", [])]
            for method, op_raw in path_item.items():
                method_l = method.lower()
                if method_l not in HTTP_METHODS or not isinstance(op_raw, dict):
                    continue
                op = self.resolve_ref(op_raw)
                params = common_params + [self._parameter(p) for p in op.get("parameters", [])]
                request_schema = None
                if "requestBody" in op:
                    body = self.resolve_ref(op["requestBody"])
                    content = body.get("content") or {}
                    media = content.get("application/json") or next(iter(content.values()), {})
                    request_schema = self.resolve_ref(media.get("schema") or {}) or None
                else:
                    body_param = next((p for p in op.get("parameters", []) if p.get("in") == "body"), None)
                    if body_param:
                        request_schema = self.resolve_ref(body_param.get("schema") or {}) or None
                security = op.get("security", root_security)
                security_required = bool(security)
                result.append(
                    Operation(
                        method=method_l.upper(),
                        path=str(path),
                        summary=str(op.get("summary") or op.get("description") or ""),
                        operation_id=str(op.get("operationId") or ""),
                        tags=[str(x) for x in (op.get("tags") or [])],
                        parameters=params,
                        request_schema=request_schema,
                        security_required=security_required,
                    )
                )
        return result

    def info(self) -> dict[str, Any]:
        info = self.document.get("info") or {}
        return {
            "title": info.get("title", "Untitled API"),
            "version": info.get("version", "unknown"),
            "openapi": self.document.get("openapi") or self.document.get("swagger"),
            "operation_count": len(self.operations()),
        }

    def sample_value(self, schema: dict[str, Any] | None, *, name: str = "value") -> Any:
        schema = self.resolve_ref(schema or {})
        if "example" in schema:
            return schema["example"]
        if "default" in schema:
            return schema["default"]
        if schema.get("enum"):
            return schema["enum"][0]
        typ = schema.get("type")
        fmt = schema.get("format")
        if typ == "integer":
            return 1
        if typ == "number":
            return 1.0
        if typ == "boolean":
            return True
        if typ == "array":
            return [self.sample_value(schema.get("items") or {})]
        if typ == "object" or "properties" in schema:
            obj: dict[str, Any] = {}
            required = set(schema.get("required") or [])
            for key, child in (schema.get("properties") or {}).items():
                if key in required or len(obj) < 4:
                    obj[key] = self.sample_value(child, name=key)
            return obj
        if fmt == "email":
            return "auditor@example.test"
        if fmt in {"uuid", "guid"}:
            return "00000000-0000-4000-8000-000000000001"
        if "id" in name.lower():
            return "1"
        return "sample"
