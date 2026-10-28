"""Bounded CyberQalqon Query Language (CQQL) v1 parser and SQL compiler.

CQQL deliberately exposes a small field catalog.  User input is parsed into a
typed AST and every value remains a SQLite parameter; callers never receive or
provide raw SQL identifiers.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, replace
from typing import Literal, TypeAlias


CQQL_VERSION = "cqql-v1"
MAX_QUERY_LENGTH = 2_000
MAX_TOKENS = 256
MAX_AST_DEPTH = 8
MAX_BOOLEAN_CLAUSES = 32
MAX_TEXT_TOKENS = 12

FieldType = Literal["string", "integer", "ip", "mitre", "text", "timestamp"]


@dataclass(frozen=True, slots=True)
class FieldDefinition:
    public_name: str
    column: str | None
    data_type: FieldType
    operators: tuple[str, ...]
    case_insensitive: bool
    indexed: bool
    sensitivity: Literal["standard", "identity", "network", "evidence"]
    source: str
    derived: bool = False
    searchable: bool = True
    maximum_length: int = 1_024
    minimum: int | None = None
    maximum: int | None = None
    allowed_values: frozenset[str] | None = None
    attribute_key: str | None = None


STRING_OPERATORS = ("=", "!=")
INTEGER_OPERATORS = ("=", "!=", ">", ">=", "<", "<=")

# This is the only authority for public CQQL names and trusted SQL columns.
FIELD_CATALOG: dict[str, FieldDefinition] = {
    "event.id": FieldDefinition("event.id", "e.event_id", "string", STRING_OPERATORS, False, True, "standard", "security_events.event_id", maximum_length=64),
    "event.code": FieldDefinition("event.code", "e.event_code", "string", STRING_OPERATORS, False, True, "standard", "security_events.event_code", maximum_length=128),
    "event.category": FieldDefinition("event.category", "e.event_category", "string", STRING_OPERATORS, True, True, "standard", "security_events.event_category", maximum_length=255),
    "event.action": FieldDefinition("event.action", "e.event_action", "string", STRING_OPERATORS, True, True, "standard", "security_events.event_action", maximum_length=255),
    "event.outcome": FieldDefinition("event.outcome", "e.outcome", "string", STRING_OPERATORS, True, True, "standard", "security_events.outcome", maximum_length=128),
    "event.severity": FieldDefinition("event.severity", "e.severity", "integer", INTEGER_OPERATORS, False, True, "standard", "security_events.severity", minimum=0, maximum=16),
    "event.source_type": FieldDefinition(
        "event.source_type", "e.source_type", "string", STRING_OPERATORS, False, True, "standard", "security_events.source_type", maximum_length=32,
        allowed_values=frozenset({"authentication", "file_integrity", "network", "web", "windows_event", "wazuh_alert", "wazuh_archive"}),
    ),
    "event.provider": FieldDefinition("event.provider", "e.event_provider", "string", STRING_OPERATORS, True, True, "standard", "security_events.event_provider", maximum_length=255),
    "event.channel": FieldDefinition("event.channel", "e.event_channel", "string", STRING_OPERATORS, True, False, "standard", "security_events.event_channel", maximum_length=255),
    "event.timestamp": FieldDefinition("event.timestamp", "e.occurred_at", "timestamp", (), False, True, "standard", "security_events.occurred_at", searchable=False),
    "host.name": FieldDefinition("host.name", "e.hostname", "string", STRING_OPERATORS, True, True, "standard", "security_events.hostname", maximum_length=255),
    "host.os": FieldDefinition("host.os", "e.operating_system", "string", STRING_OPERATORS, True, True, "standard", "security_events.operating_system", maximum_length=255),
    "agent.id": FieldDefinition("agent.id", "e.agent_id", "string", STRING_OPERATORS, False, True, "standard", "security_events.agent_id", maximum_length=128),
    "agent.name": FieldDefinition("agent.name", "e.agent_name", "string", STRING_OPERATORS, True, False, "standard", "security_events.agent_name", maximum_length=255),
    "source.ip": FieldDefinition("source.ip", "e.source_ip", "ip", STRING_OPERATORS, False, True, "network", "security_events.source_ip", maximum_length=64),
    "destination.ip": FieldDefinition("destination.ip", "e.destination_ip", "ip", STRING_OPERATORS, False, True, "network", "security_events.destination_ip", maximum_length=64),
    "source.port": FieldDefinition("source.port", "e.source_port", "integer", INTEGER_OPERATORS, False, False, "network", "security_events.source_port", minimum=1, maximum=65_535),
    "destination.port": FieldDefinition("destination.port", "e.destination_port", "integer", INTEGER_OPERATORS, False, False, "network", "security_events.destination_port", minimum=1, maximum=65_535),
    "user.name": FieldDefinition("user.name", "e.username", "string", STRING_OPERATORS, True, True, "identity", "security_events.username", maximum_length=512),
    "rule.id": FieldDefinition("rule.id", "e.rule_id", "string", STRING_OPERATORS, False, True, "standard", "security_events.rule_id", maximum_length=128),
    "mitre.id": FieldDefinition("mitre.id", None, "mitre", STRING_OPERATORS, False, False, "standard", "security_events.mitre_ids_json", derived=True, maximum_length=16),
    "process.name": FieldDefinition("process.name", "e.process_name", "string", STRING_OPERATORS, True, True, "evidence", "security_events.process_name", maximum_length=1_024),
    "process.parent.name": FieldDefinition("process.parent.name", "e.parent_process_name", "string", STRING_OPERATORS, True, False, "evidence", "security_events.parent_process_name", maximum_length=1_024),
    "ingestion.source": FieldDefinition("ingestion.source", "e.ingestion_source", "string", STRING_OPERATORS, False, False, "standard", "security_events.ingestion_source", maximum_length=128),
    "text": FieldDefinition("text", None, "text", ("CONTAINS",), True, True, "evidence", "security_events_fts.search_text", derived=True, maximum_length=512),
    "network.protocol": FieldDefinition("network.protocol", "json_extract(e.structured_json, '$._cuse.attributes.network_protocol')", "string", STRING_OPERATORS, True, False, "network", "CUSE.attributes.network_protocol", derived=True, maximum_length=32, attribute_key="network_protocol"),
    "network.duration_ms": FieldDefinition("network.duration_ms", "json_extract(e.structured_json, '$._cuse.attributes.network_duration_ms')", "integer", INTEGER_OPERATORS, False, False, "network", "CUSE.attributes.network_duration_ms", derived=True, minimum=0, maximum=31536000000, attribute_key="network_duration_ms"),
    "network.sensor.id": FieldDefinition("network.sensor.id", "json_extract(e.structured_json, '$._cuse.attributes.sensor_id')", "string", STRING_OPERATORS, False, False, "network", "CUSE.attributes.sensor_id", derived=True, maximum_length=128, attribute_key="sensor_id"),
    "network.connection.uid": FieldDefinition("network.connection.uid", "json_extract(e.structured_json, '$._cuse.attributes.connection_uid')", "string", STRING_OPERATORS, False, False, "network", "CUSE.attributes.connection_uid", derived=True, maximum_length=128, attribute_key="connection_uid"),
    "dns.question.name": FieldDefinition("dns.question.name", "json_extract(e.structured_json, '$._cuse.attributes.dns_question_name')", "string", STRING_OPERATORS, True, False, "network", "CUSE.attributes.dns_question_name", derived=True, maximum_length=1024, attribute_key="dns_question_name"),
    "dns.response.code": FieldDefinition("dns.response.code", "json_extract(e.structured_json, '$._cuse.attributes.dns_response_code')", "string", STRING_OPERATORS, True, False, "network", "CUSE.attributes.dns_response_code", derived=True, maximum_length=128, attribute_key="dns_response_code"),
    "http.host": FieldDefinition("http.host", "json_extract(e.structured_json, '$._cuse.attributes.http_host')", "string", STRING_OPERATORS, True, False, "network", "CUSE.attributes.http_host", derived=True, maximum_length=1024, attribute_key="http_host"),
    "url.path": FieldDefinition("url.path", "json_extract(e.structured_json, '$._cuse.attributes.url_path')", "string", STRING_OPERATORS, False, False, "network", "CUSE.attributes.url_path", derived=True, maximum_length=2048, attribute_key="url_path"),
    "tls.server.name": FieldDefinition("tls.server.name", "json_extract(e.structured_json, '$._cuse.attributes.tls_server_name')", "string", STRING_OPERATORS, True, False, "network", "CUSE.attributes.tls_server_name", derived=True, maximum_length=1024, attribute_key="tls_server_name"),
}


for _name, _definition in tuple(FIELD_CATALOG.items()):
    if _definition.data_type == 'string' and _definition.allowed_values is None:
        FIELD_CATALOG[_name] = replace(_definition, operators=(*STRING_OPERATORS, 'CONTAINS', 'STARTSWITH'))


class CQQLQueryError(ValueError):
    """Deterministic, user-facing CQQL validation failure."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        position: int,
        field: str | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.position = position
        self.field = field


@dataclass(frozen=True, slots=True)
class Token:
    kind: str
    value: str | int | None
    position: int


@dataclass(frozen=True, slots=True)
class Comparison:
    field: str
    operator: str
    value: str | int
    position: int


@dataclass(frozen=True, slots=True)
class BooleanExpression:
    operator: Literal["AND", "OR"]
    left: "Expression"
    right: "Expression"


@dataclass(frozen=True, slots=True)
class Negation:
    expression: "Expression"


Expression: TypeAlias = Comparison | BooleanExpression | Negation


@dataclass(frozen=True, slots=True)
class ParsedCQQL:
    expression: Expression
    token_count: int
    clause_count: int
    depth: int


@dataclass(frozen=True, slots=True)
class CompiledCQQL:
    sql: str
    parameters: tuple[object, ...]
    clause_count: int
    depth: int
    uses_fts: bool
    fingerprint: str
    cost_class: Literal["LOW", "MODERATE", "HIGH"]
    plan_class: Literal[
        "INDEX_FRIENDLY",
        "BOOLEAN_COMPLEX",
        "FTS_SELECTIVITY_UNKNOWN",
        "RESOURCE_LIMITED",
        "UNKNOWN_COST",
    ]
    planner_strategy: Literal["DEFAULT", "TIME_ORDERED_OR", "TIME_ORDERED_BOOLEAN"]
    referenced_fields: tuple[str, ...]
    diagnostic_reasons: tuple[str, ...]


def _query_error(code: str, message: str, position: int, field: str | None = None) -> CQQLQueryError:
    return CQQLQueryError(code, message, position=position, field=field)


def _lex(query: str) -> list[Token]:
    if not query.strip():
        raise _query_error("empty_query", "CQQL query must not be blank", 0)
    if len(query) > MAX_QUERY_LENGTH:
        raise _query_error(
            "query_too_long",
            f"CQQL query exceeds the {MAX_QUERY_LENGTH}-character limit",
            MAX_QUERY_LENGTH,
        )
    tokens: list[Token] = []
    index = 0
    length = len(query)
    while index < length:
        character = query[index]
        if character.isspace():
            index += 1
            continue
        if character == "(":
            tokens.append(Token("LPAREN", character, index))
            index += 1
        elif character == ")":
            tokens.append(Token("RPAREN", character, index))
            index += 1
        elif character in "=!<>":
            start = index
            index += 1
            if index < length and query[index] == "=":
                index += 1
            operator = query[start:index]
            if operator not in {"=", "!=", ">", ">=", "<", "<="}:
                raise _query_error("unsupported_operator", f"Unsupported operator {operator!r}", start)
            tokens.append(Token("OPERATOR", operator, start))
        elif character == '"':
            start = index
            index += 1
            escaped = False
            while index < length:
                current = query[index]
                if ord(current) < 0x20:
                    raise _query_error("invalid_string", "Quoted strings cannot contain control characters", index)
                if escaped:
                    escaped = False
                elif current == "\\":
                    escaped = True
                elif current == '"':
                    index += 1
                    break
                index += 1
            else:
                raise _query_error("unterminated_string", "Quoted string is not terminated", start)
            raw = query[start:index]
            try:
                decoded = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise _query_error("invalid_string", "Quoted string uses an invalid escape", start + exc.pos) from exc
            tokens.append(Token("STRING", decoded, start))
        elif character.isdigit():
            start = index
            while index < length and query[index].isdigit():
                index += 1
            tokens.append(Token("NUMBER", int(query[start:index]), start))
        elif character.isalpha() or character == "_":
            start = index
            index += 1
            while index < length and (query[index].isalnum() or query[index] in "._"):
                index += 1
            word = query[start:index]
            keyword = word.upper()
            if keyword in {"AND", "OR", "NOT", "CONTAINS", "STARTSWITH"}:
                tokens.append(Token(keyword, keyword, start))
            else:
                tokens.append(Token("IDENTIFIER", word.casefold(), start))
        else:
            raise _query_error("unexpected_character", f"Unexpected character {character!r}", index)
        if len(tokens) > MAX_TOKENS:
            raise _query_error(
                "too_many_tokens",
                f"CQQL query exceeds the {MAX_TOKENS}-token limit",
                index,
            )
    tokens.append(Token("EOF", None, length))
    return tokens


class _Parser:
    def __init__(self, tokens: list[Token]) -> None:
        self.tokens = tokens
        self.index = 0
        self.clause_count = 0
        self.parenthesis_depth = 0

    @property
    def current(self) -> Token:
        return self.tokens[self.index]

    def accept(self, kind: str) -> Token | None:
        if self.current.kind != kind:
            return None
        token = self.current
        self.index += 1
        return token

    def expect(self, kind: str, message: str) -> Token:
        token = self.accept(kind)
        if token is None:
            raise _query_error("syntax_error", message, self.current.position)
        return token

    def parse(self) -> Expression:
        expression = self.parse_or()
        if self.current.kind != "EOF":
            raise _query_error("unexpected_token", "Unexpected token after complete expression", self.current.position)
        return expression

    def parse_or(self) -> Expression:
        expressions = [self.parse_and()]
        while self.accept("OR") is not None:
            expressions.append(self.parse_and())
        return self._balanced("OR", expressions)

    def parse_and(self) -> Expression:
        expressions = [self.parse_not()]
        while self.accept("AND") is not None:
            expressions.append(self.parse_not())
        return self._balanced("AND", expressions)

    @staticmethod
    def _balanced(
        operator: Literal["AND", "OR"], expressions: list[Expression]
    ) -> Expression:
        """Keep flat boolean lists shallow while retaining left-to-right meaning."""

        if len(expressions) == 1:
            return expressions[0]
        midpoint = len(expressions) // 2
        return BooleanExpression(
            operator,
            _Parser._balanced(operator, expressions[:midpoint]),
            _Parser._balanced(operator, expressions[midpoint:]),
        )

    def parse_not(self) -> Expression:
        if self.accept("NOT") is not None:
            return Negation(self.parse_not())
        return self.parse_primary()

    def parse_primary(self) -> Expression:
        opening = self.accept("LPAREN")
        if opening is not None:
            self.parenthesis_depth += 1
            if self.parenthesis_depth > MAX_AST_DEPTH:
                raise _query_error(
                    "expression_too_deep",
                    f"CQQL nesting exceeds the depth limit of {MAX_AST_DEPTH}",
                    opening.position,
                )
            expression = self.parse_or()
            self.expect("RPAREN", "Expected ')' to close expression")
            self.parenthesis_depth -= 1
            return expression
        return self.parse_comparison()

    def parse_comparison(self) -> Comparison:
        field_token = self.expect("IDENTIFIER", "Expected a searchable field name")
        field = str(field_token.value)
        definition = FIELD_CATALOG.get(field)
        if definition is None:
            raise _query_error("unknown_field", f"Unknown CQQL field {field!r}", field_token.position, field)
        if not definition.searchable:
            raise _query_error(
                "unsupported_field",
                f"{field} must be supplied through structured start_time/end_time parameters",
                field_token.position,
                field,
            )
        operator_token = self.current
        if operator_token.kind in {"CONTAINS", "STARTSWITH"}:
            self.index += 1
            operator = str(operator_token.value)
        elif operator_token.kind == "OPERATOR":
            self.index += 1
            operator = str(operator_token.value)
        else:
            raise _query_error("syntax_error", "Expected a comparison operator", operator_token.position, field)
        if operator not in definition.operators:
            allowed = ", ".join(definition.operators)
            raise _query_error(
                "unsupported_operator",
                f"Operator {operator} is not supported for {field}; allowed: {allowed}",
                operator_token.position,
                field,
            )
        value_token = self.current
        expected_kind = "NUMBER" if definition.data_type == "integer" else "STRING"
        if value_token.kind != expected_kind:
            expected = "an integer" if expected_kind == "NUMBER" else "a quoted string"
            raise _query_error("type_error", f"{field} requires {expected}", value_token.position, field)
        self.index += 1
        value = value_token.value
        if not (isinstance(value, (str, int))):
            raise RuntimeError("Internal cqql invariant failed")
        normalized = _validate_value(definition, value, value_token.position)
        self.clause_count += 1
        if self.clause_count > MAX_BOOLEAN_CLAUSES:
            raise _query_error(
                "too_many_clauses",
                f"CQQL query exceeds the {MAX_BOOLEAN_CLAUSES}-clause limit",
                field_token.position,
            )
        return Comparison(field, operator, normalized, field_token.position)


def _validate_value(definition: FieldDefinition, value: str | int, position: int) -> str | int:
    if definition.data_type == "integer":
        if not (isinstance(value, int)):
            raise RuntimeError("Internal cqql invariant failed")
        if definition.minimum is not None and value < definition.minimum:
            raise _query_error("value_out_of_range", f"{definition.public_name} must be at least {definition.minimum}", position, definition.public_name)
        if definition.maximum is not None and value > definition.maximum:
            raise _query_error("value_out_of_range", f"{definition.public_name} must be at most {definition.maximum}", position, definition.public_name)
        return value
    if not (isinstance(value, str)):
        raise RuntimeError("Internal cqql invariant failed")
    if not value.strip():
        raise _query_error("invalid_value", f"{definition.public_name} must not be blank", position, definition.public_name)
    if len(value) > definition.maximum_length:
        raise _query_error("value_too_long", f"{definition.public_name} exceeds its value limit", position, definition.public_name)
    if definition.data_type == "ip":
        try:
            return str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise _query_error("invalid_ip", f"{definition.public_name} requires a valid IP address", position, definition.public_name) from exc
    if definition.data_type == "mitre":
        normalized = value.upper()
        if re.fullmatch(r"T\d{4}(?:\.\d{3})?", normalized) is None:
            raise _query_error("invalid_mitre_id", "mitre.id must use T#### or T####.###", position, definition.public_name)
        return normalized
    if definition.allowed_values is not None and value not in definition.allowed_values:
        raise _query_error("invalid_value", f"Unsupported value for {definition.public_name}", position, definition.public_name)
    return value


def _expression_depth(expression: Expression) -> int:
    if isinstance(expression, Comparison):
        return 1
    if isinstance(expression, Negation):
        return 1 + _expression_depth(expression.expression)
    return 1 + max(_expression_depth(expression.left), _expression_depth(expression.right))


def parse_cqql(query: str) -> ParsedCQQL:
    tokens = _lex(query)
    parser = _Parser(tokens)
    expression = parser.parse()
    depth = _expression_depth(expression)
    if depth > MAX_AST_DEPTH:
        raise _query_error(
            "expression_too_deep",
            f"CQQL expression exceeds the AST depth limit of {MAX_AST_DEPTH}",
            0,
        )
    return ParsedCQQL(
        expression=expression,
        token_count=len(tokens) - 1,
        clause_count=parser.clause_count,
        depth=depth,
    )


def _fts_query(value: str, position: int) -> str:
    tokens = re.findall(r"[\w.@:/\\-]+", value.casefold(), flags=re.UNICODE)
    if not tokens:
        raise _query_error("invalid_text_query", "text CONTAINS requires searchable characters", position, "text")
    if len(tokens) > MAX_TEXT_TOKENS:
        raise _query_error("too_many_text_tokens", f"text CONTAINS supports at most {MAX_TEXT_TOKENS} tokens", position, "text")
    if any(len(token) > 64 for token in tokens):
        raise _query_error("text_token_too_long", "Full-text tokens must not exceed 64 characters", position, "text")
    # Only compiler-produced quoted tokens reach MATCH.  User FTS operators are
    # therefore data, not syntax.
    return " AND ".join(f'"{token.replace(chr(34), chr(34) * 2)}"' for token in tokens)


def _compile_expression(expression: Expression) -> tuple[str, list[object], bool]:
    if isinstance(expression, BooleanExpression):
        left_sql, left_parameters, left_fts = _compile_expression(expression.left)
        right_sql, right_parameters, right_fts = _compile_expression(expression.right)
        return (
            f"({left_sql} {expression.operator} {right_sql})",
            [*left_parameters, *right_parameters],
            left_fts or right_fts,
        )
    if isinstance(expression, Negation):
        sql, parameters, uses_fts = _compile_expression(expression.expression)
        return f"(NOT {sql})", parameters, uses_fts

    definition = FIELD_CATALOG[expression.field]
    if definition.data_type == "text":
        if not (isinstance(expression.value, str)):
            raise RuntimeError("Internal cqql invariant failed")
        return (
            "(e.event_id IN (SELECT event_id FROM security_events_fts "
            "WHERE security_events_fts MATCH ?))",
            [_fts_query(expression.value, expression.position)],
            True,
        )
    if definition.data_type == "mitre":
        exists = (
            "EXISTS (SELECT 1 FROM json_each(e.mitre_ids_json) AS cqql_mitre "
            "WHERE cqql_mitre.value = ?)"
        )
        return (f"({exists})" if expression.operator == "=" else f"(NOT {exists})", [expression.value], False)
    if not (definition.column is not None):
        raise RuntimeError("Internal cqql invariant failed")
    if expression.operator in {'CONTAINS','STARTSWITH'}:
        column = 'LOWER(' + definition.column + ')' if definition.case_insensitive else definition.column
        parameter = 'LOWER(?)' if definition.case_insensitive else '?'
        boundary = '= 1' if expression.operator == 'STARTSWITH' else '> 0'
        return ('(instr(' + column + ', ' + parameter + ') ' + boundary + ')', [expression.value], False)
    collation = " COLLATE NOCASE" if definition.case_insensitive else ""
    return (
        f"({definition.column} {expression.operator} ?{collation})",
        [expression.value],
        False,
    )


def _walk_expression(expression: Expression) -> list[Comparison]:
    if isinstance(expression, Comparison):
        return [expression]
    if isinstance(expression, Negation):
        return _walk_expression(expression.expression)
    return [*_walk_expression(expression.left), *_walk_expression(expression.right)]


def _contains_operator(expression: Expression, operator: Literal["AND", "OR"]) -> bool:
    if isinstance(expression, Comparison):
        return False
    if isinstance(expression, Negation):
        return _contains_operator(expression.expression, operator)
    return (
        expression.operator == operator
        or _contains_operator(expression.left, operator)
        or _contains_operator(expression.right, operator)
    )


def _contains_negation(expression: Expression) -> bool:
    if isinstance(expression, Comparison):
        return False
    if isinstance(expression, Negation):
        return True
    return _contains_negation(expression.left) or _contains_negation(expression.right)


def _pure_same_field_equality_or(expression: Expression) -> bool:
    """Identify the only OR shape for which a time-ordered scan is predictable.

    SQLite's multi-seek plan for a broad same-column OR materializes every
    matching row into a temporary ORDER BY B-tree.  Scanning the trusted
    occurred-at index instead preserves identical boolean semantics and can
    stop as soon as the bounded result page is full.
    """

    comparisons = _walk_expression(expression)
    if len(comparisons) < 2 or not _contains_operator(expression, "OR"):
        return False
    if _contains_operator(expression, "AND") or _contains_negation(expression):
        return False
    field = comparisons[0].field
    definition = FIELD_CATALOG[field]
    return bool(
        definition.indexed
        and definition.column is not None
        and all(item.field == field and item.operator == "=" for item in comparisons)
    )


def _same_field_equality_or_subtree(expression: Expression) -> bool:
    """Return true when a Boolean tree contains a safely bounded OR subtree.

    A subtree qualifies only when every leaf is an equality on the same,
    directly indexed field.  This is intentionally narrower than a generic OR
    rewrite: mixed fields, FTS, derived fields, ranges, and negation retain
    SQLite's default planner behavior.
    """

    if _pure_same_field_equality_or(expression):
        return True
    if isinstance(expression, (Comparison, Negation)):
        return False
    return _same_field_equality_or_subtree(expression.left) or _same_field_equality_or_subtree(
        expression.right
    )


def _time_ordered_boolean(expression: Expression, uses_fts: bool) -> bool:
    """Select time-order scanning for a conservative nested Boolean shape.

    Schema 17 retention is bounded to 100k rows.  For direct indexed columns a
    time-ordered scan can therefore stop after the requested page without the
    multi-seek OR plan materializing and sorting every candidate.  Expensive
    per-row predicates remain excluded so sparse FTS/JSON/NOT cases cannot be
    accidentally converted into a full virtual-table or derived-field scan.
    """

    if uses_fts or _contains_negation(expression):
        return False
    if not _contains_operator(expression, "AND") or not _same_field_equality_or_subtree(expression):
        return False
    comparisons = _walk_expression(expression)
    return all(
        FIELD_CATALOG[item.field].indexed
        and FIELD_CATALOG[item.field].column is not None
        and not FIELD_CATALOG[item.field].derived
        for item in comparisons
    )


def _diagnostics(
    expression: Expression,
    uses_fts: bool,
    clause_count: int,
    depth: int,
) -> tuple[
    Literal["LOW", "MODERATE", "HIGH"],
    Literal[
        "INDEX_FRIENDLY",
        "BOOLEAN_COMPLEX",
        "FTS_SELECTIVITY_UNKNOWN",
        "RESOURCE_LIMITED",
        "UNKNOWN_COST",
    ],
    Literal["DEFAULT", "TIME_ORDERED_OR", "TIME_ORDERED_BOOLEAN"],
    tuple[str, ...],
    tuple[str, ...],
]:
    comparisons = _walk_expression(expression)
    fields = tuple(sorted({item.field for item in comparisons}))
    strategy: Literal["DEFAULT", "TIME_ORDERED_OR", "TIME_ORDERED_BOOLEAN"]
    if _pure_same_field_equality_or(expression):
        strategy = "TIME_ORDERED_OR"
    elif _time_ordered_boolean(expression, uses_fts):
        strategy = "TIME_ORDERED_BOOLEAN"
    else:
        strategy = "DEFAULT"
    substring = any(item.operator in {'CONTAINS','STARTSWITH'} and FIELD_CATALOG[item.field].data_type == 'string' for item in comparisons)
    if uses_fts or substring or _contains_operator(expression, "OR") or _contains_negation(expression):
        cost: Literal["LOW", "MODERATE", "HIGH"] = "HIGH"
    elif any(
        FIELD_CATALOG[item.field].derived
        or not FIELD_CATALOG[item.field].indexed
        or item.operator not in {"="}
        for item in comparisons
    ):
        cost = "MODERATE"
    else:
        cost = "LOW"
    plan_class: Literal[
        "INDEX_FRIENDLY",
        "BOOLEAN_COMPLEX",
        "FTS_SELECTIVITY_UNKNOWN",
        "RESOURCE_LIMITED",
        "UNKNOWN_COST",
    ]
    if uses_fts:
        # Static token count is not a defensible selectivity estimate. Runtime
        # benchmark evidence is reported separately instead of mislabelling an
        # arbitrary token as broad or selective.
        plan_class = "FTS_SELECTIVITY_UNKNOWN"
    elif any(
        FIELD_CATALOG[item.field].derived or not FIELD_CATALOG[item.field].indexed
        for item in comparisons
    ):
        plan_class = "UNKNOWN_COST"
    elif substring or clause_count >= 24 or depth >= 7 or _contains_negation(expression):
        plan_class = "RESOURCE_LIMITED"
    elif _contains_operator(expression, "OR"):
        plan_class = "BOOLEAN_COMPLEX"
    else:
        plan_class = "INDEX_FRIENDLY"
    reasons: list[str] = []
    if substring:
        reasons.append('BOUNDED_SUBSTRING_SCAN')
    if uses_fts:
        reasons.append("FTS_CANDIDATE_MATERIALIZATION")
    if _contains_operator(expression, "OR"):
        reasons.append("BOOLEAN_OR")
    if _contains_negation(expression):
        reasons.append("NEGATION_SCAN")
    if any(FIELD_CATALOG[item.field].derived for item in comparisons):
        reasons.append("DERIVED_FIELD")
    if any(not FIELD_CATALOG[item.field].indexed for item in comparisons):
        reasons.append("UNINDEXED_FIELD")
    if any(item.operator not in {"="} for item in comparisons):
        reasons.append("RANGE_COMPARISON")
    if strategy == "TIME_ORDERED_OR":
        reasons.append("TIME_ORDERED_OR")
    if strategy == "TIME_ORDERED_BOOLEAN":
        reasons.append("TIME_ORDERED_BOOLEAN")
    if not reasons:
        reasons.append("INDEXED_EQUALITY")
    return cost, plan_class, strategy, fields, tuple(reasons)


def compile_cqql(query: str) -> CompiledCQQL:
    parsed = parse_cqql(query)
    sql, parameters, uses_fts = _compile_expression(parsed.expression)
    cost_class, plan_class, planner_strategy, referenced_fields, diagnostic_reasons = _diagnostics(
        parsed.expression, uses_fts, parsed.clause_count, parsed.depth
    )
    fingerprint = hashlib.sha256(
        json.dumps(
            {"query": query, "version": CQQL_VERSION},
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    return CompiledCQQL(
        sql=sql,
        parameters=tuple(parameters),
        clause_count=parsed.clause_count,
        depth=parsed.depth,
        uses_fts=uses_fts,
        fingerprint=fingerprint,
        cost_class=cost_class,
        plan_class=plan_class,
        planner_strategy=planner_strategy,
        referenced_fields=referenced_fields,
        diagnostic_reasons=diagnostic_reasons,
    )


def public_field_catalog() -> list[dict[str, object]]:
    return [
        {
            "name": field.public_name,
            "data_type": field.data_type,
            "operators": list(field.operators),
            "indexed": field.indexed,
            "sensitivity": field.sensitivity,
            "source": field.source,
            "derived": field.derived,
            "searchable": field.searchable,
        }
        for field in FIELD_CATALOG.values()
    ]
