"""Bounded Sigma 2.1 detection/correlation subset, explicit endpoint shadow profile.

No code, regex, SQL, feed fetching, activation or automatic finding creation.
Unsupported semantics are rejected, rather than approximated silently.
"""
from __future__ import annotations

import json
import hashlib
import re
import uuid
from datetime import date, datetime, timezone

import yaml
from yaml.tokens import AliasToken, AnchorToken, TagToken

from app.schemas.shadow_detection import ShadowRule, SelectionStep
from app.services.cqql import (compile_cqql, parse_cqql, FIELD_CATALOG,
                               Comparison, BooleanExpression, CQQLQueryError)
from app.services.wazuh_normalizer import canonical_json

MAX_BYTES = 32768
MAX_DOCS = 8
PROFILE = 'CQ_ENDPOINT_SHADOW_V1'


class SigmaImportError(ValueError):
    pass


def _load(text):
    if not isinstance(text, str):
        raise SigmaImportError('RULE_SIZE_LIMIT')
    try:
        size = len(text.encode('utf-8'))
    except UnicodeError:
        raise SigmaImportError('INVALID_RULE_ENCODING') from None
    if size > MAX_BYTES:
        raise SigmaImportError('RULE_SIZE_LIMIT')
    try:
        for count, token in enumerate(yaml.scan(text), 1):
            if count > 4096:
                raise SigmaImportError('RULE_COMPLEXITY_LIMIT')
            if isinstance(token, (AliasToken, AnchorToken, TagToken)):
                raise SigmaImportError('YAML_ALIAS_ANCHOR_TAG_UNSUPPORTED')
        # Inspect bounded nodes before object construction. Standard safe_load
        # cannot report duplicate keys, so reject them explicitly in this pass.
        documents_seen = nodes_seen = 0
        for root in yaml.compose_all(text, Loader=yaml.SafeLoader):
            documents_seen += 1
            if documents_seen > MAX_DOCS or not isinstance(root, yaml.MappingNode):
                raise SigmaImportError('RULE_DOCUMENT_LIMIT_OR_SHAPE')
            stack = [(root, 0)]
            while stack:
                node, depth = stack.pop();nodes_seen += 1
                if nodes_seen > 1500 or depth > 12:
                    raise SigmaImportError('RULE_COMPLEXITY_LIMIT')
                if isinstance(node, yaml.MappingNode):
                    keys = set()
                    for key, value in node.value:
                        if (not isinstance(key, yaml.ScalarNode) or key.tag != 'tag:yaml.org,2002:str'
                                or key.value in keys):
                            raise SigmaImportError('DUPLICATE_OR_NON_TEXT_KEY')
                        keys.add(key.value);stack.append((value, depth+1))
                elif isinstance(node, yaml.SequenceNode):
                    stack.extend((value, depth+1) for value in node.value)
        documents = list(yaml.safe_load_all(text))
    except (yaml.YAMLError, RecursionError, UnicodeError, ValueError) as exc:
        if isinstance(exc, SigmaImportError):
            raise
        raise SigmaImportError('INVALID_SAFE_YAML') from None
    if not 1 <= len(documents) <= MAX_DOCS:
        raise SigmaImportError('RULE_DOCUMENT_LIMIT')
    stack = [(value, 0) for value in documents]
    count = 0
    while stack:
        value, depth = stack.pop();count += 1
        if count > 1500 or depth > 12:
            raise SigmaImportError('RULE_COMPLEXITY_LIMIT')
        if isinstance(value, dict):
            stack.extend((item, depth+1) for item in value.values())
        elif isinstance(value, list):
            stack.extend((item, depth+1) for item in value)
        elif not isinstance(value, (str, int, float, bool, date, type(None))):
            raise SigmaImportError('INVALID_YAML_VALUE')
    if any(not isinstance(value, dict) for value in documents):
        raise SigmaImportError('RULE_OBJECT_REQUIRED')
    return documents


COMMON = {'title','id','name','status','description','author','date','modified','logsource','detection',
          'correlation','falsepositives','level','tags','references','license','taxonomy'}
FIELD_MAP = {
    'Computer': 'host.name', 'ComputerName': 'host.name', 'EventID': 'event.code',
    'TargetUserName': 'user.name', 'User': 'user.name', 'IpAddress': 'source.ip',
    'SourceIp': 'source.ip', 'DestinationIp': 'destination.ip', 'SourcePort': 'source.port',
    'DestinationPort': 'destination.port', 'Image': 'process.name', 'ParentImage': 'process.parent.name',
    'src_ip': 'source.ip', 'dest_ip': 'destination.ip', 'src_port': 'source.port', 'dest_port': 'destination.port',
    'query': 'dns.question.name', 'rrname': 'dns.question.name', 'sni': 'tls.server.name',
    'hostname': 'http.host', 'signature_id': 'rule.id', 'proto': 'network.protocol',
}


def _date(value):
    try:
        result = value if type(value) is date else date.fromisoformat(value)
        return datetime(result.year, result.month, result.day, tzinfo=timezone.utc)
    except (ValueError, TypeError, AttributeError):
        raise SigmaImportError('EXPLICIT_ISO_RULE_DATE_REQUIRED') from None


def _metadata(document):
    for key, limit in (('description',1024),('author',128),('license',128)):
        if key in document and (not isinstance(document[key],str) or len(document[key]) > limit):
            raise SigmaImportError('INVALID_BOUNDED_METADATA')
    if 'status' in document and document['status'] not in {'stable','test','experimental','deprecated','unsupported'}:
        raise SigmaImportError('UNSUPPORTED_EXTERNAL_STATUS')
    for key, maximum, length in (('tags',12,64),('references',5,256),('falsepositives',10,256)):
        if key in document and (not isinstance(document[key],list) or len(document[key]) > maximum
                or any(not isinstance(value,str) or len(value) > length for value in document[key])):
            raise SigmaImportError('INVALID_BOUNDED_METADATA')
    if 'name' in document and (not isinstance(document['name'],str)
            or re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,63}',document['name']) is None):
        raise SigmaImportError('INVALID_RULE_NAME')


def _field(name, taxonomy):
    value = name if taxonomy == 'cyberqalqon-cuse-v1' else FIELD_MAP.get(name)
    if value not in FIELD_CATALOG or value == 'text':
        raise SigmaImportError('UNSUPPORTED_FIELD_OR_TAXONOMY')
    return value


def _atom(field, value, operator):
    definition = FIELD_CATALOG[field]
    if isinstance(value, bool) or value is None or not isinstance(value, (str, int)):
        raise SigmaImportError('UNSUPPORTED_NULL_OR_VALUE_TYPE')
    if definition.data_type == 'integer':
        if type(value) is not int or operator != '=':
            raise SigmaImportError('INTEGER_EQUALITY_REQUIRED')
        encoded = str(value)
    else:
        if field in {'event.code','rule.id'} and type(value) is int:
            value = str(value)
        if not isinstance(value, str) or not value or not value.isascii() or any(ord(c) < 32 for c in value):
            raise SigmaImportError('BOUNDED_ASCII_LITERAL_REQUIRED')
        if any(char in value for char in '*?'):
            raise SigmaImportError('WILDCARD_SEMANTICS_UNSUPPORTED')
        encoded = json.dumps(value)
    if operator not in definition.operators:
        raise SigmaImportError('UNSUPPORTED_MODIFIER_FOR_FIELD')
    return field + ' ' + operator + ' ' + encoded


def _selection(value, taxonomy):
    if isinstance(value, list):
        if not 1 <= len(value) <= 8 or not all(isinstance(item, dict) for item in value):
            raise SigmaImportError('UNSUPPORTED_KEYWORD_SELECTION')
        return '(' + ' OR '.join(_selection(item, taxonomy) for item in value) + ')'
    if not isinstance(value, dict) or not 1 <= len(value) <= 16:
        raise SigmaImportError('BOUNDED_SELECTION_MAP_REQUIRED')
    terms = []
    for key, values in value.items():
        pieces = key.split('|')
        if len(pieces) > 2 or len(pieces) == 2 and pieces[1] not in {'contains','startswith'}:
            raise SigmaImportError('UNSUPPORTED_MODIFIER')
        field = _field(pieces[0], taxonomy)
        operator = {'contains': 'CONTAINS', 'startswith': 'STARTSWITH'}.get(pieces[-1], '=') if len(pieces) == 2 else '='
        values = values if isinstance(values, list) else [values]
        if not 1 <= len(values) <= 10:
            raise SigmaImportError('SELECTION_VALUE_LIMIT')
        terms.append('(' + ' OR '.join(_atom(field, item, operator) for item in values) + ')')
    return '(' + ' AND '.join(terms) + ')'


def _logsource(value):
    if not isinstance(value, dict) or set(value) - {'product','service','category','definition'}:
        raise SigmaImportError('UNSUPPORTED_LOGSOURCE')
    product, service, category = value.get('product'), value.get('service'), value.get('category')
    if category is not None:
        raise SigmaImportError('LOGSOURCE_CATEGORY_MAPPING_UNSUPPORTED')
    if product == 'windows' and service in {'security','sysmon'}:
        return ('WINDOWS_EVENTCHANNEL' if service == 'security' else 'SYSMON',
                'event.channel = ' + json.dumps('Security' if service == 'security' else 'Microsoft-Windows-Sysmon/Operational'))
    if product == 'linux' and service == 'sshd':
        return 'LINUX_AUTH', 'event.category = "linux_ssh"'
    if product == 'zeek' and service in {'conn','dns','http','ssl'}:
        return 'ZEEK', 'event.channel = ' + json.dumps(service)
    if product == 'suricata' and service in {'alert','dns','http','tls','flow'}:
        return 'SURICATA', 'event.channel = ' + json.dumps(service)
    raise SigmaImportError('UNSUPPORTED_LOGSOURCE')


def _base(document):
    family, source = _logsource(document.get('logsource'))
    taxonomy = document.get('taxonomy', 'sigma')
    if taxonomy not in {'sigma','cyberqalqon-cuse-v1'}:
        raise SigmaImportError('UNSUPPORTED_TAXONOMY')
    detection = document.get('detection')
    if not isinstance(detection, dict) or not 2 <= len(detection) <= 9:
        raise SigmaImportError('BOUNDED_DETECTION_REQUIRED')
    condition = detection.get('condition')
    if not isinstance(condition, str) or len(condition) > 512:
        raise SigmaImportError('BOOLEAN_CONDITION_REQUIRED')
    selections = {}
    for name, value in detection.items():
        if name == 'condition':continue
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,63}', name) or name.lower() in {'and','or','not'}:
            raise SigmaImportError('UNSUPPORTED_SELECTION_IDENTIFIER')
        selections[name] = _selection(value, taxonomy)
    tokens, end = [], 0
    for token in re.finditer(r'[()]|[A-Za-z_][A-Za-z0-9_]*', condition):
        if condition[end:token.start()].strip():
            raise SigmaImportError('UNSUPPORTED_CONDITION')
        word = token.group();end = token.end()
        if word in '()':tokens.append(word)
        elif word.lower() in {'and','or','not'}:tokens.append(word.upper())
        elif word in selections:tokens.append(selections[word])
        else:raise SigmaImportError('UNKNOWN_SELECTION')
    if condition[end:].strip() or not tokens:
        raise SigmaImportError('UNSUPPORTED_CONDITION')
    query = '(' + source + ') AND (' + ' '.join(tokens) + ')'
    compile_cqql(query)
    return family, query


def _constraints(expression):
    if isinstance(expression, Comparison) and expression.operator == '=':
        value = expression.value
        if isinstance(value, str) and FIELD_CATALOG[expression.field].case_insensitive:
            value = value.lower()  # Accepted Sigma literals are ASCII only.
        return {expression.field: {value}}
    if isinstance(expression, BooleanExpression):
        left, right = _constraints(expression.left), _constraints(expression.right)
        if expression.operator == 'AND':
            result = {**left, **right}
            for key in left.keys() & right.keys():result[key] = left[key] & right[key]
            return result
        return {key: left[key] | right[key] for key in left.keys() & right.keys()}
    return {}


def convert_sigma(text: str):
    try:
        return _convert(text)
    except (CQQLQueryError, OverflowError, RecursionError, TypeError) as exc:
        raise SigmaImportError('UNSUPPORTED_BOUNDED_RULE_SEMANTICS') from None


def _convert(text):
    documents = _load(text)
    lookup = {}
    for document in documents:
        if set(document) - COMMON or not isinstance(document.get('title'), str) or not 1 <= len(document['title']) <= 128:
            raise SigmaImportError('UNSUPPORTED_OR_MISSING_RULE_FIELD')
        _metadata(document)
        try:identifier = str(uuid.UUID(document['id']))
        except (ValueError, KeyError, AttributeError):raise SigmaImportError('EXPLICIT_UUID_REQUIRED') from None
        if document['id'] != identifier:
            raise SigmaImportError('CANONICAL_UUID_REQUIRED')
        _date(document.get('date'))
        if ('detection' in document) == ('correlation' in document):
            raise SigmaImportError('ONE_DETECTION_OR_CORRELATION_REQUIRED')
        for key in (identifier, document.get('name')):
            if key is None:continue
            if not isinstance(key, str) or not key or len(key) > 128 or key in lookup:
                raise SigmaImportError('DUPLICATE_RULE_ID_OR_NAME')
            lookup[key] = document
    referenced = set()
    for document in documents:
        if 'correlation' in document:
            if 'logsource' in document:
                raise SigmaImportError('CORRELATION_LOGSOURCE_UNSUPPORTED')
            correlation = document['correlation']
            if not isinstance(correlation, dict) or set(correlation) - {'type','rules','group-by','timespan','condition','generate'}:
                raise SigmaImportError('UNSUPPORTED_CORRELATION_FIELD')
            refs = correlation.get('rules')
            if not isinstance(refs, list) or not 1 <= len(refs) <= 3 or not all(isinstance(value, str) for value in refs):
                raise SigmaImportError('BOUNDED_CORRELATION_REFERENCES_REQUIRED')
            if correlation.get('generate', False) is not False:
                raise SigmaImportError('GENERATE_TRUE_UNSUPPORTED')
            for key in refs:
                if key not in lookup:raise SigmaImportError('MISSING_REFERENCED_RULE')
                referenced.add(lookup[key]['id'])

    def parts(document, parents=()):
        if document['id'] in parents or len(parents) > 2:
            raise SigmaImportError('CYCLIC_OR_DEEP_CORRELATION')
        if 'detection' in document:
            family, query = _base(document)
            return [(family, query, 1)], None, None, [document['id']]
        corr = document['correlation']
        kind = corr.get('type')
        if kind not in {'event_count','temporal','temporal_ordered'}:
            raise SigmaImportError('UNSUPPORTED_CORRELATION_TYPE')
        span = corr.get('timespan')
        if not isinstance(span, str) or re.fullmatch(r'[1-9][0-9]{0,3}[smh]', span) is None:
            raise SigmaImportError('BOUNDED_TIMESPAN_REQUIRED')
        seconds = int(span[:-1]) * {'s': 1, 'm': 60, 'h': 3600}[span[-1]]
        if seconds > 1800:
            raise SigmaImportError('TIMESPAN_LIMIT')
        group = corr.get('group-by')
        if not isinstance(group, list) or not 1 <= len(group) <= 4:
            raise SigmaImportError('BOUNDED_GROUP_REQUIRED')
        group = tuple(_field(value, document.get('taxonomy', 'sigma')) for value in group)
        if 'host.name' not in group or len(set(group)) != len(group):
            raise SigmaImportError('ENDPOINT_GROUP_REQUIRED')
        if 'user.name' in group:
            # Native SID partitioning is stronger than plain Sigma username
            # grouping. Reject rather than silently alter account semantics.
            raise SigmaImportError('ACCOUNT_GROUPING_UNSUPPORTED_NATIVE_IDENTITY_POLICY')
        if any(value not in {'host.name','source.ip','process.guid'} for value in group):
            raise SigmaImportError('UNSUPPORTED_GROUP_FIELD')
        result, ids = [], [document['id']]
        for ref in corr['rules']:
            child, child_group, child_span, child_ids = parts(lookup[ref], (*parents, document['id']))
            if child_group is not None:
                # Aggregate marker time is not the first contributing event
                # time. Flattening would silently narrow a parent's window.
                raise SigmaImportError('NESTED_CORRELATION_MARKER_SEMANTICS_UNSUPPORTED')
            result.extend(child);ids.extend(child_ids)
        if kind == 'event_count':
            condition = corr.get('condition')
            if len(result) != 1 or result[0][2] != 1 or not isinstance(condition, dict) or len(condition) != 1:
                raise SigmaImportError('SINGLE_BASE_EVENT_COUNT_REQUIRED')
            operator, threshold = next(iter(condition.items()))
            if operator not in {'gte','gt'} or type(threshold) is not int:
                raise SigmaImportError('UNSUPPORTED_COUNT_COMPARATOR')
            threshold += int(operator == 'gt')
            if not 1 <= threshold <= 10:
                raise SigmaImportError('COUNT_LIMIT')
            family, query, _ = result[0];result = [(family, query, threshold)]
        else:
            if not 2 <= len(result) <= 3:
                raise SigmaImportError('TEMPORAL_STEP_LIMIT')
            if 'condition' in corr and corr['condition'] != {'gte': len(result)}:
                raise SigmaImportError('PARTIAL_TEMPORAL_THRESHOLD_UNSUPPORTED')
            constraints = [_constraints(parse_cqql(query).expression) for _, query, _ in result]
            for index, left in enumerate(constraints):
                for right in constraints[index+1:]:
                    if not any(left[key] and right[key] and left[key].isdisjoint(right[key]) for key in left.keys() & right.keys()):
                        raise SigmaImportError('OVERLAPPING_TEMPORAL_SELECTORS_UNSUPPORTED')
        return result, group, seconds, ids

    # Validate every graph component, including a cycle disconnected from a
    # valid root. A valid document must not hide invalid companion documents.
    for document in documents:
        parts(document)
    source_sha256 = hashlib.sha256(text.encode('utf-8')).hexdigest()
    roots = [document for document in documents if document['id'] not in referenced]
    if not roots:
        raise SigmaImportError('CYCLIC_CORRELATION')
    rules = []
    for document in roots:
        values, group, seconds, ids = parts(document)
        families = tuple(dict.fromkeys(family for family, _, _ in values))
        metadata = {key: value.isoformat() if type(value) is date else value for key, value in document.items()
                    if key not in {'detection','correlation'}}
        metadata.update(sigma_source_sha256=source_sha256, profile=PROFILE,
                        external_rules=[{key: value.isoformat() if type(value) is date else value for key, value in lookup[identifier].items()
                                         if key not in {'detection','correlation'}} for identifier in dict.fromkeys(ids)])
        level = document.get('level', 'medium')
        if level not in {'informational','low','medium','high','critical'}:
            raise SigmaImportError('UNSUPPORTED_LEVEL')
        created = _date(document['date']);modified = _date(document.get('modified', document['date']))
        try:
            rule = ShadowRule(
                contract='cdrc-v3', rule_id='SHADOW-SIGMA-'+uuid.UUID(document['id']).hex.upper(),
                title=document['title'], description=document.get('description') or 'Imported Sigma endpoint shadow profile.',
                author='CyberQalqon Sigma adapter', status='SHADOW_ONLY', confidence=40,
                severity={'informational': 2, 'low': 4, 'medium': 8, 'high': 12, 'critical': 15}[level],
                source_families=families, required_fields=group or ('host.name',), group_by=group or ('host.name',),
                steps=tuple(SelectionStep(query=query, threshold=threshold) for _, query, threshold in values),
                correlation_mode='UNORDERED' if document.get('correlation', {}).get('type') == 'temporal' else 'ORDERED',
                predicate_semantics='SIGMA_2VL', external_rule_ids=tuple(dict.fromkeys(ids)),
                external_metadata_json=canonical_json(metadata), window_seconds=seconds or 300, allowed_lateness=0,
                created_at=created, updated_at=modified)
        except ValueError:
            raise SigmaImportError('UNSUPPORTED_BOUNDED_RULE_DEFINITION') from None
        rules.append({'definition': rule.model_dump(mode='json'), 'rule_version': rule.rule_version,
                      'external_id': document['id']})
    return {'contract': 'cq-sigma-preview-v1', 'profile': PROFILE, 'status': 'CONVERTED_SHADOW_ONLY',
            'production_active': False, 'rules': rules, 'source_sha256': source_sha256,
            'warnings': ['ENDPOINT_NAMESPACE_ONLY_NO_CROSS_COLLECTOR_CORRELATION',
                         'SOURCE_AND_WINDOW_COMPLETENESS_UNPROVEN', 'PREVIEW_DOES_NOT_PERSIST_OR_ACTIVATE_RULES']}
