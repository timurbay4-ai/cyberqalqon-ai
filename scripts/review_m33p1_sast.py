"""Materialize the individually reviewed M33 findings; fail on source drift.

Not a scanner replacement or suppression. Raw scanner exit/findings remain intact.
Provenance notes describe present callers, not arbitrary future internal callers.
"""
from __future__ import annotations
import ast
from collections import Counter
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Reviewed SQL interpolation provenance, indexed by the original finding ordinal.
# Values always remain DB-API parameters; these notes identify syntax provenance.
SQL = {
    1: 'CLI builds only question-mark placeholders for fixed correlation rule IDs; IDs and limit are bound separately.',
    46: 'get_agent constructs question-mark count from selected alert IDs; all alert IDs are bound and result is capped at 25.',
    47: 'AlertWorkflowFilters -> _conditions emits literal alert/workflow clauses and separate value parameters; list joins only those clauses.',
    48: 'alert_where uses literal clauses from _conditions; filter values are alert_params, never SQL text.',
    49: 'Same literal alert_where plus one of two fixed unassigned predicates; all values remain bound.',
    50: 'bulk_update constructs question-mark placeholders for bounded alert_ids; actor/version/RBAC checks precede mutation.',
    53: 'AlertRepository conditions use fixed filter columns, parameterized values and validated pagination; base_where contains no request text.',
    54: 'page_where adds fixed keyset comparison with bound time/ID; sort chooses ASC or DESC literals only.',
    55: 'AuditRepository.list emits constant filter clauses; search wildcard escaping and binding protect user-provided values.',
    56: 'CaseRepository.list conditions are literal status/owner/query clauses; filters and cursor values are bound.',
    57: 'Metadata assignment keys derive only from title/description/severity/priority plus two literal SLA fields; all new values/version/ID are bound.',
    58: 'kind indexes a three-entry literal alert/incident/event table-column map; unsupported kind raises before execute; reference ID is bound.',
    59: 'Insert table/column uses the same three-entry literal map; case/reference/actor/time values are bound.',
    60: 'CQQL route compiles validated AST; _candidate_from emits two fixed FROM forms, predicates come from compiler, directions literal and values bound.',
    61: 'Analytics projection indexes GROUP_COLUMNS constant map; predicate comes from compiler, time/value parameters separate; no raw field interpolation.',
    62: 'Covering INDEX_NAME is imported source constant and definition verified; projection from GROUP_COLUMNS; compiler parameters remain bound.',
    63: 'Dimension and gN aliases are integers from bounded group_by enumeration; limits bound; GROUP_COLUMNS rejects unknown fields.',
    64: 'bucket_expression selects only fixed hour/day substr expressions, with no user format string.',
    65: 'Export shares validated CQQL compiler, fixed select/FROM fragments and sort direction; time/values/limit are parameters, connection query_only.',
    69: 'RuleCondition uses enum field -> _EVENT_COLUMNS, literal operator templates and internal prefix c.; conditions and times/limits bound.',
    73: '_hunt_where uses fixed filters or compile_cqql; count receives separate parameters and bounded query-only deadline.',
    74: 'Same validated hunt predicate, fixed sort choice and projection; limit/offset and filter values bound.',
    76: 'IOC indicator filters are literal type/activity/search clauses; indicator_type enum and escaped LIKE values bound.',
    85: 'Protection alias explicitly rejects everything except security_events/e before formatting; predicate is fixed schema-17 protection logic.',
    86: 'Protection page IDs supply only question-mark count; IDs from source rows passed as values.',
    87: 'Evidence pin IDs supply only question-mark count; evidence_type is a literal and IDs bound.',
    88: 'Case reference IDs supply only question-mark count; reference_type literal and IDs bound.',
    89: 'Linked alert IDs form a bound tuple and a generated question-mark list; source contents never enter SQL syntax.',
    90: 'Retention where is empty or fixed keyset predicate over occurred_at/event_id; cursor and page size are bound.',
    91: 'protected predicate is the alias-validated fixed helper; age cutoff bound and protected-evidence logic preserved.',
    92: 'Selected deletable event IDs become only question-mark placeholders; actual IDs bound inside the same writer transaction.',
    93: 'Batch ID and dedup hash arrays determine question-mark count only; both sets bound independently, no batch activation implied.',
    94: 'Batch alert lookup uses question-mark count only and bound source event IDs.',
    95: 'count_where comes from EventRepository._conditions, fixed exact_fields/FTS/keyset clauses; all values bound.',
    96: 'Overview bucket chooses fixed strftime hour/day formats according to source conditional, not caller SQL; times bound.',
    97: 'Alert overview uses the same fixed bucket format; time boundaries bound.',
    98: 'Aggregate projection uses _protected_event_filter() with its default allowlisted alias; no request SQL.',
    99: '_require_alerts emits only generated question marks for IDs, values bound, missing IDs reject.',
    100: 'Incident filter builder emits fixed rule/status/agent/time/search clauses; values bound, count SQL never contains raw filters.',
    101: 'Incident keyset page_where adds fixed predicates; order branch is literal, all page/filter values bound.',
    102: '_event_select emits e.* plus a fixed optional-column list; introspected names only select fallback presence, never copied into SQL; ID bound.',
    103: 'Target column is selected from fixed hostname/username/source_ip/etc target kinds; target value/time bounds are parameters.',
    104: 'Relation field/NOCASE are fixed source tuples; cursor_clause literal, decoded cursor values bound and source binding checked.',
    105: 'Incident IDs create only question-mark placeholders; fixed projection and cursor clause, values bound.',
    106: 'Only generated question-mark count is interpolated; incident IDs bound; capped result.',
    107: 'Case IDs create reused placeholder groups with bound tuples; literal relation subqueries/projection/keyset and bound times/ID/limit.',
    108: 'Notification scope always includes analyst_id = ?; remaining read-state clauses literal and analyst/limit bound.',
    109: '_capacity iterates only three literal sidecar table/cap tuples; adding flags do not become SQL identifiers.',
    110: 'page predicate is empty or fixed bound keyset WHERE; cursor validates store/checksum; limit bound.',
    111: 'Related incident predicate is transformed from literal alert-condition strings, with related values in separate incident_params.',
    112: 'Event report WHERE joins literal severity/host/rule/time clauses, all values bound.',
    113: 'Alert report WHERE uses matching literal clauses and separate parameters.',
    114: 'Incident report conditions are fixed time and related-alert EXISTS clauses; values bound.',
    115: 'Event source aggregation shares literal event_where; no caller-provided group identifier.',
    116: 'Severity CASE and grouping literal; alert_where from fixed clauses and bound values.',
    117: 'Rule aggregation literal group column, fixed alert_where and bound values.',
    118: 'Host COALESCE/grouping source constants; fixed event_where and bound values.',
    119: 'Authentication predicate is fixed source SQL with fixed report filters; all variable values bound.',
    120: 'File-integrity predicate is literal plus fixed event_where and bound report values.',
    126: 'RuleSpec comes from built-in RULE_BY_ID; placeholder counts for source/event categories, enum rule and bound values/time/limit.',
    133: 'snapshot_columns is constant schema column enumeration; evidence IDs become only question marks and are bound.',
    134: 'Reconcile predicate is empty or fixed revision keyset; validated store/source/checksum cursor and bound values/limit.',
    137: 'Built-in correlation spec rule IDs form only question-mark count; agent/time/IDs/limit bound.',
    138: 'Correlation membership lookup creates only question marks, alert IDs bound.',
    139: 'Same bound membership IDs and fixed manual-incident exclusion; no dynamic identifiers.',
    140: '_logical callers pass only explicit literal source/sidecar table tuples, never sqlite_master names or a request parameter.',
    141: 'snapshot_columns is constant, LIMIT bound, offline disposable scheduler validates source and admission.',
    142: 'Every rule step is compiled CQQL; columns fixed; predicates generated from validated AST; all literal values/time/limit bound.',
    143: 'Sealed recovery set validates version, bounds, uniqueness and digest; event IDs create only placeholders and are bound.',
    144: 'Finding detail uses fixed snapshot column list and bound evidence IDs from verified sidecar references.',
    149: 'id_clause is empty or literal AND id = ?; queue_id bound, queue states/time/lease values bound.',
    150: 'Counter name is one of two source literals after DeliveryClassification validation; leased item and byte count bound.',
    151: 'counter_sql selects one of three literal failure-counter assignments; classification validates before execute; values sanitized/bound.',
}

# Module-specific behavioral evidence; not a claim that one generic SQL test
# reaches every repository/caller. Individual test function IDs are exported too.
TESTS_BY_MODULE = {
    'correlate_alerts':['test_incident_correlation'], 'agents':['test_agents'],
    'alert_workflows':['test_alert_workflows'], 'alerts':['test_alert_reads','test_alert_ingestion'],
    'audit':['test_auth','test_m30_shadow','test_m33p1_security'], 'cases':['test_cases','test_m33p1_security'],
    'cqql':['test_cqql','test_m33p1_security'], 'detection_engineering':['test_detection_engineering'],
    'detection_readiness':['test_detection_readiness'], 'events':['test_security_events','test_m19_ingestion_remediation','test_m33p1_security'],
    'incidents':['test_incidents','test_incident_correlation'], 'investigation_workbench':['test_investigation_workbench','test_m33_release'],
    'notifications':['test_alert_workflows','test_cases'], 'shadow_history':['test_m31_history','test_m32_storage'],
    'siem':['test_siem_console'], 'advanced_detection':['test_advanced_detection','test_detection_quality'],
    'detection_quality':['test_detection_quality'], 'evidence_consistency':['test_m32_storage','test_m33_release'],
    'incident_correlation':['test_incident_correlation'], 'shadow_backup':['test_m32_storage','test_backup_restore'],
    'shadow_continuity':['test_m33_release'], 'shadow_detection':['test_m30_shadow','test_m31_history'],
    'windows_agent_diagnostics':['test_m33_release'], 'rc_demo':['test_m33_release'],
    'shadow_scenario':['test_m30_shadow'],
}


def main():
    raw = json.loads((ROOT/'docs/release/M33_SAST_RESULTS.json').read_text(encoding='utf-8'))
    reviewed = []
    for index, old in enumerate(raw['findings'], 1):
        path = ROOT/old['path']; content = path.read_bytes()
        if hashlib.sha256(content).hexdigest() != old['source_sha256']:
            raise RuntimeError('Finding source drift requires fresh individual review')
        source = content.decode('utf-8'); tree = ast.parse(source)
        functions = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                     and n.lineno <= old['line'] <= n.end_lineno]
        function = min(functions, key=lambda n: n.end_lineno-n.lineno) if functions else None
        name = function.name if function else 'MODULE'
        rule = old['test_id']; category = 'FALSE_POSITIVE'; change = 'No source change justified by this finding.'
        impact = 'No SQL syntax injection from current external callers; changing internal construction/callers requires re-review.'
        reachability = 'Authenticated API -> schema/enum/compiler -> repository; internal helper is not an API SQL endpoint.'
        tests = ['backend/tests/test_security_events.py', 'backend/tests/test_cqql.py',
                 'backend/tests/test_cases.py', 'backend/tests/test_m31_history.py']
        if rule == 'B608':
            rationale = SQL[index]
            if 'wazuh/' in old['path']:
                reachability = 'Local sender delivery state -> spool, leased ownership and DeliveryClassification; no remote SQL API.'
                tests = ['wazuh/tests/test_spool.py']
            elif '/cli/' in old['path'] or 'shadow_backup' in old['path']:
                reachability = 'Explicit local CLI or disposable/offline backup helper; current literal caller provenance reviewed.'
        elif rule == 'B101':
            if name in {'run_demo', 'run_scenario'}:
                category = 'TEST_ONLY_FIXTURE'
                rationale = 'Explicit synthetic disposable CLI self-check; assert validates test results, not production auth or mutation permission.'
                impact = 'python -O can omit demo validation; ordinary pytest/CLI uses optimization disabled. Do not treat optimized demo as acceptance.'
            else:
                category = 'DEFENSE_IN_DEPTH_IMPROVEMENT'
                rationale = 'Internal post-query/type/parser invariant; caller validation or preceding not-found/state checks protect external inputs.'
                impact = 'Under python -O invariant diagnostics disappear; inspected downstream operations fail on absent rows/type mismatch rather than granting authority.'
            reachability = 'Exact enclosing function: '+name+'; no assert is the sole authentication/RBAC/CSRF check.'
            tests = ['backend/tests/test_detection_engineering.py', 'backend/tests/test_cqql.py',
                     'backend/tests/test_m33_release.py', 'wazuh/tests/test_m22_forward_integration.py']
        elif rule in {'B104', 'B108'}:
            rationale = ('String is a missing-IP classifier or suspicious writable-path detection marker, not a listener or temporary file operation.')
            impact = 'No socket bind, file creation or unsafe directory permission results from this literal.'
            reachability = 'Telemetry normalization/detection evaluation on strings; no host operation.'
            tests = ['backend/tests/test_advanced_detection.py', 'backend/tests/test_detection_quality.py']
            if '/detection_quality.py' in old['path']:
                category = 'TEST_ONLY_FIXTURE'
            if index == 125:
                category = 'DUPLICATE_FINDING'
                rationale += ' Same line/classification as ordinal 124; second static path marker, retained as a separate raw finding.'
        else:
            category = 'ENVIRONMENT_CONFIGURATION_WARNING'
            rationale = 'Fixed sc.exe/wsl.exe argument lists, shell=False, bounded timeout; distro is a local operator option, agent name only escaped for regex.'
            impact = 'No request-derived shell execution. Local executable search trusts operator PATH; privileged WSL diagnostics remain an operator gate.'
            reachability = 'Read-only local Windows diagnostic entry point; not called in this task and not a remotely exposed shell.'
            tests = ['backend/tests/test_m33_release.py', 'tests/deployment/test_windows_monitoring_artifacts.py']
        stable = hashlib.sha256((old['path']+'|'+str(old['line'])+'|'+rule+'|'+str(index)).encode()).hexdigest()[:16]
        modules = TESTS_BY_MODULE.get(path.stem)
        if modules:
            tests = ['backend/tests/'+name+'.py' for name in modules]
        # Only cite real test sources; do not invent evidence paths.
        tests = [name for name in tests if (ROOT/name).is_file()]
        if not tests:
            raise RuntimeError('Triage verification evidence is missing')
        test_ids = []
        for test_path in tests:
            tree_of_tests = ast.parse((ROOT/test_path).read_text(encoding='utf-8'))
            names = [n.name for n in ast.walk(tree_of_tests) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))
                     and n.name.startswith('test_')]
            # Relevant adversarial/contract examples are navigation references;
            # the whole module is executed in full regression.
            selected = [n for n in names if any(word in n for word in
                        ('sql','inject','parameter','csrf','bound','conflict','permission','audit','security','restore','identity'))]
            test_ids.extend(test_path+'::'+name for name in (selected or names)[:8])
        reviewed.append({'id':'M33P1-'+stable, 'original_ordinal':index, 'file':old['path'], 'line':old['line'],
                         'function':name, 'scanner_rule':rule, 'severity':old['severity'], 'confidence':old['confidence'],
                         'source_sha256':old['source_sha256'], 'category':category, 'exploitability_or_impact':impact,
                         'reachability':reachability, 'trust_boundary_and_rationale':rationale,
                         'proposed_fix':change if category != 'DEFENSE_IN_DEPTH_IMPROVEMENT' else 'Optional future explicit invariant errors; no confirmed auth bypass found. Keep scanner findings visible.',
                         'actual_fix':'NONE_REQUIRED_FOR_CONFIRMED_VULNERABILITY', 'verification_tests':tests,
                         'verification_test_functions':test_ids,
                         'review_status':'SOURCE_REVIEWED_SINGLE_ENGINEER_NOT_INDEPENDENT_SIGNOFF'})
    if len(reviewed) != 151 or len(SQL) != 73:
        raise RuntimeError('Incomplete finding inventory cannot pass triage')
    strict = [r for r in reviewed if r['severity'] in {'MEDIUM','HIGH'} and r['confidence'] in {'MEDIUM','HIGH'}]
    report = {'scope':'INDIVIDUAL_SOURCE_PROVENANCE_TRIAGE_OF_ORIGINAL_151_FINDINGS', 'total_found':151,
              'strict_found':len(strict), 'confirmed_high_risk':0, 'confirmed_fixed':0,
              'unresolved_scanner_findings':0, 'reviewed_category_counts':dict(Counter(r['category'] for r in reviewed)),
              'raw_scanner_gate':'FAIL_UNCHANGED_NO_SUPPRESSION', 'triage_gate':'PASS_WITH_WARNINGS_SINGLE_REVIEW',
              'independent_review':'NOT_PERFORMED', 'limits':'Present source/callers only; not a proof of absence of all application vulnerabilities.',
              'findings':reviewed}
    output = ROOT/'docs/release/M33P1_SAST_TRIAGE.json'
    output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k!='findings'}))


if __name__ == '__main__':
    main()
