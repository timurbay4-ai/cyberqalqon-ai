from app.cli.m34_demo import run_demo


def test_complete_isolated_network_auth_shadow_case_and_report_workflow():
    result=run_demo()
    assert result['scope']=='SYNTHETIC_DISPOSABLE_M34' and result['production']=='NOT_DEPLOYED'
    assert result['new_201']==result['event_count']==19 and result['duplicate_200']==9
    assert result['auth_findings']==2 and result['network_findings']==1
    assert result['benign_dns_findings']==0 and result['explicit_cases']==1 and result['automatic_incidents']==0
    assert result['ioc_matches']>0 and result['dns_query_events']==4
    assert result['investigation_finding_id']==result['finding_detail']['finding_id']
    assert result['integrity']['source']['schema']==17 and result['integrity']['history']['schema']==1
    assert all(row['quick_check']=='ok' and row['foreign_key_violations']==0 for row in [
        result['integrity']['source'],result['integrity']['history'],*result['integrity']['checkpoints']])
    assert result['AI_ENABLED'] is False and result['batch_enabled'] is False
