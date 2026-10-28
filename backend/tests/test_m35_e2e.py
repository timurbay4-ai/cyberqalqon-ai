from app.cli.m35_demo import run_demo


def test_m35_actual_owned_api_recovery_and_evidence_workflow():
    result=run_demo()
    assert result['scope']=='SYNTHETIC_DISPOSABLE_M35' and result['production']=='NOT_DEPLOYED'
    assert result['go']==result['collector_binary_and_spool']==result['file_rotation_acceptance']=='NOT_EVALUATED_BY_THIS_PYTHON_DEMO'
    assert result['unsealed_run']['checkpoint']=='UNSEALED'
    assert result['unsealed_run']['recovery_state']=='UNSEALED_VERIFICATION_REQUIRED'
    assert result['completed_run']['run_id']==result['unsealed_run']['run_id']
    assert result['completed_run']['status']=='COMPLETED'
    assert result['counts']=={'findings':1,'revisions':1}
    history=result['history_committed_coverage']['detection_workers'][0]
    checkpoint=result['checkpoint_committed_coverage']['detection_workers'][0]
    assert history['progress']['stage']=='FINDINGS_COMMITTED' and history['ticks_committed']==0
    assert checkpoint['progress']['stage']=='CHECKPOINT_COMMITTED' and checkpoint['ticks_committed']==1
    assert result['investigation_finding_id']==result['finding_detail']['finding_id']
    assert 'MISSING' in result['missing_evidence_detail']['current_evidence_availability'].values()
    assert result['retention_gap_coverage']['detection_workers'][0]['progress']['observed_gap']=='RETENTION_GAP'
    assert all(x['quick_check']=='ok' and x['foreign_key_violations']==0 for x in result['integrity'].values())
    assert not result['AI_ENABLED'] and not result['batch_enabled']
