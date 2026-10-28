import {fireEvent,render,screen} from '@testing-library/react';
import {describe,it,expect,vi} from 'vitest';
import captured from '../test/m35-api-contract.json';
import {M30_API_CONTRACT} from '../test/m30-api-contract';
import {M31_API_CONTRACT} from '../test/m31-api-contract';
import {createMockApi} from '../test/fixtures';
import {parseDurableRun,parseDurableStatus,parseFindingPage} from '../api/shadow-history-contracts';
import {parseShadowCatalog} from '../api/shadow-contracts';
import {parseSourceCoverage} from '../api/collection-contract';
import {SourceCoverage} from './source-coverage';
import {ShadowHistory} from './shadow-history';

function api(){return createMockApi({
  getDurableShadowStatus:vi.fn().mockResolvedValue(parseDurableStatus(captured.unsealed_history_status)),
  getShadowCatalog:vi.fn().mockResolvedValue(parseShadowCatalog(M30_API_CONTRACT.catalog)),
  listDurableShadowFindings:vi.fn().mockResolvedValue(parseFindingPage(M31_API_CONTRACT.history_page)),
  getDurableShadowRun:vi.fn().mockResolvedValue(parseDurableRun(captured.unsealed_run)),
  resumeDurableShadowRun:vi.fn().mockResolvedValue(parseDurableRun(captured.completed_run)),
});}

describe('M35 actual unsealed intent and checkpoint progress',()=>{
  it('accepts actual before/after contracts without claiming source completeness',()=>{
    const before=parseDurableRun(captured.unsealed_run),after=parseDurableRun(captured.completed_run);
    expect(before.recovery_state).toBe('UNSEALED_VERIFICATION_REQUIRED');
    expect(before.recovery_intent?.verification).toBe('RECHECK_REQUIRED');
    expect(after.run_id).toBe(before.run_id);expect(after.checkpoint).toBe('SEALED');
    expect(parseSourceCoverage(captured.history_committed_coverage).detection_workers[0].ticks_committed).toBe(0);
    expect(parseSourceCoverage(captured.checkpoint_committed_coverage).detection_workers[0].ticks_committed).toBe(1);
  });
  it.each(['wrong-seal','global-scope','oversize','wrong-verification','unknown-state'])('rejects forged intent %s',kind=>{
    const value=structuredClone(captured.completed_run);
    if(kind==='wrong-seal')value.recovery_intent.manifest_sha256='f'.repeat(64);
    if(kind==='global-scope')value.recovery_intent.scope='GLOBAL_COMPLETE';
    if(kind==='oversize')value.recovery_intent.candidate_rows=1001;
    if(kind==='wrong-verification')value.recovery_intent.verification='RECHECK_REQUIRED';
    if(kind==='unknown-state')value.recovery_state='AUTOMATICALLY_RECOVERED';
    expect(()=>parseDurableRun(value)).toThrow();
  });
  it.each(['false-checkpoint','fake-global-complete','missing-run','fake-history-complete'])('rejects forged progress %s',kind=>{
    const value=structuredClone(captured.history_committed_coverage),worker=value.detection_workers[0];
    if(kind==='false-checkpoint')worker.progress.stage='CHECKPOINT_COMMITTED';
    if(kind==='fake-global-complete')worker.progress.window_completeness='COMPLETE';
    if(kind==='missing-run')worker.progress.pending_run_id=null as unknown as string;
    if(kind==='fake-history-complete')worker.progress.run_status='RUNNING';
    expect(()=>parseSourceCoverage(value)).toThrow();
  });
  it('shows actual history completion while checkpoint remains pending',async()=>{
    render(<SourceCoverage api={createMockApi({getSourceCoverage:vi.fn().mockResolvedValue(parseSourceCoverage(captured.history_committed_coverage))})}/>);
    expect(await screen.findByLabelText('Durable evaluation progress')).toHaveTextContent('Evaluation stage: FINDINGS_COMMITTED');
    expect(screen.getByLabelText('Durable evaluation progress')).toHaveTextContent('Checkpoint commits: 0');
    expect(screen.getByLabelText('Durable evaluation progress')).toHaveTextContent('collector delivery acknowledgement is UNKNOWN');
  });
  it('requires an explicit human action to verify and resume',async()=>{
    const mock=api();render(<ShadowHistory api={mock} canMutate onOpenEvent={()=>undefined}/>);
    fireEvent.click(await screen.findByRole('button',{name:'Inspect pending run '+captured.unsealed_run.run_id}));
    const button=await screen.findByRole('button',{name:'Verify source and resume unsealed intent'});
    expect(mock.resumeDurableShadowRun).not.toHaveBeenCalled();
    expect(screen.getByLabelText('Unsealed recovery verification')).toHaveTextContent('Checkpoint has not advanced');
    fireEvent.click(button);
    expect(await screen.findByText(/: COMPLETED; checkpoint SEALED/)).toBeInTheDocument();
    expect(mock.resumeDurableShadowRun).toHaveBeenCalledOnce();
    expect(vi.mocked(mock.resumeDurableShadowRun).mock.calls[0][0]).toBe(captured.unsealed_run.run_id);
  });
  it('allows viewer inspection while keeping recovery mutation disabled',async()=>{
    const mock=api();render(<ShadowHistory api={mock} canMutate={false} onOpenEvent={()=>undefined}/>);
    fireEvent.click(await screen.findByRole('button',{name:'Inspect pending run '+captured.unsealed_run.run_id}));
    expect(await screen.findByRole('button',{name:'Verify source and resume unsealed intent'})).toBeDisabled();
    expect(mock.resumeDurableShadowRun).not.toHaveBeenCalled();
  });
});
