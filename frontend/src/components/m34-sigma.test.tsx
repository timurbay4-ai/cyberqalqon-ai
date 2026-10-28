import {act,fireEvent,render,screen,waitFor} from '@testing-library/react';
import {describe,it,expect,vi} from 'vitest';
import captured from '../test/m34-sigma-contract.json';
import {M31_API_CONTRACT} from '../test/m31-api-contract';
import {M30_API_CONTRACT} from '../test/m30-api-contract';
import {createMockApi} from '../test/fixtures';
import {parseSigmaPreview} from '../api/sigma-contract';
import {parseDurableStatus,parseDurableRun,parseFindingPage,parseFindingDetail} from '../api/shadow-history-contracts';
import {parseShadowCatalog} from '../api/shadow-contracts';
import {SigmaImport} from './sigma-import';
import {ShadowHistory} from './shadow-history';

describe('M34 actual Sigma preview and durable finding contracts',()=>{
  it('accepts the actual converted rule, completed run and retained network finding',()=>{
    const preview=parseSigmaPreview(captured.sigma_preview);
    expect(preview.rules[0].definition.contract).toBe('cdrc-v3');
    expect(parseDurableRun(captured.network_evaluation).result?.finding_ids).toHaveLength(1);
    expect(parseFindingDetail(captured.finding_detail).matching_evidence.evaluation_version).toBe('m34-shadow-v1');
  });
  it.each(['active','profile','source-hash','external-id','local-id','metadata','hidden-v2','semantics'])('rejects forged %s output',kind=>{
    const value=structuredClone(captured.sigma_preview);
    const row=value.rules[0],definition=row.definition;
    if(kind==='active')Object.assign(value,{production_active:true});
    if(kind==='profile')value.profile='UNRESTRICTED';
    if(kind==='source-hash')value.source_sha256='f'.repeat(64);
    if(kind==='external-id')row.external_id='not-a-uuid';
    if(kind==='local-id')definition.rule_id='SHADOW-UNRELATED';
    if(kind==='metadata')definition.external_metadata_json='{}';
    if(kind==='hidden-v2')definition.contract='cdrc-v2';
    if(kind==='semantics')definition.predicate_semantics='CQQL_SQL_3VL';
    expect(()=>parseSigmaPreview(value)).toThrow();
  });
  it('requires an explicit preview and use action without automatically evaluating',async()=>{
    const mock=createMockApi({previewSigma:vi.fn().mockResolvedValue(parseSigmaPreview(captured.sigma_preview))});
    const use=vi.fn();render(<SigmaImport api={mock} canMutate onUseRule={use}/>);
    expect(screen.getByRole('button',{name:'Preview Sigma conversion'})).toBeDisabled();
    fireEvent.change(screen.getByLabelText('Sigma YAML'),{target:{value:captured.sigma_source}});
    expect(mock.previewSigma).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button',{name:'Preview Sigma conversion'}));
    const button=await screen.findByRole('button',{name:'Use in existing durable shadow evaluator'});
    expect(use).not.toHaveBeenCalled();expect(mock.createDurableShadowRun).not.toHaveBeenCalled();
    fireEvent.click(button);expect(use).toHaveBeenCalledWith(parseSigmaPreview(captured.sigma_preview).rules[0]);
  });
  it('keeps viewer import controls read-only',()=>{
    const mock=createMockApi();render(<SigmaImport api={mock} canMutate={false} onUseRule={()=>undefined}/>);
    expect(screen.getByLabelText('Sigma YAML')).toHaveAttribute('readonly');
    expect(screen.getByRole('button',{name:'Preview Sigma conversion'})).toBeDisabled();
    expect(mock.previewSigma).not.toHaveBeenCalled();
  });
  it('exposes rejection without adding a usable rule',async()=>{
    const mock=createMockApi({previewSigma:vi.fn().mockRejectedValue(new Error('Unsupported Sigma modifier'))});
    render(<SigmaImport api={mock} canMutate onUseRule={()=>undefined}/>);
    fireEvent.change(screen.getByLabelText('Sigma YAML'),{target:{value:captured.sigma_source}});
    fireEvent.click(screen.getByRole('button',{name:'Preview Sigma conversion'}));
    expect(await screen.findByRole('alert')).toHaveTextContent('Unsupported Sigma modifier');
    expect(screen.queryByRole('button',{name:'Use in existing durable shadow evaluator'})).toBeNull();
  });
  it('cancels stale preview after source edits',async()=>{
    let finish:((value:ReturnType<typeof parseSigmaPreview>)=>void)|undefined,signal:AbortSignal|undefined;
    const mock=createMockApi({previewSigma:vi.fn().mockImplementation((_text,requestSignal)=>{signal=requestSignal;return new Promise(resolve=>{finish=resolve;});})});
    render(<SigmaImport api={mock} canMutate onUseRule={()=>undefined}/>);
    fireEvent.change(screen.getByLabelText('Sigma YAML'),{target:{value:captured.sigma_source}});
    fireEvent.click(screen.getByRole('button',{name:'Preview Sigma conversion'}));
    expect(screen.getByRole('status')).toHaveTextContent('Validating');
    fireEvent.change(screen.getByLabelText('Sigma YAML'),{target:{value:'# different rule'}});
    await act(async()=>{finish?.(parseSigmaPreview(captured.sigma_preview));});
    expect(signal?.aborted).toBe(true);expect(screen.queryByText(/Converted 1 definition/)).toBeNull();
  });
  it('passes the reviewed imported definition to the existing evaluator only on request',async()=>{
    const preview=parseSigmaPreview(captured.sigma_preview);
    const mock=createMockApi({
      getDurableShadowStatus:vi.fn().mockResolvedValue(parseDurableStatus(M31_API_CONTRACT.history_status)),
      getShadowCatalog:vi.fn().mockResolvedValue(parseShadowCatalog(M30_API_CONTRACT.catalog)),
      listDurableShadowFindings:vi.fn().mockResolvedValue(parseFindingPage(M31_API_CONTRACT.history_page)),
      createDurableShadowRun:vi.fn().mockResolvedValue(parseDurableRun(captured.network_evaluation)),
    });
    render(<ShadowHistory api={mock} canMutate importedRules={preview.rules} onOpenEvent={()=>undefined}/>);
    await waitFor(()=>expect(screen.getByLabelText('Durable rule')).toHaveValue('import:'+preview.rules[0].rule_version));
    await screen.findByRole('option',{name:preview.rules[0].definition.title});
    expect(mock.createDurableShadowRun).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button',{name:'Evaluate and save bounded findings'}));
    expect(await screen.findByText(/Not a global detection count/)).toBeInTheDocument();
    expect(mock.createDurableShadowRun).toHaveBeenCalledOnce();
    expect(vi.mocked(mock.createDurableShadowRun).mock.calls[0][0].simulation.rule).toEqual(preview.rules[0].definition);
  });
});
