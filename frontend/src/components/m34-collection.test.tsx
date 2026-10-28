import {fireEvent,render,screen,waitFor,within} from '@testing-library/react';
import {describe,it,expect,vi} from 'vitest';
import contract from '../test/m34-api-contract.json';
import {createMockApi} from '../test/fixtures';
import {parseSourceCoverage} from '../api/collection-contract';
import {parseSecurityEvent,parseCUSEMetadata} from '../api/contracts';
import {SourceCoverage} from './source-coverage';
import {EventSourceContext} from './event-source-context';

describe('M34 actual synthetic API contracts and source evidence UI',()=>{
  it('accepts every captured network event and keeps source and delivery identities distinct',()=>{
    expect(contract.scope).toBe('SYNTHETIC_TEST');
    for(const row of contract.network_events){
      const event=parseSecurityEvent(row);
      expect(event.source_type).toBe('network');
      expect(event.cuse?.adapter_version).toBe('m34-network-v1');
      expect(event.cuse?.endpoint_identity_verified).toBe(false);
      expect(event.source_event_id).not.toBe(event.cuse?.original_event_identity);
    }
  });
  it('accepts observed and empty retained samples without manufacturing connected state',()=>{
    const empty=parseSourceCoverage(contract.empty_source_coverage),observed=parseSourceCoverage(contract.observed_source_coverage);
    expect(empty.sample_count).toBe(0);expect(observed.sample_count).toBe(9);
    expect(observed.families.every(row=>row.connected==='UNKNOWN')).toBe(true);
    expect(observed.registered_sources.every(row=>row.last_acknowledged_delivery===null)).toBe(true);
  });
  it.each(['production','connectivity','count','freshness','identity','worker'])('rejects forged %s metadata',mode=>{
    const value=structuredClone(contract.observed_source_coverage) as Record<string,any>;
    if(mode==='production')value.production_active=true;
    if(mode==='connectivity')value.families[6].connected='CONNECTED';
    if(mode==='count')value.families[6].sample_normalized_count=1001;
    if(mode==='freshness')value.families[0].freshness='OBSERVED';
    if(mode==='identity')value.registered_sources[0].last_acknowledged_delivery='invented';
    if(mode==='worker')value.continuous_worker_state='OBSERVED_ISOLATED_WORKERS';
    expect(()=>parseSourceCoverage(value)).toThrow();
  });
  it('rejects network identity metadata on a legacy CUSE adapter',()=>{
    const value=structuredClone(contract.network_events[0].cuse);
    value.adapter_version='m28-v1';
    expect(()=>parseCUSEMetadata(value)).toThrow();
  });
  it('drills from actual source evidence into the existing event workflow',async()=>{
    const report=parseSourceCoverage(contract.observed_source_coverage),open=vi.fn();
    const api=createMockApi({getSourceCoverage:vi.fn().mockResolvedValue(report)});
    render(<SourceCoverage api={api} onOpenEvent={open}/>);
    fireEvent.click(await screen.findByRole('button',{name:'Open ZEEK event'}));
    expect(open).toHaveBeenCalledWith(report.families.find(row=>row.family==='ZEEK')?.latest_event_id);
    expect(screen.getByText(/SYNTHETIC TEST/)).toBeInTheDocument();
    expect(screen.getByText(/Parser availability does not prove connectivity/)).toBeInTheDocument();
  });
  it('shows empty, loading and failure states without green fallback counts',async()=>{
    let resolve!:(value:ReturnType<typeof parseSourceCoverage>)=>void;
    const api=createMockApi({getSourceCoverage:vi.fn().mockImplementation(()=>new Promise(value=>{resolve=value;}))});
    const view=render(<SourceCoverage api={api}/>);
    expect(screen.getByRole('status')).toHaveTextContent('Loading bounded source coverage');
    resolve(parseSourceCoverage(contract.empty_source_coverage));
    expect(await screen.findByText(/No retained source observations/)).toBeInTheDocument();
    view.unmount();
    render(<SourceCoverage api={createMockApi({getSourceCoverage:vi.fn().mockRejectedValue(new Error('Permission denied'))})}/>);
    expect(await screen.findByRole('alert')).toHaveTextContent('Permission denied');
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
  });
  it('escapes source labels and creates bound, non-URL DNS query pivots',async()=>{
    const report=parseSourceCoverage(contract.observed_source_coverage);
    report.registered_sources[0].host='<img src=x onerror=alert(1)>';
    const view=render(<SourceCoverage api={createMockApi({getSourceCoverage:vi.fn().mockResolvedValue(report)})}/>);
    expect(await screen.findByText(/Host <img src=x/)).toBeInTheDocument();
    expect(view.container.querySelector('img')).toBeNull();view.unmount();
    const event=parseSecurityEvent(contract.network_events.find(row=>row.event_provider==='Zeek'&&row.event_channel==='dns'));
    const pivot=vi.fn(),url=window.location.href;
    render(<EventSourceContext event={event} onPivotQuery={pivot}/>);
    fireEvent.click(screen.getByRole('button',{name:'Search dns.question.name'}));
    expect(pivot).toHaveBeenCalledWith('dns.question.name = "synthetic.example.test"');
    expect(window.location.href).toBe(url);
  });
});
