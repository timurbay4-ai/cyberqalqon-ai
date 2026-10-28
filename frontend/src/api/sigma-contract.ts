import {ContractError} from './contracts';
import {parseShadowRule} from './shadow-contracts';
import type {ShadowRule} from '../types/shadow-detection';

export interface SigmaPreview {
  contract:'cq-sigma-preview-v1';profile:'CQ_ENDPOINT_SHADOW_V1';status:'CONVERTED_SHADOW_ONLY';
  production_active:false;source_sha256:string;warnings:string[];
  rules:{definition:ShadowRule;rule_version:string;external_id:string}[];
}
export function parseSigmaPreview(value:unknown):SigmaPreview {
  const fail=():never=>{throw new ContractError('sigma.preview');};
  if(!value||typeof value!=='object'||Array.isArray(value))return fail();
  const item=value as Record<string,unknown>;
  if(item.contract!=='cq-sigma-preview-v1'||item.profile!=='CQ_ENDPOINT_SHADOW_V1'||item.status!=='CONVERTED_SHADOW_ONLY'||item.production_active!==false||typeof item.source_sha256!=='string'||!/^[a-f0-9]{64}$/.test(item.source_sha256)||!Array.isArray(item.rules)||item.rules.length<1||item.rules.length>8||!Array.isArray(item.warnings)||item.warnings.length>20||item.warnings.some(value=>typeof value!=='string'||value.length>256))return fail();
  const seen=new Set<string>();
  const rules=item.rules.map(value=>{
    if(!value||typeof value!=='object'||Array.isArray(value))return fail();
    const row=value as Record<string,unknown>,definition=parseShadowRule(row.definition);
    if(definition.contract!=='cdrc-v3'||definition.predicate_semantics!=='SIGMA_2VL'||definition.status!=='SHADOW_ONLY'||definition.confidence>40||typeof row.rule_version!=='string'||!/^[a-f0-9]{64}$/.test(row.rule_version)||typeof row.external_id!=='string'||!/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(row.external_id)||!definition.external_rule_ids?.includes(row.external_id)||seen.has(row.rule_version))return fail();
    if(definition.rule_id!=='SHADOW-SIGMA-'+row.external_id.replaceAll('-','').toUpperCase())return fail();
    const metadata=JSON.parse(definition.external_metadata_json??'null') as Record<string,unknown>|null;
    if(!metadata||metadata.id!==row.external_id||metadata.sigma_source_sha256!==item.source_sha256)return fail();
    seen.add(row.rule_version);
    return {definition,rule_version:row.rule_version,external_id:row.external_id};
  });
  return {contract:'cq-sigma-preview-v1',profile:'CQ_ENDPOINT_SHADOW_V1',status:'CONVERTED_SHADOW_ONLY',production_active:false,source_sha256:item.source_sha256,rules,warnings:item.warnings as string[]};
}
