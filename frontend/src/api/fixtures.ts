/**
 * Development-only fixture data.
 *
 * ⚠️  DEVELOPMENT FIXTURES — NOT PRODUCTION DATA ⚠️
 *
 * These records are used only when:
 *  - The backend is unavailable during UI development
 *  - Running isolated component tests
 *
 * They are clearly labeled "DEMO" in the UI to prevent confusion.
 * The production application never silently falls back to these.
 */

import type { IncidentResponse, IncidentListResponse } from '@/types';

export const FIXTURE_INCIDENT_1: IncidentResponse = {
  id: 'demo-inc-001',
  alert_id: 'wazuh-demo-001',
  event_timestamp: '2026-09-30T21:00:00+05:00',
  created_at: '2026-09-30T21:00:05+05:00',
  updated_at: '2026-09-30T21:00:05+05:00',
  agent_id: '001',
  agent_name: 'WIN-PC-01',
  agent_ip: '192.0.2.10',
  rule_id: '5710',
  rule_level: 10,
  rule_description: 'Multiple authentication failures',
  rule_metadata: { id: '5710', level: 10, description: 'Multiple authentication failures' },
  mitre_ids: ['T1110'],
  mitre_tactics: ['Credential Access'],
  mitre_techniques: ['Brute Force'],
  source_ip: '192.168.1.25',
  destination_ip: null,
  user: 'demo-user',
  source_user: 'demo-user',
  destination_user: null,
  location: 'auth.log',
  decoder: { name: 'sshd' },
  full_log: 'Sep 30 21:00:00 WIN-PC-01 sshd: Failed password for demo-user from 192.168.1.25 port 55234',
  raw_event: {
    id: 'wazuh-demo-001',
    timestamp: '2026-09-30T21:00:00+05:00',
    agent: { id: '001', name: 'WIN-PC-01', ip: '192.0.2.10' },
    rule: { id: '5710', level: 10, description: 'Multiple authentication failures', mitre: { id: ['T1110'], tactic: ['Credential Access'], technique: ['Brute Force'] } },
    data: { srcip: '192.168.1.25', srcuser: 'demo-user' },
    location: 'auth.log',
    decoder: { name: 'sshd' },
    full_log: 'Sep 30 21:00:00 WIN-PC-01 sshd: Failed password for demo-user from 192.168.1.25 port 55234',
  },
  severity: 'high',
  priority_score: 67,
  repetition_count: 8,
  asset_importance: 'normal',
  ai_status: 'not_configured',
  review_status: 'needs_review',
  reviews: [],
};

export const FIXTURE_INCIDENT_2: IncidentResponse = {
  id: 'demo-inc-002',
  alert_id: 'wazuh-demo-002',
  event_timestamp: '2026-09-30T19:30:00+05:00',
  created_at: '2026-09-30T19:30:05+05:00',
  updated_at: '2026-09-30T20:45:00+05:00',
  agent_id: '002',
  agent_name: 'SRV-DC-01',
  agent_ip: '192.0.2.20',
  rule_id: '92200',
  rule_level: 14,
  rule_description: 'Encoded PowerShell command execution detected',
  rule_metadata: { id: '92200', level: 14, description: 'Encoded PowerShell command execution detected' },
  mitre_ids: ['T1059.001', 'T1086'],
  mitre_tactics: ['Execution'],
  mitre_techniques: ['PowerShell', 'Command and Scripting Interpreter'],
  source_ip: null,
  destination_ip: null,
  user: 'SYSTEM',
  source_user: 'SYSTEM',
  destination_user: null,
  location: 'WinEvtLog:Security',
  decoder: { name: 'windows_eventlog' },
  full_log: 'EventID=4688 CommandLine=powershell.exe -EncodedCommand dABlAHMAdAA=',
  raw_event: {
    id: 'wazuh-demo-002',
    timestamp: '2026-09-30T19:30:00+05:00',
    agent: { id: '002', name: 'SRV-DC-01', ip: '192.0.2.20' },
    rule: { id: '92200', level: 14, description: 'Encoded PowerShell command execution detected', mitre: { id: ['T1059.001', 'T1086'], tactic: ['Execution'], technique: ['PowerShell'] } },
    data: { srcuser: 'SYSTEM' },
    location: 'WinEvtLog:Security',
  },
  severity: 'critical',
  priority_score: 95,
  repetition_count: 1,
  asset_importance: 'high',
  ai_status: 'not_configured',
  review_status: 'needs_review',
  reviews: [],
};

export const FIXTURE_INCIDENT_3: IncidentResponse = {
  id: 'demo-inc-003',
  alert_id: 'wazuh-demo-004',
  event_timestamp: '2026-09-29T14:10:00+05:00',
  created_at: '2026-09-29T14:10:05+05:00',
  updated_at: '2026-09-29T17:00:00+05:00',
  agent_id: '003',
  agent_name: 'DEV-LAPTOP-03',
  agent_ip: '192.0.2.30',
  rule_id: '31530',
  rule_level: 7,
  rule_description: 'Unusual outbound HTTPS connection to unknown endpoint',
  rule_metadata: { id: '31530', level: 7, description: 'Unusual outbound HTTPS connection' },
  mitre_ids: ['T1071.001'],
  mitre_tactics: ['Command and Control'],
  mitre_techniques: ['Web Protocols'],
  source_ip: '192.0.2.30',
  destination_ip: '203.0.113.99',
  user: null,
  source_user: null,
  destination_user: null,
  location: 'network.log',
  decoder: null,
  full_log: null,
  raw_event: {
    id: 'wazuh-demo-004',
    agent: { id: '003', name: 'DEV-LAPTOP-03' },
    rule: { id: '31530', level: 7, description: 'Unusual outbound HTTPS connection' },
    data: { srcip: '192.0.2.30', dstip: '203.0.113.99' },
  },
  severity: 'medium',
  priority_score: 33,
  repetition_count: 1,
  asset_importance: 'normal',
  ai_status: 'not_configured',
  review_status: 'needs_review',
  reviews: [
    {
      id: 'rev-001',
      status: 'confirmed',
      analyst: 'analyst-2',
      note: 'Verified benign — developer testing external API.',
      created_at: '2026-09-29T17:00:00+05:00',
    },
  ],
};

export const FIXTURE_INCIDENT_LIST: IncidentListResponse = {
  total: 3,
  limit: 50,
  offset: 0,
  items: [FIXTURE_INCIDENT_2, FIXTURE_INCIDENT_1, FIXTURE_INCIDENT_3],
};
