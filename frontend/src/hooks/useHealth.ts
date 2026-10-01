/**
 * useHealth — polls backend health/readiness endpoints.
 * Used by the Dashboard overview to show backend status.
 */

import { useState, useEffect, useRef } from 'react';
import { api, NetworkError } from '@/api/client';

export type BackendStatus = 'unknown' | 'online' | 'degraded' | 'offline';

export interface HealthState {
  status: BackendStatus;
  lastChecked: Date | null;
  checking: boolean;
}

const POLL_INTERVAL_MS = 30_000; // 30 seconds — reasonable for a SOC dashboard

export function useHealth() {
  const [health, setHealth] = useState<HealthState>({
    status: 'unknown',
    lastChecked: null,
    checking: false,
  });
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const check = () => {
    setHealth((prev) => ({ ...prev, checking: true }));

    Promise.allSettled([api.health(), api.ready()])
      .then(([healthResult, readyResult]) => {
        let status: BackendStatus;
        if (healthResult.status === 'rejected') {
          status =
            healthResult.reason instanceof NetworkError ? 'offline' : 'offline';
        } else if (readyResult.status === 'rejected') {
          // health ok but ready failed — DB not ready
          status = 'degraded';
        } else {
          status = 'online';
        }
        setHealth({ status, lastChecked: new Date(), checking: false });
      });
  };

  useEffect(() => {
    check();
    intervalRef.current = setInterval(check, POLL_INTERVAL_MS);
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  return { health, refresh: check };
}
