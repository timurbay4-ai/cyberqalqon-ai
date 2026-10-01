/**
 * useStats — fetches pre-computed incident statistics from the backend.
 *
 * Uses GET /api/v1/incidents/stats which returns database-computed totals
 * (not limited to current page). Falls back gracefully when backend is offline.
 */

import { useState, useEffect, useCallback } from 'react';
import { api, NetworkError } from '@/api/client';
import type { IncidentStatsResponse } from '@/types';

type StatsState =
  | { status: 'idle' }
  | { status: 'loading' }
  | { status: 'success'; data: IncidentStatsResponse }
  | { status: 'error'; message: string; isNetwork: boolean };

export function useStats() {
  const [state, setState] = useState<StatsState>({ status: 'idle' });

  const fetch = useCallback(() => {
    setState({ status: 'loading' });
    api
      .getStats()
      .then((data) => setState({ status: 'success', data }))
      .catch((err: unknown) => {
        const isNetwork = err instanceof NetworkError;
        setState({
          status: 'error',
          message:
            err instanceof Error ? err.message : 'Failed to load statistics.',
          isNetwork,
        });
      });
  }, []);

  useEffect(() => {
    fetch();
  }, [fetch]);

  return { state, refetch: fetch };
}
