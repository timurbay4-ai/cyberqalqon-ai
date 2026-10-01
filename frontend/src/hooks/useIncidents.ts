/**
 * useIncidents — fetches paginated incident list from the backend.
 *
 * Returns loading/error/data states.
 * Never silently falls back to mock data on error.
 */

import { useState, useEffect, useCallback } from 'react';
import { api, ApiRequestError, NetworkError } from '@/api/client';
import type { IncidentListResponse, IncidentListParams } from '@/types';

export type FetchState =
  | { status: 'idle' }
  | { status: 'loading' }
  | { status: 'success'; data: IncidentListResponse }
  | { status: 'error'; message: string; isNetwork: boolean };

export function useIncidents(params: IncidentListParams = {}) {
  const [state, setState] = useState<FetchState>({ status: 'idle' });

  const fetch = useCallback(() => {
    setState({ status: 'loading' });

    api
      .listIncidents(params)
      .then((data) => setState({ status: 'success', data }))
      .catch((err: unknown) => {
        if (err instanceof NetworkError) {
          setState({ status: 'error', message: err.message, isNetwork: true });
        } else if (err instanceof ApiRequestError) {
          setState({
            status: 'error',
            message: `${err.message} (${err.code})`,
            isNetwork: false,
          });
        } else {
          setState({
            status: 'error',
            message: 'An unexpected error occurred.',
            isNetwork: false,
          });
        }
      });
  }, [JSON.stringify(params)]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    fetch();
  }, [fetch]);

  return { state, refetch: fetch };
}
