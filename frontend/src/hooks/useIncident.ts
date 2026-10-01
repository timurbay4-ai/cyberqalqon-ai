/**
 * useIncident — fetches a single incident by ID.
 */

import { useState, useEffect, useCallback } from 'react';
import { api, ApiRequestError, NetworkError } from '@/api/client';
import type { IncidentResponse } from '@/types';

export type IncidentFetchState =
  | { status: 'idle' }
  | { status: 'loading' }
  | { status: 'success'; data: IncidentResponse }
  | { status: 'error'; message: string; isNetwork: boolean; isNotFound: boolean };

export function useIncident(id: string | undefined) {
  const [state, setState] = useState<IncidentFetchState>({ status: 'idle' });

  const fetch = useCallback(() => {
    if (!id) return;
    setState({ status: 'loading' });

    api
      .getIncident(id)
      .then((data) => setState({ status: 'success', data }))
      .catch((err: unknown) => {
        if (err instanceof NetworkError) {
          setState({ status: 'error', message: err.message, isNetwork: true, isNotFound: false });
        } else if (err instanceof ApiRequestError) {
          setState({
            status: 'error',
            message: err.message,
            isNetwork: false,
            isNotFound: err.status === 404,
          });
        } else {
          setState({
            status: 'error',
            message: 'An unexpected error occurred.',
            isNetwork: false,
            isNotFound: false,
          });
        }
      });
  }, [id]);

  useEffect(() => {
    fetch();
  }, [fetch]);

  return { state, refetch: fetch };
}
