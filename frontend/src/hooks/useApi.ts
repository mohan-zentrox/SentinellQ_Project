/**
 * Small data-fetching hooks.
 *
 * Deliberately hand-rolled rather than adding react-query: the whole app needs
 * load/error/refetch and nothing more (no cache invalidation graph, no optimistic
 * mutations), and the existing dependency list is kept short on purpose.
 *
 * The `AbortController` is the part that matters. Without it, navigating away
 * mid-request lands a `setState` on an unmounted component and -- worse -- a
 * slow first request can resolve after a fast second one and overwrite fresher
 * data with staler data.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError } from "../api/client";

export interface AsyncState<T> {
  data: T | null;
  isLoading: boolean;
  error: string | null;
  reload: () => void;
}

function messageFor(error: unknown): string {
  if (error instanceof ApiError) return error.message;
  if (error instanceof Error) return error.message;
  return "Request failed";
}

/**
 * Run `fetcher` on mount and whenever `deps` change.
 *
 * `fetcher` must be stable or built from `deps`; it is intentionally not part of
 * the dependency array, because an inline arrow would otherwise refetch on every
 * render.
 */
export function useApiData<T>(fetcher: () => Promise<T>, deps: unknown[] = []): AsyncState<T> {
  const [data, setData] = useState<T | null>(null);
  const [isLoading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [nonce, setNonce] = useState(0);
  const latestRequest = useRef(0);

  const reload = useCallback(() => setNonce((value) => value + 1), []);

  useEffect(() => {
    const requestId = ++latestRequest.current;
    let active = true;
    setLoading(true);
    setError(null);

    fetcher()
      .then((result) => {
        // Ignore a response that has been superseded by a newer request.
        if (active && requestId === latestRequest.current) {
          setData(result);
        }
      })
      .catch((err) => {
        if (active && requestId === latestRequest.current) {
          setError(messageFor(err));
        }
      })
      .finally(() => {
        if (active && requestId === latestRequest.current) {
          setLoading(false);
        }
      });

    return () => {
      active = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, nonce]);

  return { data, isLoading, error, reload };
}

/** Wraps a mutating call with pending/error state and a success message. */
export function useMutation<TArgs extends unknown[], TResult>(
  action: (...args: TArgs) => Promise<TResult>,
) {
  const [isPending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  const run = useCallback(
    async (...args: TArgs): Promise<TResult | undefined> => {
      setPending(true);
      setError(null);
      setMessage(null);
      try {
        return await action(...args);
      } catch (err) {
        setError(messageFor(err));
        return undefined;
      } finally {
        setPending(false);
      }
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [],
  );

  return { run, isPending, error, setError, message, setMessage };
}

/** Debounce a value, so a filter input does not issue a request per keystroke. */
export function useDebounced<T>(value: T, delayMs = 300): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delayMs);
    return () => clearTimeout(timer);
  }, [value, delayMs]);
  return debounced;
}
