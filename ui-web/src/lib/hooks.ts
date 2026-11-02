import { useCallback, useEffect, useRef, useState, useSyncExternalStore } from 'react';
import { getLink, subscribeLink, type LinkSnapshot } from './api';

// 視窗可見性：隱藏時停止資料輪詢（SDD-03 §9.6 的暫停規則）。
export function useDocumentVisible(): boolean {
  return useSyncExternalStore(
    (cb) => {
      document.addEventListener('visibilitychange', cb);
      return () => document.removeEventListener('visibilitychange', cb);
    },
    () => document.visibilityState === 'visible',
  );
}

export function useLink(): LinkSnapshot {
  return useSyncExternalStore(subscribeLink, getLink);
}

export interface AsyncState<T> {
  data: T | undefined;
  error: unknown;
  loading: boolean; // 首次載入中（尚無資料）
  slow: boolean; // 首次載入超過 3 秒（part3 §3.7.2 ①）
  reload: () => void;
  setData: (updater: (prev: T | undefined) => T | undefined) => void;
}

// 取數 + 可選輪詢。輪詢在視窗不可見時暫停；失敗時保留既有資料（不清空，part3 §3.10.4）。
export function useAsync<T>(
  fetcher: (signal: AbortSignal) => Promise<T>,
  deps: unknown[],
  opts: { pollMs?: number; enabled?: boolean } = {},
): AsyncState<T> {
  const { pollMs, enabled = true } = opts;
  const [data, setDataState] = useState<T | undefined>(undefined);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [slow, setSlow] = useState(false);
  const [tick, setTick] = useState(0);
  const visible = useDocumentVisible();
  const fetcherRef = useRef(fetcher);
  fetcherRef.current = fetcher;
  const hasData = useRef(false);

  useEffect(() => {
    hasData.current = false;
    setDataState(undefined);
    setLoading(true);
    setError(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  useEffect(() => {
    if (!enabled) return;
    const ac = new AbortController();
    let slowTimer: number | undefined;
    if (!hasData.current) {
      slowTimer = window.setTimeout(() => setSlow(true), 3000);
    }
    fetcherRef
      .current(ac.signal)
      .then((d) => {
        hasData.current = true;
        setDataState(d);
        setError(null);
      })
      .catch((e: unknown) => {
        if ((e as Error)?.name === 'AbortError') return;
        setError(e);
      })
      .finally(() => {
        if (!ac.signal.aborted) {
          setLoading(false);
          setSlow(false);
        }
        if (slowTimer) window.clearTimeout(slowTimer);
      });
    return () => {
      ac.abort();
      if (slowTimer) window.clearTimeout(slowTimer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick, enabled]);

  useEffect(() => {
    if (!pollMs || !enabled || !visible) return;
    const h = window.setInterval(() => setTick((t) => t + 1), pollMs);
    return () => window.clearInterval(h);
  }, [pollMs, enabled, visible]);

  const reload = useCallback(() => setTick((t) => t + 1), []);
  const setData = useCallback((u: (prev: T | undefined) => T | undefined) => setDataState(u), []);
  return { data, error, loading: loading && data === undefined, slow, reload, setData };
}

export function useInterval(fn: () => void, ms: number | null) {
  const ref = useRef(fn);
  ref.current = fn;
  useEffect(() => {
    if (ms === null) return;
    const h = window.setInterval(() => ref.current(), ms);
    return () => window.clearInterval(h);
  }, [ms]);
}

// 全域鍵盤快捷鍵（輸入框中不觸發）。
export function useHotkeys(map: Record<string, (e: KeyboardEvent) => void>, active = true) {
  const ref = useRef(map);
  ref.current = map;
  useEffect(() => {
    if (!active) return;
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement | null;
      const tag = t?.tagName;
      const typing = tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || t?.isContentEditable;
      if (typing && e.key !== 'Escape') return;
      if (e.ctrlKey || e.metaKey || e.altKey) return;
      const h = ref.current[e.key];
      if (h) {
        h(e);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [active]);
}
