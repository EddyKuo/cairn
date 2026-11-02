// Toast（元件 #14）：右下、最多同時 3 則、成功類 4 秒自動消失、錯誤類需手動關閉（§3.7.2）。
// [復原] 只出現在可逆動作（誤報標記 10 秒內、L1 暫停程序）。
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';

export type ToastType = 'success' | 'info' | 'warning' | 'error';
export interface ToastSpec {
  type: ToastType;
  message: ReactNode;
  undoAction?: () => void | Promise<void>;
  undoLabel?: string;
  duration?: number; // ms；error 預設不自動消失
  detailAction?: { label: string; onClick: () => void };
}
interface ToastItem extends ToastSpec {
  id: number;
}

const Ctx = createContext<(t: ToastSpec) => void>(() => {});

export function useToast() {
  return useContext(Ctx);
}

let nextId = 1;

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);
  const dismiss = useCallback((id: number) => setItems((xs) => xs.filter((x) => x.id !== id)), []);
  const push = useCallback((t: ToastSpec) => {
    const item = { ...t, id: nextId++ };
    setItems((xs) => [...xs, item].slice(-3));
  }, []);
  const value = useMemo(() => push, [push]);
  return (
    <Ctx.Provider value={value}>
      {children}
      <div className="toasts" role="status" aria-live="polite">
        {items.map((t) => (
          <ToastView key={t.id} t={t} onDismiss={() => dismiss(t.id)} />
        ))}
      </div>
    </Ctx.Provider>
  );
}

function ToastView({ t, onDismiss }: { t: ToastItem; onDismiss: () => void }) {
  const duration = t.duration ?? (t.type === 'error' ? 0 : t.undoAction ? 10_000 : 4_000);
  useEffect(() => {
    if (!duration) return;
    const h = window.setTimeout(onDismiss, duration);
    return () => window.clearTimeout(h);
  }, [duration, onDismiss]);
  return (
    <div className={`toast ${t.type}`}>
      <div className="grow sm">{t.message}</div>
      {t.detailAction && (
        <button className="btn sm" onClick={t.detailAction.onClick}>
          {t.detailAction.label}
        </button>
      )}
      {t.undoAction && (
        <button
          className="btn sm"
          onClick={async () => {
            await t.undoAction?.();
            onDismiss();
          }}
        >
          {t.undoLabel ?? '復原'}
        </button>
      )}
      <button className="btn sm ghost" onClick={onDismiss} aria-label="關閉通知">
        ✕
      </button>
    </div>
  );
}
