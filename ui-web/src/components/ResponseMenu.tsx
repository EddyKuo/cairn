// 回應動作下拉選單 + prepare → 二次確認 → execute 流程（part3 §3.3.3、§3.8.4；SDD-03 §8.3）。
// 錯誤處理（SDD-03 §9.3.4）：
//   409 IMPACT_CHANGED → 自動重新 prepare 並提示樹已變化
//   410 TOKEN_EXPIRED  → 重新 prepare
//   400 TYPED_CONFIRMATION_MISMATCH → 欄位提示
//   207 部分成功 → 琥珀 Toast；502 ACTION_FAILED → 紅色 Toast（不自動消失）
//   503 → 非冪等方法一律不自動重試，提示查閱稽核頁
import { useEffect, useRef, useState } from 'react';
import { api, ApiError, errorMessage, isNonIdempotentError } from '../lib/api';
import { ACTION_ICON, ACTION_LABEL, basename } from '../lib/format';
import type { ActionName, AlertDetail, ExecuteRequest, PrepareRequest, PrepareResponse } from '../lib/types';
import { ConfirmDialog } from './ConfirmDialog';
import { useToast } from './Toast';

interface Option {
  action: ActionName;
  label: string;
  level: 'L1' | 'L2' | 'L3';
  req: PrepareRequest;
  disabled?: string;
  done?: boolean;
}

function buildOptions(a: AlertDetail): Option[] {
  const byGuid = new Map(a.process_tree.map((p) => [p.process_guid, p]));
  const focus = byGuid.get(a.focus_process_guid);
  // 終止程序樹的根：焦點程序往上最高的「非既有」祖先（不殺 explorer.exe 這類既有殼層）
  let treeRoot = focus;
  while (treeRoot?.parent_guid) {
    const p = byGuid.get(treeRoot.parent_guid);
    if (!p || p.preexisting) break;
    treeRoot = p;
  }
  const subtreeCount = (() => {
    if (!treeRoot) return 0;
    let n = 0;
    const stack = [treeRoot.process_guid];
    while (stack.length) {
      const g = stack.pop()!;
      n++;
      for (const c of a.process_tree) if (c.parent_guid === g) stack.push(c.process_guid);
    }
    return n;
  })();
  const done = (act: ActionName, target?: string) =>
    a.actions_taken.some((x) => x.action === act && !x.reverted && x.result !== 'failed' && (!target || x.target.includes(target)));

  const opts: Option[] = [];
  if (focus) {
    const alive = focus.state === 'running';
    opts.push({
      action: 'suspend_process',
      label: `${ACTION_ICON.suspend_process} 暫停程序 ${focus.name} (${focus.pid})`,
      level: 'L1',
      req: { action: 'suspend_process', target_guid: focus.process_guid },
      disabled: alive ? undefined : focus.state === 'suspended' ? '已暫停' : '程序已結束',
    });
  }
  if (treeRoot) {
    opts.push({
      action: 'terminate_process_tree',
      label: `${ACTION_ICON.terminate_process_tree} 終止程序樹（${treeRoot.name} 起 ${subtreeCount} 個程序）`,
      level: 'L3',
      req: { action: 'terminate_process_tree', target_guid: treeRoot.process_guid },
      disabled: a.process_tree.some((p) => p.state === 'running' || p.state === 'suspended') ? undefined : '程序皆已結束',
    });
  }
  const files = a.available_targets?.files?.length
    ? a.available_targets.files
    : focus?.image_path
      ? [{ path: focus.image_path }]
      : [];
  for (const f of files.slice(0, 3)) {
    opts.push({
      action: 'quarantine_file',
      label: `${ACTION_ICON.quarantine_file} 隔離檔案 ${basename(f.path)}`,
      level: 'L2',
      req: { action: 'quarantine_file', target_path: f.path },
      done: done('quarantine_file', f.path),
    });
  }
  const ips =
    a.available_targets?.ips ??
    Array.from(
      new Map(a.timeline.filter((e) => e.remote_addr).map((e) => [e.remote_addr!, { ip: e.remote_addr!, port: e.remote_port }])).values(),
    );
  for (const ip of ips.slice(0, 3)) {
    opts.push({
      action: 'firewall_block',
      label: `${ACTION_ICON.firewall_block} 封鎖 IP ${ip.ip}`,
      level: 'L2',
      req: { action: 'firewall_block', target_ip: ip.ip },
      done: done('firewall_block', ip.ip),
    });
  }
  return opts;
}

export function ResponseMenu({ alert, onChanged, onShowActions }: { alert: AlertDetail; onChanged: () => void; onShowActions: () => void }) {
  const toast = useToast();
  const [open, setOpen] = useState(false);
  const [prep, setPrep] = useState<{ opt: Option; res: PrepareResponse } | null>(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [fieldError, setFieldError] = useState<string | null>(null);
  const ref = useRef<HTMLSpanElement>(null);
  const options = buildOptions(alert);

  useEffect(() => {
    if (!open) return;
    const h = (e: MouseEvent) => !ref.current?.contains(e.target as Node) && setOpen(false);
    document.addEventListener('mousedown', h);
    return () => document.removeEventListener('mousedown', h);
  }, [open]);

  const doPrepare = async (opt: Option, why?: string) => {
    try {
      const res = await api.prepareAction(alert.alert_id, opt.req);
      setNotice(why ?? null);
      setFieldError(null);
      setPrep({ opt, res });
    } catch (e) {
      setPrep(null);
      toast({ type: 'error', message: `無法取得影響清單：${errorMessage(e)}` });
    }
  };

  const reportResult = (status: number, data: { overall_result: string; results: { result: string; name?: string; pid?: number; target?: string; error_message?: string; error_code?: string }[]; undo_token?: string | null; audit_entry_id: string | number }, opt: Option) => {
    const okN = data.results.filter((r) => r.result === 'success').length;
    const failed = data.results.filter((r) => r.result !== 'success');
    if (status === 207 || data.overall_result === 'partial_success') {
      toast({
        type: 'warning',
        message: (
          <>
            ⚠ {ACTION_LABEL[opt.action]}：{okN} 個成功，{failed.length} 個失敗
            {failed.map((f, i) => (
              <div key={i} className="xs">
                {f.name ?? f.target} {f.pid ? `(${f.pid})` : ''} 失敗 — {f.error_message} {f.error_code ? `(${f.error_code})` : ''}
              </div>
            ))}
          </>
        ),
        duration: 0,
      });
    } else if (data.overall_result === 'failed') {
      toast({ type: 'error', message: `⚠ ${ACTION_LABEL[opt.action]}失敗：${failed[0]?.error_message ?? '未知錯誤'}` });
    } else {
      const undo = data.undo_token;
      toast({
        type: 'success',
        message: `✓ 已${ACTION_LABEL[opt.action]}${okN > 1 ? ` ${okN} 個目標` : ''}`,
        // L1 可逆動作附 [復原]；不可逆動作無復原鍵
        undoAction:
          opt.level === 'L1' && undo
            ? async () => {
                try {
                  await api.undo(undo);
                  toast({ type: 'success', message: '已復原。' });
                } catch (e) {
                  toast({ type: 'error', message: `復原失敗：${errorMessage(e)}` });
                }
                onChanged();
              }
            : undefined,
      });
    }
    onChanged();
  };

  const execute = async (opt: Option, body: ExecuteRequest) => {
    setBusy(true);
    try {
      const r = await api.executeAction(alert.alert_id, body);
      setPrep(null);
      reportResult(r.status, r.data, opt);
    } catch (e) {
      if (e instanceof ApiError) {
        if (e.code === 'IMPACT_CHANGED') {
          await doPrepare(opt, '程序樹在確認期間已變化，已重新取得影響清單，請再次確認。');
        } else if (e.code === 'TOKEN_EXPIRED' || e.code === 'TOKEN_INVALID') {
          await doPrepare(opt, '確認已逾時，已重新取得影響清單，請再次確認。');
        } else if (e.code === 'TYPED_CONFIRMATION_MISMATCH') {
          setFieldError('輸入的程序名稱與根程序不符。');
        } else if (isNonIdempotentError(e)) {
          setPrep(null);
          toast({
            type: 'error',
            message: '與服務的連線中斷，無法確認動作是否已執行。請勿重複送出，恢復連線後請至稽核記錄確認結果。',
            detailAction: { label: '已執行動作', onClick: onShowActions },
          });
        } else if (e.status === 502) {
          setPrep(null);
          toast({ type: 'error', message: `⚠ ${ACTION_LABEL[opt.action]}失敗：${e.message}` });
          onChanged();
        } else {
          setPrep(null);
          toast({ type: 'error', message: `${ACTION_LABEL[opt.action]}失敗：${errorMessage(e)}` });
        }
      } else {
        setPrep(null);
        toast({ type: 'error', message: errorMessage(e) });
      }
    } finally {
      setBusy(false);
    }
  };

  const choose = async (opt: Option) => {
    setOpen(false);
    if (opt.level === 'L1') {
      // L1：直接執行 + Toast [復原]（免 token）
      await execute(opt, { ...opt.req, action: opt.action, reason: '分析師手動暫停' });
      return;
    }
    await doPrepare(opt);
  };

  return (
    <span ref={ref} style={{ position: 'relative' }}>
      <button className="btn" onClick={() => setOpen((o) => !o)} aria-haspopup="menu" aria-expanded={open}>
        ⚡ 回應動作 ▾
      </button>
      {open && (
        <div className="menu" role="menu" style={{ top: 34, left: 0 }}>
          {options.length === 0 && <div className="sm muted" style={{ padding: 8 }}>此告警沒有可執行的回應目標。</div>}
          {options.map((o, i) => (
            <button key={i} role="menuitem" disabled={!!o.disabled || o.done} onClick={() => choose(o)} title={o.disabled}>
              <span className="grow">{o.label}</span>
              <span className={`xs mono ${o.level === 'L3' ? 'fg-critical' : 'muted'}`}>{o.level}</span>
              {o.disabled && <span className="xs muted">{o.disabled}</span>}
              {o.done && <span className="xs fg-success">✓已執行</span>}
            </button>
          ))}
          <hr style={{ border: 'none', borderTop: '1px solid var(--border-default)', margin: '4px 0' }} />
          <button
            role="menuitem"
            onClick={() => {
              setOpen(false);
              onShowActions();
            }}
          >
            ↩ 還原已執行的動作…
          </button>
        </div>
      )}
      {prep && (
        <ConfirmDialog
          prep={prep.res}
          busy={busy}
          notice={notice}
          fieldError={fieldError}
          onCancel={() => setPrep(null)}
          onExpired={() => void doPrepare(prep.opt, '確認 token 已逾時，已重新取得影響清單。')}
          onConfirm={(typed, reason) =>
            execute(prep.opt, {
              ...prep.opt.req,
              action: prep.opt.action,
              confirmation_token: prep.res.confirmation_token,
              typed_confirmation: prep.res.require_typed_confirmation ? typed : undefined,
              reason,
            })
          }
        />
      )}
    </span>
  );
}
