// AttackTag（元件 #9）：ATT&CK 技術膠囊。
// 氣隙可用是核心賣點（part3 §3.5.2 / U-09）：一律先顯示內建描述彈窗，官網連結為次要動作，
// 且交由宿主以預設瀏覽器開啟——WebView2 內不做任何外部導覽，不可出現斷開的連結。
import { useEffect, useRef, useState } from 'react';
import { openExternal } from '../lib/host';

// 精簡內建 ATT&CK 描述（規則包涵蓋的技術）。敘事回應帶 attack_mapping 時以其為準。
const BUILTIN: Record<string, { name: string; desc: string }> = {
  T1003: { name: '憑證傾印', desc: '從作業系統取得帳號登入資訊與憑證。' },
  'T1003.001': { name: '憑證傾印：LSASS 記憶體', desc: '讀取 LSASS 程序記憶體以取得憑證。' },
  T1053: { name: '排程工作', desc: '濫用工作排程器執行或持續駐留惡意程式碼。' },
  'T1053.005': { name: '排程工作：Scheduled Task', desc: '透過 schtasks 等建立排程工作。' },
  T1055: { name: '程序注入', desc: '將程式碼注入其他程序以規避防禦或提升權限。' },
  'T1055.001': { name: '程序注入：DLL 注入', desc: '將 DLL 注入其他程序的位址空間後執行。' },
  'T1055.002': { name: '程序注入：PE 注入', desc: '將可攜式執行檔寫入其他程序後執行。' },
  T1059: { name: '命令與腳本直譯器', desc: '濫用命令列或腳本直譯器執行命令。' },
  'T1059.001': { name: '命令與腳本直譯器：PowerShell', desc: '利用 PowerShell 執行命令、腳本或負載。' },
  'T1059.003': { name: '命令與腳本直譯器：Windows Command Shell', desc: '利用 cmd.exe 執行命令。' },
  'T1059.005': { name: '命令與腳本直譯器：Visual Basic', desc: '利用 VBScript / VBA 執行程式碼。' },
  T1071: { name: '應用層協定', desc: '以一般應用層協定進行命令與控制通訊以混入正常流量。' },
  'T1071.001': { name: '應用層協定：Web', desc: '以 HTTP/HTTPS 進行命令與控制通訊。' },
  T1105: { name: '工具傳入', desc: '從外部將工具或檔案傳入受害環境。' },
  T1112: { name: '修改登錄檔', desc: '修改登錄檔以隱藏設定、持續駐留或規避防禦。' },
  T1218: { name: '系統二進位代理執行', desc: '利用受信任的已簽章系統程式代理執行惡意內容。' },
  'T1218.005': { name: '系統二進位代理執行：Mshta', desc: '利用 mshta.exe 執行 HTA 或腳本。' },
  'T1218.010': { name: '系統二進位代理執行：Regsvr32', desc: '利用 regsvr32.exe 載入並執行程式碼。' },
  'T1218.011': { name: '系統二進位代理執行：Rundll32', desc: '利用 rundll32.exe 執行 DLL 匯出函式。' },
  T1486: { name: '加密資料以造成衝擊', desc: '加密目標系統上的資料以中斷可用性（勒索軟體）。' },
  T1490: { name: '抑制系統復原', desc: '刪除影子複本、停用復原功能以阻礙還原。' },
  T1547: { name: '開機或登入自動啟動', desc: '設定開機或登入時自動執行以持續駐留。' },
  'T1547.001': { name: '自動啟動：Run 機碼 / 啟動資料夾', desc: '寫入 Run 機碼或啟動資料夾以持續駐留。' },
  T1562: { name: '削弱防禦', desc: '停用或修改安全工具以規避偵測。' },
  'T1562.001': { name: '削弱防禦：停用或修改工具', desc: '停用防毒、EDR 或其記錄功能。' },
  T1566: { name: '網路釣魚', desc: '以釣魚訊息取得初始存取。' },
  'T1566.001': { name: '網路釣魚：夾帶附件', desc: '以夾帶惡意附件的郵件取得初始存取。' },
  T1036: { name: '偽裝', desc: '以合法名稱或位置偽裝惡意程式。' },
  T1027: { name: '混淆檔案或資訊', desc: '以編碼、加密等方式混淆內容以規避分析。' },
  T1070: { name: '移除跡證', desc: '刪除或修改記錄以掩蓋入侵痕跡。' },
  'T1070.001': { name: '移除跡證：清除事件記錄', desc: '清除 Windows 事件記錄。' },
};

export function attackUrl(id: string): string {
  const [base, sub] = id.split('.');
  return `https://attack.mitre.org/techniques/${base}/${sub ? `${sub}/` : ''}`;
}

export function AttackTag({
  techniqueId,
  name,
  offlineDescription,
  showName = false,
}: {
  techniqueId: string;
  name?: string;
  offlineDescription?: string;
  showName?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLSpanElement>(null);
  const builtin = BUILTIN[techniqueId] ?? BUILTIN[techniqueId.split('.')[0]];
  const label = name ?? builtin?.name ?? '';
  const desc = offlineDescription ?? builtin?.desc ?? '此技術的內建描述不在精簡資料集中。';

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (!ref.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', onDoc);
    return () => document.removeEventListener('mousedown', onDoc);
  }, [open]);

  return (
    <span ref={ref} style={{ position: 'relative', display: 'inline-flex', alignItems: 'center', gap: 6 }}>
      <button className="pill" onClick={() => setOpen((o) => !o)} aria-expanded={open} title={label}>
        {techniqueId} ↗
      </button>
      {showName && label && <span className="sm">{label}</span>}
      {open && (
        <span className="popover" role="dialog" style={{ top: 24, left: 0 }}>
          <div className="mono" style={{ fontWeight: 600 }}>
            {techniqueId}
          </div>
          {label && <div style={{ fontWeight: 500, margin: '4px 0' }}>{label}</div>}
          <div className="secondary">{desc}</div>
          <div className="row" style={{ marginTop: 8 }}>
            <button className="btn sm" onClick={() => openExternal(attackUrl(techniqueId))}>
              以瀏覽器開啟 MITRE 官網
            </button>
          </div>
        </span>
      )}
    </span>
  );
}
