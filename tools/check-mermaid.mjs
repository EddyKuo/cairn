// 驗證 Markdown 內所有 ```mermaid 區塊可被 mermaid 正確解析。
// 用法: node tools/check-mermaid.mjs docs/sdd/*.md
// 相依: npm i mermaid@11 jsdom
import { readFileSync } from 'fs';
import { JSDOM } from 'jsdom';

const dom = new JSDOM('<!doctype html><html><body></body></html>');
global.window = dom.window;
global.document = dom.window.document;
global.Element = dom.window.Element;
global.DOMParser = dom.window.DOMParser;
global.SVGElement = dom.window.SVGElement;
global.HTMLElement = dom.window.HTMLElement;
global.Node = dom.window.Node;

const mermaid = (await import('mermaid')).default;
mermaid.initialize({ startOnLoad: false, securityLevel: 'loose' });

const files = process.argv.slice(2);
if (!files.length) { console.error('用法: node tools/check-mermaid.mjs <markdown...>'); process.exit(2); }

let ok = 0, fail = 0;
for (const file of files) {
  const text = readFileSync(file, 'utf8');
  const blocks = [...text.matchAll(/```mermaid\n([\s\S]*?)\n```/g)];
  for (const [i, m] of blocks.entries()) {
    const line = text.slice(0, m.index).split('\n').length;
    try { await mermaid.parse(m[1]); ok++; }
    catch (e) {
      fail++;
      console.log(`FAIL ${file}:${line} (第 ${i + 1} 張)\n  ${String(e.message || e).split('\n').slice(0, 4).join('\n  ')}`);
    }
  }
}
console.log(`\nmermaid: ok=${ok} fail=${fail}`);
process.exit(fail ? 1 : 0);
