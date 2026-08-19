# 文件工具

> 版本：v0.1 · 2026-08-19

## check-mermaid.mjs — 驗證 SDD 內的 UML 圖

文件集的 32 張 UML（目前全部在 `docs/sdd/`） 全部以 Mermaid 撰寫。改圖後跑這支，避免推上去才發現 render 失敗。

```bash
cd tools
npm i          # 首次執行需安裝（jsdom + mermaid，約 166MB，僅開發用）
npm run check:uml
```

輸出 `mermaid: ok=32 fail=0` 即全數通過；失敗會印出檔名、行號與語法錯誤位置。
