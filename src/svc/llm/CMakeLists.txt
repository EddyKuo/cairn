# ============================================================
# src/svc/llm → cairn_llm
#   LlamaServerSupervisor：llama-server.exe 子程序（Job Object / 閒置卸載 / 退避）
#   WinHttpClient       ：loopback HTTP（分階段逾時 + 總時長看門狗 + 跨執行緒取消）
#   NarrativeEngine     ：INarrativeEngine / LlamaHttpEngine / NullNarrativeEngine
#   LlmWorker           ：T5 執行緒，有界佇列 32
# Prompt 隔離與輸出驗證（純邏輯）在 src/core/prompt（cairn_common），此處只做 Win32 與執行緒。
# ★ 架構紅線：本庫不得被 cairn_rules 連結；LLM 不參與計分與回應決策。
# ============================================================
add_library(cairn_llm STATIC
    WinHttpClient.cpp
    LlamaServerSupervisor.cpp
    NarrativeEngine.cpp
    LlmWorker.cpp)

target_link_libraries(cairn_llm
    PUBLIC  cairn_svc_common
    PRIVATE winhttp.lib bcrypt.lib advapi32.lib)
