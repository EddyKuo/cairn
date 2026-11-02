# ============================================================
# src/svc —— CairnAgent.exe：所有 Win32 相依集中於此（part4 §4.2）
#   每個子目錄各自 add_library STATIC（對齊 CONVENTIONS C-2.2 的 8 庫）：
#     telemetry/ → cairn_telemetry     store/    → cairn_store
#     response/  → cairn_response      llm/      → cairn_llm
#     rpc/       → cairn_rpc
#   common/WinUtil.h 為 header-only 的共用小工具（UTF 轉換、資料目錄、Win32 錯誤）。
# ============================================================

add_library(cairn_svc_common INTERFACE)
target_include_directories(cairn_svc_common INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(cairn_svc_common INTERFACE
    cairn_common WIL::WIL spdlog::spdlog nlohmann_json::nlohmann_json
    shell32.lib ole32.lib)

add_subdirectory(telemetry)
add_subdirectory(store)
add_subdirectory(response)
add_subdirectory(llm)
add_subdirectory(rpc)

# cairn_core = cairn_common + cairn_rules + cairn_store（CONVENTIONS C-2.2）
target_link_libraries(cairn_core INTERFACE cairn_store)

# ---- CairnAgent.exe（由 svc host 整合層定義，見 host.cmake）----
include(${CMAKE_CURRENT_SOURCE_DIR}/host.cmake OPTIONAL)
