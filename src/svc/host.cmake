# ============================================================
# CairnAgent.exe —— 服務宿主 + RPC handlers（由 src/svc/CMakeLists.txt include）
#   host/              ServiceHost（啟停時序、AnalysisThread、MaintenanceThread）、SCM 樣板、設定、持久狀態
#   host/handlers/     27 條 JSON-RPC 方法（可攜：只做參數解析 → 模組 API → UI 契約 JSON）
#   handlers 編入 EXE 而非 cairn_rpc：它們需要所有模組，放進庫會造成 core.* 橫向相依（SDD-01 L-2）。
# ============================================================

# config/policy.default.json 內嵌（policy.json 缺失或損毀時寫回，SDD-01 §2.6）
set(_policy_json ${PROJECT_SOURCE_DIR}/config/policy.default.json)
set(_policy_cpp  ${CMAKE_CURRENT_BINARY_DIR}/PolicyEmbedded.cpp)
add_custom_command(
    OUTPUT  ${_policy_cpp}
    COMMAND ${CMAKE_COMMAND} -DINPUT=${_policy_json} -DOUTPUT=${_policy_cpp}
            -DNAMESPACE=cairn::host -DFUNC=EmbeddedDefaultPolicy
            -P ${CMAKE_CURRENT_SOURCE_DIR}/host/EmbedText.cmake
    DEPENDS ${_policy_json} ${CMAKE_CURRENT_SOURCE_DIR}/host/EmbedText.cmake
    COMMENT "Embedding default policy.json")

# 可攜的 host 邏輯（設定解析、持久狀態、undo、JSON 轉換、handlers）另成靜態庫，供 cairn_tests_svc 連結測試
add_library(cairn_host STATIC
    host/PolicyConfig.cpp
    host/HostState.cpp
    host/UndoStore.cpp
    host/handlers/Convert.cpp
    host/handlers/AlertHandlers.cpp
    host/handlers/ResponseHandlers.cpp
    host/handlers/ConfigHandlers.cpp
    host/handlers/SystemHandlers.cpp)
target_include_directories(cairn_host PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(cairn_host PUBLIC
    cairn_core cairn_store cairn_response cairn_rpc cairn_svc_common nlohmann_json::nlohmann_json)

add_executable(CairnAgent
    host/main.cpp
    host/ServiceControl.cpp
    host/ServiceHost.cpp
    ${_policy_cpp})

target_link_libraries(CairnAgent PRIVATE
    cairn_host
    cairn_core
    cairn_telemetry
    cairn_store
    cairn_response
    cairn_llm
    cairn_rpc
    cairn_svc_common
    wevtapi.lib bcrypt.lib crypt32.lib ole32.lib oleaut32.lib winhttp.lib
    advapi32.lib psapi.lib shell32.lib)

# 服務與 --console 共用同一個 EXE：CONSOLE 子系統（服務模式下 SCM 不配主控台，不影響）
if(MSVC)
    target_link_options(CairnAgent PRIVATE /SUBSYSTEM:CONSOLE)
endif()

set_target_properties(CairnAgent PROPERTIES OUTPUT_NAME "CairnAgent")

# 規則與組態複製到 EXE 旁（開發期 ServiceHost 會在 %ProgramData%\Cairn\rules 不存在時從此處讀）
add_custom_command(TARGET CairnAgent POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${PROJECT_SOURCE_DIR}/rules $<TARGET_FILE_DIR:CairnAgent>/rules
    COMMAND ${CMAKE_COMMAND} -E copy_if_different ${PROJECT_SOURCE_DIR}/config/policy.default.json
            $<TARGET_FILE_DIR:CairnAgent>/policy.default.json
    COMMENT "Copying rules/ and policy.default.json next to CairnAgent.exe")
