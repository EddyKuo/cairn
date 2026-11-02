# ============================================================
# src/svc/response —— cairn_response（W3-1 ~ W3-5）
#   T6 ResponseExecutor + 四個 C-9 動作 + ConfirmationTokenStore + 動作紀錄
#   可攜檔案（無 Win32）：Sha256 / ResponseJson / ConfirmationTokenStore /
#                       ActionRecordStore / FirewallNaming / ResponseTargets
#   Win32 檔案：ProcessResponder / QuarantineStore / FirewallResponder / ResponseExecutor
#   ntdll 的 NtSuspendProcess / NtResumeProcess 以 GetProcAddress 動態取得，不需連結 ntdll.lib
# ============================================================
add_library(cairn_response STATIC
    Sha256.cpp
    ResponseJson.cpp
    ResponseTargets.cpp
    ConfirmationTokenStore.cpp
    ActionRecordStore.cpp
    FirewallNaming.cpp
    ProcessResponder.cpp
    QuarantineStore.cpp
    FirewallResponder.cpp
    ResponseExecutor.cpp)

target_include_directories(cairn_response PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)
target_link_libraries(cairn_response
    PUBLIC  cairn_svc_common
    PRIVATE bcrypt.lib crypt32.lib advapi32.lib ole32.lib oleaut32.lib)
