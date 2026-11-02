# ============================================================
# src/ui —— CairnConsole.exe：MFC 宿主 + WebView2，零偵測邏輯（part4 §4.2、SDD-03 §9）
#   - 動態連結 MFC（CMAKE_MFC_FLAG 2，part0 §0.3；不用 /MT 以免 MFC/CRT 堆積不一致）
#   - ui-web/dist 於建置時掃描並產生 RCDATA（不用 SetVirtualHostNameToFolderMapping，part4 §4.2）
#   - 只依賴 cairn_common；不得連結任何 svc 函式庫（ui.host 不得有偵測邏輯）
# ============================================================

set(CMAKE_MFC_FLAG 2)

set(CAIRN_UI_WEB_DIST "${PROJECT_SOURCE_DIR}/ui-web/dist" CACHE PATH "ui-web 建置產物目錄")
set(CAIRN_UI_GEN_DIR  "${CMAKE_CURRENT_BINARY_DIR}/generated")

# 每次建置都重新掃描 dist（檔名含內容雜湊，無法於 configure 期得知）。
# 腳本只在內容變更時改寫輸出檔，避免無謂的重新連結。
add_custom_target(cairn_ui_assets
    COMMAND ${CMAKE_COMMAND}
            -DDIST_DIR=${CAIRN_UI_WEB_DIST}
            -DOUT_DIR=${CAIRN_UI_GEN_DIR}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/EmbedAssets.cmake
    BYPRODUCTS ${CAIRN_UI_GEN_DIR}/assets.rc ${CAIRN_UI_GEN_DIR}/assets_table.inc
    COMMENT "嵌入 ui-web/dist 至 CairnConsole.exe RCDATA"
    VERBATIM)

set(CAIRN_UI_SOURCES
    pch.h
    Utf.h
    CairnConsole.h      CairnConsole.cpp
    MainFrame.h         MainFrame.cpp
    WebViewHost.h       WebViewHost.cpp
    ResourceInterceptor.h ResourceInterceptor.cpp
    RpcClient.h         RpcClient.cpp
    EmbeddedAssets.h    EmbeddedAssets.cpp
    DevHttp.cpp
    resource.h
    CairnConsole.rc
    CairnConsole.manifest)

add_executable(CairnConsole WIN32 ${CAIRN_UI_SOURCES})
add_dependencies(CairnConsole cairn_ui_assets)

target_compile_definitions(CairnConsole PRIVATE _AFXDLL)
target_include_directories(CairnConsole PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${CAIRN_UI_GEN_DIR})
target_precompile_headers(CairnConsole PRIVATE pch.h)
set_source_files_properties(CairnConsole.rc PROPERTIES
    OBJECT_DEPENDS "${CAIRN_UI_GEN_DIR}/assets.rc")
set_source_files_properties(EmbeddedAssets.cpp PROPERTIES
    OBJECT_DEPENDS "${CAIRN_UI_GEN_DIR}/assets_table.inc")

target_link_libraries(CairnConsole PRIVATE
    cairn_common
    unofficial::webview2::webview2
    WIL::WIL
    nlohmann_json::nlohmann_json
    dwmapi.lib shlwapi.lib advapi32.lib shell32.lib comctl32.lib ws2_32.lib)

# MFC Unicode 應用程式的進入點
target_link_options(CairnConsole PRIVATE /ENTRY:wWinMainCRTStartup)

# 正式組建移除 DevTools、右鍵選單與 --dev-http（以 _DEBUG 區分；見 WebViewHost.cpp / DevHttp.cpp）
