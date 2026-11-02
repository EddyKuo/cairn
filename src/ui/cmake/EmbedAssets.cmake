# ============================================================
# EmbedAssets.cmake —— 建置期以 `cmake -P` 執行
#   輸入：DIST_DIR（ui-web/dist）、OUT_DIR
#   輸出：OUT_DIR/assets.rc         —— 每個檔案一條 RCDATA（資源 ID 自 1000 起）
#         OUT_DIR/assets_table.inc  —— { L"/相對路徑", 資源ID }, 的路徑表，供 EmbeddedAssets.cpp include
# ============================================================
if(NOT DEFINED DIST_DIR OR NOT DEFINED OUT_DIR)
    message(FATAL_ERROR "EmbedAssets.cmake 需要 -DDIST_DIR 與 -DOUT_DIR")
endif()

if(NOT EXISTS "${DIST_DIR}/index.html")
    message(FATAL_ERROR
        "\n找不到前端建置產物：${DIST_DIR}/index.html\n"
        "CairnConsole.exe 會把 ui-web/dist 嵌入 EXE 資源，請先建置前端：\n"
        "    npm --prefix ui-web ci\n"
        "    npm --prefix ui-web run build\n"
        "（見 docs/part4_plan.md §4.1.2）\n")
endif()

file(GLOB_RECURSE _files RELATIVE "${DIST_DIR}" "${DIST_DIR}/*")
list(SORT _files)

set(_rc  "// 由 EmbedAssets.cmake 自動產生，請勿手動編輯\n")
set(_tbl "// 由 EmbedAssets.cmake 自動產生，請勿手動編輯\n")
set(_id 1000)
foreach(_f IN LISTS _files)
    # 不嵌入 source map 等開發用檔案
    if(_f MATCHES "\\.map$")
        continue()
    endif()
    file(TO_CMAKE_PATH "${DIST_DIR}/${_f}" _abs)
    string(APPEND _rc  "${_id} RCDATA \"${_abs}\"\n")
    string(APPEND _tbl "{ L\"/${_f}\", ${_id} },\n")
    math(EXPR _id "${_id} + 1")
endforeach()

file(MAKE_DIRECTORY "${OUT_DIR}")
foreach(_pair "assets.rc;_rc" "assets_table.inc;_tbl")
    list(GET _pair 0 _name)
    list(GET _pair 1 _var)
    set(_new "${${_var}}")
    set(_old "")
    if(EXISTS "${OUT_DIR}/${_name}")
        file(READ "${OUT_DIR}/${_name}" _old)
    endif()
    if(NOT _old STREQUAL _new)
        file(WRITE "${OUT_DIR}/${_name}" "${_new}")
    endif()
endforeach()
