# ============================================================
# src/core —— 純邏輯，零 Win32、零 I/O（part4 §4.2 最重要的結構約束）
#   不得 #include <windows.h>、不得連結任何 Win32 函式庫。
#
# 目標（對齊 CONVENTIONS C-2.2）：
#   cairn_common : base/ + model/ + prompt/   （Result、RingBuffer、事件模型、Interner、Prompt 隔離與輸出驗證）
#   cairn_rules  : tree/ + rules/ + score/ + engine/（程序樹、規則 DSL、序列比對、計分、AnalysisEngine）
#   cairn_core   : INTERFACE 匯總 = cairn_common + cairn_rules（+ cairn_store，由 src/svc 追加）
# ============================================================

file(GLOB CAIRN_COMMON_SOURCES CONFIGURE_DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/base/*.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/model/*.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/prompt/*.cpp)

add_library(cairn_common STATIC ${CAIRN_COMMON_SOURCES})
target_include_directories(cairn_common PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(cairn_common
    PUBLIC  cairn_compile_options
    PRIVATE nlohmann_json::nlohmann_json)

file(GLOB CAIRN_RULES_SOURCES CONFIGURE_DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/tree/*.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/rules/*.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/score/*.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/engine/*.cpp)

add_library(cairn_rules STATIC ${CAIRN_RULES_SOURCES})
target_link_libraries(cairn_rules
    PUBLIC  cairn_common
    PRIVATE yaml-cpp::yaml-cpp)

add_library(cairn_core INTERFACE)
target_link_libraries(cairn_core INTERFACE cairn_common cairn_rules)

# 架構紅線（W3）：ScoreEngine / AnalysisEngine 不得 include 任何 llm/ 或 prompt/ 標頭。
# 以建置期檢查落實，code review 之外再多一道機器把關。
file(GLOB_RECURSE _cairn_redline_files
    ${CMAKE_CURRENT_SOURCE_DIR}/score/*
    ${CMAKE_CURRENT_SOURCE_DIR}/engine/*)
foreach(_f IN LISTS _cairn_redline_files)
    file(STRINGS ${_f} _hits REGEX "#include[ \t]*[<\"](llm|prompt)/")
    if(_hits)
        message(FATAL_ERROR "架構紅線違反：${_f} include 了 llm/ 或 prompt/ 標頭（LLM 不得參與計分）")
    endif()
endforeach()
# 同理：src/core 不得 include <windows.h>
file(GLOB_RECURSE _cairn_core_files ${CMAKE_CURRENT_SOURCE_DIR}/*.h ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)
foreach(_f IN LISTS _cairn_core_files)
    file(STRINGS ${_f} _hits REGEX "#include[ \t]*<(windows|Windows|winternl|wil/)")
    if(_hits)
        message(FATAL_ERROR "src/core 不得相依 Win32：${_f}")
    endif()
endforeach()
