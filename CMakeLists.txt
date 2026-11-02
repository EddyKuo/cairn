# ============================================================
# Cairn M0 — 頂層建置腳本
# 權威約定：docs/CONVENTIONS.md C-1（C++20 / MSVC v143 / CMake 3.25+ / vcpkg manifest）
#
# 目標平台僅 Windows。唯一例外：選項 CAIRN_CORE_ONLY=ON 時只建置 src/core 與
# tests/core（零 Win32 相依），供非 Windows 開發機做語法／型別檢查。
# ============================================================
cmake_minimum_required(VERSION 3.25)

project(Cairn
    VERSION 0.1.0
    DESCRIPTION "Cairn M0 — Minimum Verifiable EDR"
    LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(CAIRN_CORE_ONLY  "只建置 src/core + tests/core（非 Windows 檢查用）" OFF)
option(CAIRN_BUILD_TESTS "建置 gtest 測試"                               ON)
option(CAIRN_ENABLE_ASAN "AddressSanitizer 建置（x64-asan preset）"      OFF)
option(CAIRN_BUILD_UI    "建置 CairnConsole.exe（需 MFC + WebView2）"   ON)

if(NOT WIN32 AND NOT CAIRN_CORE_ONLY)
    message(FATAL_ERROR
        "Cairn 僅支援 Windows（CONVENTIONS C-1）。"
        "非 Windows 環境請以 -DCAIRN_CORE_ONLY=ON 只建置 src/core。")
endif()

# ------------------------------------------------------------
# 編譯選項（CONVENTIONS C-1）
# ------------------------------------------------------------
add_library(cairn_compile_options INTERFACE)
if(MSVC)
    target_compile_options(cairn_compile_options INTERFACE
        /W4 /permissive- /GS /sdl /utf-8 /Zc:__cplusplus /EHsc
        $<$<NOT:$<BOOL:${CAIRN_ENABLE_ASAN}>>:/guard:cf>)
    target_compile_definitions(cairn_compile_options INTERFACE
        UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN
        _WIN32_WINNT=0x0A00 WINVER=0x0A00)
    target_link_options(cairn_compile_options INTERFACE
        $<$<NOT:$<BOOL:${CAIRN_ENABLE_ASAN}>>:/guard:cf>)
    if(CAIRN_ENABLE_ASAN)
        target_compile_options(cairn_compile_options INTERFACE /fsanitize=address /Zi)
        target_compile_definitions(cairn_compile_options INTERFACE
            _DISABLE_VECTOR_ANNOTATION _DISABLE_STRING_ANNOTATION)
    endif()
else()
    target_compile_options(cairn_compile_options INTERFACE -Wall -Wextra -Wpedantic)
    if(CAIRN_ENABLE_ASAN)
        target_compile_options(cairn_compile_options INTERFACE -fsanitize=address -fno-omit-frame-pointer)
        target_link_options(cairn_compile_options INTERFACE -fsanitize=address)
    endif()
endif()

# ------------------------------------------------------------
# 第三方相依（全部經 vcpkg，CONVENTIONS C-3）
# ------------------------------------------------------------
find_package(yaml-cpp CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(yyjson CONFIG REQUIRED)
if(CAIRN_BUILD_TESTS)
    find_package(GTest CONFIG REQUIRED)
    enable_testing()
endif()
if(NOT CAIRN_CORE_ONLY)
    find_package(unofficial-sqlite3 CONFIG REQUIRED)
    find_package(spdlog CONFIG REQUIRED)
    find_package(wil CONFIG REQUIRED)
    if(CAIRN_BUILD_UI)
        find_package(unofficial-webview2 CONFIG REQUIRED)
    endif()
endif()

# ------------------------------------------------------------
# 子目錄
# ------------------------------------------------------------
add_subdirectory(src/core)
if(NOT CAIRN_CORE_ONLY)
    add_subdirectory(src/svc)
    if(CAIRN_BUILD_UI)
        add_subdirectory(src/ui)
    endif()
endif()
if(CAIRN_BUILD_TESTS)
    add_subdirectory(tests)
endif()
