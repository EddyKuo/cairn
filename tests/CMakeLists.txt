# ============================================================
# tests —— gtest + CTest
#   core.* ：純邏輯，不需管理員、不需 Sysmon（主戰場）
#   svc.*  ：需 Win32，部分需管理員（CI 上以 GTEST_SKIP 標記）
# 測試名稱前綴讓 `ctest -R "core\."` 只跑核心測試（part4 W2 出場條件 1）。
# ============================================================
include(GoogleTest)

file(GLOB CAIRN_CORE_TEST_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/core/*.cpp)
add_executable(cairn_tests_core ${CAIRN_CORE_TEST_SOURCES})
target_link_libraries(cairn_tests_core PRIVATE cairn_core nlohmann_json::nlohmann_json GTest::gtest GTest::gtest_main)
target_compile_definitions(cairn_tests_core PRIVATE
    CAIRN_TEST_FIXTURES_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures"
    CAIRN_RULES_DIR="${PROJECT_SOURCE_DIR}/rules")
gtest_discover_tests(cairn_tests_core TEST_PREFIX "core." DISCOVERY_MODE PRE_TEST)

if(NOT CAIRN_CORE_ONLY)
    file(GLOB CAIRN_SVC_TEST_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/svc/*.cpp)
    add_executable(cairn_tests_svc ${CAIRN_SVC_TEST_SOURCES})
    target_link_libraries(cairn_tests_svc PRIVATE
        cairn_core cairn_telemetry cairn_store cairn_response cairn_llm cairn_rpc cairn_host
        GTest::gtest GTest::gtest_main)
    target_compile_definitions(cairn_tests_svc PRIVATE
        CAIRN_TEST_FIXTURES_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures"
        CAIRN_SCHEMA_DIR="${PROJECT_SOURCE_DIR}/src/svc/store/schema")
    gtest_discover_tests(cairn_tests_svc TEST_PREFIX "svc." DISCOVERY_MODE PRE_TEST)
endif()
