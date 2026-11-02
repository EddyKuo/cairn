# cairn_store —— SQLite 開啟與 schema、批次寫入、retention、稽核鏈、唯讀查詢（CONVENTIONS C-2.2）
#
# schema 內嵌方式：建置時以 EmbedSchema.cmake 把 schema/001_init.sql 轉成位元組陣列的 .cpp
#   （選擇產生 .cpp 而非 RCDATA：cairn_store 是靜態庫，RCDATA 必須由最終 EXE 的 .rc 帶入，
#    測試執行檔還得另外連結資源；位元組陣列則無此耦合，且避開 MSVC 字串常值 16 KB 上限 C2026）。
set(_schema_sql ${CMAKE_CURRENT_SOURCE_DIR}/schema/001_init.sql)
set(_schema_cpp ${CMAKE_CURRENT_BINARY_DIR}/SchemaEmbedded.cpp)
add_custom_command(
    OUTPUT  ${_schema_cpp}
    COMMAND ${CMAKE_COMMAND} -DINPUT=${_schema_sql} -DOUTPUT=${_schema_cpp}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/EmbedSchema.cmake
    DEPENDS ${_schema_sql} ${CMAKE_CURRENT_SOURCE_DIR}/EmbedSchema.cmake
    COMMENT "Embedding SQLite schema")

add_library(cairn_store STATIC
    SqliteDb.cpp
    Sha256.cpp
    AuditChain.cpp
    SpillFile.cpp
    RetentionJob.cpp
    WriteDao.cpp
    WriterThread.cpp
    ReadOnlyDb.cpp
    ${_schema_cpp})

target_include_directories(cairn_store PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)
target_link_libraries(cairn_store
    PUBLIC  cairn_common cairn_svc_common unofficial::sqlite3::sqlite3
    PRIVATE nlohmann_json::nlohmann_json bcrypt.lib)
