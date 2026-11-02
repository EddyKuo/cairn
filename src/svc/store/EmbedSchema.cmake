# 以 cmake -P 執行：把 schema SQL 轉成位元組陣列的 .cpp（避開 MSVC 字串常值 16 KB 上限 C2026）。
#   cmake -DINPUT=<sql> -DOUTPUT=<cpp> -P EmbedSchema.cmake
file(READ "${INPUT}" _hex HEX)
string(LENGTH "${_hex}" _len)
math(EXPR _bytes "${_len} / 2")
string(REGEX REPLACE "([0-9a-f][0-9a-f])" "0x\\1," _arr "${_hex}")
# 每 24 個位元組換行，避免單行過長
string(REGEX REPLACE "((0x[0-9a-f][0-9a-f],){24})" "\\1\n    " _arr "${_arr}")
file(WRITE "${OUTPUT}"
"// 自動產生，請勿手改。來源：${INPUT}\n"
"#include \"store/SqliteDb.h\"\n"
"namespace cairn::store {\n"
"namespace { constexpr unsigned char kSchema[] = {\n    ${_arr}0x00 }; }\n"
"std::string_view EmbeddedSchemaSql() noexcept\n"
"{\n"
"    return std::string_view(reinterpret_cast<const char*>(kSchema), ${_bytes});\n"
"}\n"
"} // namespace cairn::store\n")
