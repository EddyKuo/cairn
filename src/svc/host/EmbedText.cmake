# 以 cmake -P 執行：把任意文字檔轉成位元組陣列的 .cpp，提供 std::string_view <FUNC>() noexcept。
#   cmake -DINPUT=<file> -DOUTPUT=<cpp> -DNAMESPACE=cairn::host -DFUNC=EmbeddedDefaultPolicy -P EmbedText.cmake
# 用位元組陣列而非字串常值：避開 MSVC 字串常值 16 KB 上限（C2026）與跳脫問題。
file(READ "${INPUT}" _hex HEX)
string(LENGTH "${_hex}" _len)
math(EXPR _bytes "${_len} / 2")
string(REGEX REPLACE "([0-9a-f][0-9a-f])" "0x\\1," _arr "${_hex}")
string(REGEX REPLACE "((0x[0-9a-f][0-9a-f],){24})" "\\1\n    " _arr "${_arr}")
file(WRITE "${OUTPUT}"
"// 自動產生，請勿手改。來源：${INPUT}\n"
"#include <string_view>\n"
"namespace ${NAMESPACE} {\n"
"namespace { constexpr unsigned char kData[] = {\n    ${_arr}0x00 }; }\n"
"std::string_view ${FUNC}() noexcept\n"
"{\n"
"    return std::string_view(reinterpret_cast<const char*>(kData), ${_bytes});\n"
"}\n"
"} // namespace ${NAMESPACE}\n")
