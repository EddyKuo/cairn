// src/svc/store/Sha256.h                      namespace cairn::store
// SHA-256（小寫 hex）。Windows 上以 CNG（BCrypt）計算；非 Windows 以內建的可攜實作
// （僅供開發機語法檢查與單元測試，產品只在 Windows 上建置）。
#pragma once
#include <string>
#include <string_view>

namespace cairn::store {

[[nodiscard]] std::string Sha256Hex(std::string_view data);

} // namespace cairn::store
