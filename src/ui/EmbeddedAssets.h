// EmbeddedAssets.h —— 從 EXE 的 RCDATA 取出 ui-web/dist 檔案（part4 §4.2）
//   不用 SetVirtualHostNameToFolderMapping：那需要 dist 目錄真實存在於磁碟上，等於散佈前端原始碼，
//   且多一個可被竄改的攻擊面。
#pragma once

#include <cstddef>
#include <string>
#include <string_view>

namespace cairn::ui {

struct AssetBlob {
    const void*  data = nullptr;   // 指向映像內的資源區段，生命週期 = 程序
    size_t       size = 0;
    std::wstring mime;
};

class EmbeddedAssets {
public:
    // path 為 URL 路徑（"/index.html"、"/assets/index-xxx.js"）；"/" 視為 "/index.html"。
    // 會去除 query string 與 fragment；拒絕含 ".." 的路徑。
    [[nodiscard]] bool Find(std::wstring_view path, AssetBlob& out) const;

    [[nodiscard]] static std::wstring MimeFor(std::wstring_view path);
    [[nodiscard]] size_t Count() const noexcept;
};

} // namespace cairn::ui
