// src/svc/telemetry/BookmarkStore.h           namespace cairn::telemetry
// Event Log 書籤（EvtRender(EvtRenderBookmark) 的 XML）持久化。
// 位置：%ProgramData%\Cairn\bookmarks\{name}.xml（part2 §2.2.3）。
//
// ★ 可攜程式碼：只做檔案 I/O，不碰 EVT_HANDLE。
//   EVT_HANDLE 的書籤由 EvtChannelSource 在回呼執行緒上更新與渲染，渲染出的 XML 字串
//   交給維護執行緒以本類別寫檔（SDD-01 §3.2.2：維護執行緒永不觸碰 EVT_HANDLE）。
//
// 寫入為原子性：先寫 {name}.xml.tmp 再 rename 覆蓋，斷電時不會留下半個書籤
// （半個書籤 → EvtCreateBookmark 失敗 → 退回 ToFutureEvents → 整段事件遺失）。
#pragma once
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

#include "base/Result.h"

namespace cairn::telemetry {

class BookmarkStore {
public:
    explicit BookmarkStore(std::filesystem::path dir);

    // 讀取書籤 XML（UTF-8）。不存在或空檔回傳 nullopt。
    [[nodiscard]] std::optional<std::string> Load(std::string_view name) const;

    // 原子寫入。
    [[nodiscard]] Status Save(std::string_view name, std::string_view xml) const;

    // 書籤失效（通道被清空）時刪除，下次以 ToFutureEvents 起訂。
    void Remove(std::string_view name) const noexcept;

    [[nodiscard]] std::filesystem::path PathFor(std::string_view name) const;

private:
    std::filesystem::path m_dir;
};

} // namespace cairn::telemetry
