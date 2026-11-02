#include "host/HandlerContext.h"

namespace cairn::host {

std::pair<std::string, int64_t> UndoStore::Issue(UndoEntry e, const std::string& token)
{
    const int64_t now = m_clock.NowMs();
    e.expiresAt = now + std::chrono::duration_cast<std::chrono::milliseconds>(m_ttl).count();
    std::lock_guard lk{m_mutex};
    // 順手清掉過期項目，避免無限成長
    for (auto it = m_entries.begin(); it != m_entries.end();) {
        if (it->second.expiresAt <= now) it = m_entries.erase(it);
        else ++it;
    }
    m_entries[token] = e;
    return {token, e.expiresAt};
}

std::optional<UndoEntry> UndoStore::Take(const std::string& token)
{
    std::lock_guard lk{m_mutex};
    auto it = m_entries.find(token);
    if (it == m_entries.end()) return std::nullopt;
    UndoEntry e = it->second;
    m_entries.erase(it);
    if (e.expiresAt <= m_clock.NowMs()) return std::nullopt;
    return e;
}

void UndoStore::Sweep()
{
    const int64_t now = m_clock.NowMs();
    std::lock_guard lk{m_mutex};
    for (auto it = m_entries.begin(); it != m_entries.end();) {
        if (it->second.expiresAt <= now) it = m_entries.erase(it);
        else ++it;
    }
}

} // namespace cairn::host
