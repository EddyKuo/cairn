#include "model/StringInterner.h"

#include <mutex>

namespace cairn::model {

std::string ToLowerAscii(std::string_view s)
{
    std::string out(s);
    for (auto& c : out)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return out;
}

StringInterner::StringInterner(size_t maxEntries) : m_maxEntries(maxEntries) {}

InternId StringInterner::Intern(std::string_view s)
{
    {
        std::shared_lock rl{m_mutex};
        if (auto it = m_index.find(s); it != m_index.end()) return it->second;
    }
    std::unique_lock wl{m_mutex};
    if (auto it = m_index.find(s); it != m_index.end()) return it->second;   // double-check
    if (m_storage.size() >= m_maxEntries) return kInvalidInternId;
    const auto id = static_cast<InternId>(m_storage.size());
    m_storage.emplace_back(s);
    m_index.emplace(std::string_view{m_storage.back()}, id);
    return id;
}

InternId StringInterner::InternLower(std::string_view s)
{
    return Intern(ToLowerAscii(s));
}

InternId StringInterner::Find(std::string_view s) const
{
    std::shared_lock rl{m_mutex};
    if (auto it = m_index.find(s); it != m_index.end()) return it->second;
    return kInvalidInternId;
}

std::string_view StringInterner::Resolve(InternId id) const
{
    if (id == kInvalidInternId) return {};
    std::shared_lock rl{m_mutex};
    if (id >= m_storage.size()) return {};
    return m_storage[id];
}

size_t StringInterner::Size() const
{
    std::shared_lock rl{m_mutex};
    return m_storage.size();
}

bool StringInterner::IsSaturated() const
{
    std::shared_lock rl{m_mutex};
    return m_storage.size() >= m_maxEntries;
}

} // namespace cairn::model
