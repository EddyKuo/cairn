// DevHttp.cpp —— `CairnConsole.exe --dev-http 5080`：僅供前端開發（part3 §3.8.0）
//   Vite dev server（http://localhost:5173）沒有 WebView2 攔截層，因此以本機 HTTP 把 /api/v1/* 轉給
//   ResourceInterceptor::HandleApi → Named Pipe JSON-RPC。
//   ⚠ 此旗標在 Release 組態下以 #ifdef 完全移除，不是執行期開關（正式組建不開任何監聽埠）。
#include "pch.h"

#include "ResourceInterceptor.h"

#ifdef _DEBUG

namespace {
std::atomic<SOCKET> g_listen{INVALID_SOCKET};
std::thread         g_thread;

bool RecvUntil(SOCKET s, std::string& buf, size_t want)
{
    char tmp[8192];
    while (buf.size() < want) {
        const int n = ::recv(s, tmp, sizeof(tmp), 0);
        if (n <= 0) return false;
        buf.append(tmp, static_cast<size_t>(n));
    }
    return true;
}

void Serve(SOCKET c, cairn::ui::ResourceInterceptor* ri)
{
    std::string buf;
    char        tmp[8192];
    size_t      headerEnd = std::string::npos;
    while ((headerEnd = buf.find("\r\n\r\n")) == std::string::npos) {
        const int n = ::recv(c, tmp, sizeof(tmp), 0);
        if (n <= 0 || buf.size() > 64 * 1024) return;
        buf.append(tmp, static_cast<size_t>(n));
    }
    const std::string head = buf.substr(0, headerEnd);
    const size_t sp1 = head.find(' '), sp2 = head.find(' ', sp1 + 1);
    if (sp1 == std::string::npos || sp2 == std::string::npos) return;
    const std::string method = head.substr(0, sp1);
    std::string target = head.substr(sp1 + 1, sp2 - sp1 - 1);

    size_t contentLength = 0;
    for (size_t p = head.find("\r\n"); p != std::string::npos;) {
        const size_t e = head.find("\r\n", p + 2);
        std::string line = head.substr(p + 2, e == std::string::npos ? std::string::npos : e - p - 2);
        if (_strnicmp(line.c_str(), "content-length:", 15) == 0) contentLength = std::strtoul(line.c_str() + 15, nullptr, 10);
        p = e;
    }
    if (contentLength > (1u << 20)) return;
    std::string body = buf.substr(headerEnd + 4);
    if (!RecvUntil(c, body, contentLength)) return;
    body.resize(contentLength);

    std::string path = target, query;
    if (const auto q = target.find('?'); q != std::string::npos) {
        path = target.substr(0, q);
        query = target.substr(q + 1);
    }
    cairn::ui::HttpReply r;
    if (path.rfind("/api/v1/", 0) == 0) {
        r = ri->HandleApi(method, path, query, body);
    } else {
        r = {404, R"({"error":{"code":"NO_ROUTE","message":"dev-http 只轉接 /api/v1/*"}})"};
    }
    std::string resp = "HTTP/1.1 " + std::to_string(r.status) + " " + cairn::ui::ReasonPhrase(r.status) + "\r\n" +
                       "Content-Type: application/json; charset=utf-8\r\n" +
                       "Content-Length: " + std::to_string(r.body.size()) + "\r\nConnection: close\r\n\r\n" + r.body;
    size_t sent = 0;
    while (sent < resp.size()) {
        const int n = ::send(c, resp.data() + sent, static_cast<int>(resp.size() - sent), 0);
        if (n <= 0) break;
        sent += static_cast<size_t>(n);
    }
}
} // namespace

bool StartDevHttpServer(uint16_t port, cairn::ui::ResourceInterceptor* ri)
{
    WSADATA wsa{};
    if (::WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return false;
    SOCKET s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return false;
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    ::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);   // 只綁 loopback
    if (::bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 || ::listen(s, 8) != 0) {
        ::closesocket(s);
        return false;
    }
    g_listen = s;
    g_thread = std::thread([ri] {
        for (;;) {
            const SOCKET c = ::accept(g_listen.load(), nullptr, nullptr);
            if (c == INVALID_SOCKET) break;   // StopDevHttpServer 關閉了監聽 socket
            Serve(c, ri);
            ::closesocket(c);
        }
    });
    ::OutputDebugStringW(L"[CairnConsole] --dev-http 已啟動（僅 Debug 組建）\n");
    return true;
}

void StopDevHttpServer()
{
    const SOCKET s = g_listen.exchange(INVALID_SOCKET);
    if (s == INVALID_SOCKET) return;   // 未啟動
    ::closesocket(s);
    if (g_thread.joinable()) g_thread.join();
    ::WSACleanup();
}

#else

bool StartDevHttpServer(uint16_t, cairn::ui::ResourceInterceptor*) { return false; }
void StopDevHttpServer() {}

#endif
