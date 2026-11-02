// ResourceInterceptor.cpp —— 見 ResourceInterceptor.h
#include "pch.h"

#include "ResourceInterceptor.h"

#include "EmbeddedAssets.h"
#include "RpcClient.h"
#include "Utf.h"

#include <cctype>
#include <cstdlib>

using nlohmann::json;
using Microsoft::WRL::ComPtr;

namespace cairn::ui {

namespace {

constexpr size_t kMaxRequestBody = 1u << 20;   // 1 MiB（與管線上限一致）

// 所有回應統一附加的安全標頭（SDD-03 §9.3.3）
constexpr wchar_t kSecurityHeaders[] =
    L"Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    L"img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'\r\n"
    L"X-Content-Type-Options: nosniff\r\n"
    L"Referrer-Policy: no-referrer\r\n"
    L"Cache-Control: no-store\r\n";

// ---------------------------------------------------------------------------
// 路由表（SDD-03 §9.3.2）。{name} 為路徑參數，名稱即傳給 RPC 的 params 鍵名。
// ---------------------------------------------------------------------------
struct Route {
    const char* method;
    const char* pattern;
    const char* rpc;          // nullptr = M0 不實作
    int         okStatus;
    int         timeoutMs;
};

constexpr Route kRoutes[] = {
    {"GET", "/api/v1/health", "health.get", 200, 5000},
    {"GET", "/api/v1/alerts", "alerts.list", 200, 5000},
    {"GET", "/api/v1/alerts/{alert_id}", "alerts.get", 200, 5000},
    {"GET", "/api/v1/alerts/{alert_id}/narrative", "narrative.get", 200, 5000},
    {"POST", "/api/v1/alerts/{alert_id}/narrative/regenerate", "narrative.regenerate", 202, 5000},
    {"POST", "/api/v1/alerts/{alert_id}/narrative/feedback", "narrative.feedback", 200, 5000},
    {"POST", "/api/v1/alerts/{alert_id}/verdict", "alerts.setVerdict", 200, 10000},
    {"POST", "/api/v1/alerts/{alert_id}/actions/prepare", "response.prepare", 200, 10000},
    {"POST", "/api/v1/alerts/{alert_id}/actions", "response.execute", 200, 30000},
    {"POST", "/api/v1/alerts/{alert_id}/actions/{audit_id}/revert", "response.revert", 200, 30000},
    {"GET", "/api/v1/events/stream", nullptr, 501, 0},   // M1（SDD-03 §9.6）
    {"GET", "/api/v1/events", "events.query", 200, 10000},
    {"GET", "/api/v1/exclusions", "exclusions.list", 200, 5000},
    {"POST", "/api/v1/exclusions", "exclusions.add", 200, 10000},
    {"GET", "/api/v1/exclusions/preview", "exclusions.preview", 200, 10000},
    {"GET", "/api/v1/exclusions/suggestions", "exclusions.suggestions", 200, 10000},
    {"DELETE", "/api/v1/exclusions/suggestions/{suggestion_id}", "exclusions.dismissSuggestion", 200, 5000},
    {"DELETE", "/api/v1/exclusions/{exclusion_id}", "exclusions.remove", 200, 10000},
    {"GET", "/api/v1/rules", "rules.list", 200, 5000},
    {"PATCH", "/api/v1/rules/{rule_id}", "rules.setStatus", 200, 10000},
    {"POST", "/api/v1/rules/{rule_id}/explain", "rules.explain", 200, 10000},
    {"GET", "/api/v1/audit", "audit.list", 200, 10000},
    {"GET", "/api/v1/quarantine", "quarantine.list", 200, 5000},
    {"POST", "/api/v1/undo/{undo_token}", "undo.apply", 200, 10000},
    {"POST", "/api/v1/protection/pause", "protection.pause", 200, 10000},
    {"POST", "/api/v1/protection/resume", "protection.resume", 200, 10000},
    {"POST", "/api/v1/learning-mode/finish", "learning.finish", 200, 10000},
    {"GET", "/api/v1/export", "export.create", 200, 30000},
};

std::vector<std::string_view> Split(std::string_view s)
{
    std::vector<std::string_view> out;
    size_t i = 0;
    while (i < s.size()) {
        if (s[i] == '/') {
            ++i;
            continue;
        }
        const size_t j = s.find('/', i);
        out.push_back(s.substr(i, j == std::string_view::npos ? std::string_view::npos : j - i));
        if (j == std::string_view::npos) break;
        i = j;
    }
    return out;
}

const Route* MatchRoute(std::string_view method, std::string_view path, json& pathParams, bool& methodMismatch)
{
    methodMismatch = false;
    const auto segs = Split(path);
    for (const auto& r : kRoutes) {
        const auto pat = Split(r.pattern);
        if (pat.size() != segs.size()) continue;
        json params = json::object();
        bool ok = true;
        for (size_t i = 0; i < pat.size() && ok; ++i) {
            if (pat[i].size() > 2 && pat[i].front() == '{' && pat[i].back() == '}') {
                params[std::string(pat[i].substr(1, pat[i].size() - 2))] = PercentDecode(segs[i]);
            } else if (pat[i] != segs[i]) {
                ok = false;
            }
        }
        if (!ok) continue;
        if (method != r.method) {
            methodMismatch = true;
            continue;
        }
        pathParams = std::move(params);
        return &r;
    }
    return nullptr;
}

HttpReply ErrorReply(int status, std::string_view code, std::string_view message, const json& details = json())
{
    json e = {{"code", code}, {"message", message}};
    if (!details.is_null() && !details.empty()) e["details"] = details;
    return HttpReply{status, json{{"error", e}}.dump(-1, ' ', false, json::error_handler_t::replace)};
}

// 業務碼 → HTTP（SDD-03 §9.3.4、part3 §3.8.0）
int StatusForBusinessCode(std::string_view code)
{
    struct M {
        const char* code;
        int         status;
    };
    static constexpr M kMap[] = {
        {"NOT_FOUND", 404},
        {"INVALID_PARAMS", 400},
        {"TOKEN_INVALID", 401},
        {"CONFIRMATION_REQUIRED", 403},
        {"TOKEN_EXPIRED", 410},
        {"TYPED_CONFIRMATION_MISMATCH", 400},
        {"IMPACT_CHANGED", 409},
        {"NOT_REVERSIBLE", 409},
        {"CONFLICT", 409},
        {"PARTIAL_SUCCESS", 207},
        {"ACTION_FAILED", 502},
        {"MESSAGE_TOO_LARGE", 413},
        {"RESULT_TOO_LARGE", 413},
        {"UNPROCESSABLE", 422},
        {"SERVICE_UNAVAILABLE", 503},
        {"RPC_TIMEOUT", 504},
        {"TIMEOUT", 504},
        {"NOT_IMPLEMENTED", 501},
    };
    for (const auto& m : kMap)
        if (code == m.code) return m.status;
    return 0;
}

HttpReply MapRpcError(const RpcOutcome& r)
{
    switch (r.kind) {
    case RpcOutcome::Kind::LinkDown:
        return ErrorReply(503, "SERVICE_UNAVAILABLE", "無法連線至 Cairn 服務");
    case RpcOutcome::Kind::Timeout:
        return ErrorReply(504, "RPC_TIMEOUT", "Cairn 服務回應逾時");
    case RpcOutcome::Kind::Protocol:
        return ErrorReply(502, "BAD_RPC_RESPONSE", r.message.empty() ? "服務回應格式錯誤" : r.message);
    default:
        break;
    }
    // RpcError：優先採用 error.data 的業務碼與 http 狀態
    std::string code;
    int         status = 0;
    json        details = json::object();
    if (r.data.is_object()) {
        code = r.data.value("code", std::string{});
        status = r.data.value("http", 0);
        if (auto it = r.data.find("details"); it != r.data.end()) details = *it;
    }
    if (status == 0 && !code.empty()) status = StatusForBusinessCode(code);
    if (status == 0) {
        switch (r.code) {
        case -32601: status = 404; if (code.empty()) code = "NOT_FOUND"; break;
        case -32602: status = 400; if (code.empty()) code = "INVALID_PARAMS"; break;
        case -32600: status = 400; if (code.empty()) code = "INVALID_REQUEST"; break;
        default: status = 500; if (code.empty()) code = "INTERNAL"; break;
        }
    }
    if (code.empty()) code = "INTERNAL";
    return ErrorReply(status, code, r.message, details);
}

// 單一待完成的 API 請求：UI 執行緒建立 → 執行緒池跑 RPC → PostMessage 回 UI 執行緒完成
struct PendingApi {
    const ResourceInterceptor*                                   self = nullptr;
    wil::com_ptr<ICoreWebView2Environment>                       env;
    wil::com_ptr<ICoreWebView2WebResourceRequestedEventArgs>     args;
    wil::com_ptr<ICoreWebView2Deferral>                          deferral;
    std::string method, path, query, body;
    HttpReply   reply;
    HWND        notifyWnd = nullptr;
};

void CALLBACK RunPendingApi(PTP_CALLBACK_INSTANCE, void* ctx)
{
    auto* p = static_cast<PendingApi*>(ctx);
    p->reply = p->self->HandleApi(p->method, p->path, p->query, p->body);
    if (!::PostMessageW(p->notifyWnd, WM_APP_API_REPLY, 0, reinterpret_cast<LPARAM>(p))) {
        // 視窗已毀：COM 物件屬於 UI 執行緒，於此僅能放棄（不得在背景執行緒 Release STA 物件）。
        // 洩漏一個小結構體優於跨 apartment 釋放；此路徑只會在程序結束時發生。
    }
}

wil::com_ptr<IStream> StreamFrom(const void* data, size_t size)
{
    wil::com_ptr<IStream> s;
    s.attach(::SHCreateMemStream(static_cast<const BYTE*>(data), static_cast<UINT>(size)));
    return s;
}

bool ReadContent(ICoreWebView2WebResourceRequest* req, std::string& out)
{
    wil::com_ptr<IStream> content;
    if (FAILED(req->get_Content(content.put())) || !content) return true;
    char buf[16 * 1024];
    for (;;) {
        ULONG n = 0;
        const HRESULT hr = content->Read(buf, sizeof(buf), &n);
        if (n > 0) {
            out.append(buf, n);
            if (out.size() > kMaxRequestBody) return false;
        }
        if (hr != S_OK || n == 0) break;
    }
    return true;
}

bool IsKnownNumericKey(std::string_view k)
{
    return k == "limit" || k == "event_count" || k == "offset";
}
bool IsKnownBoolKey(std::string_view k)
{
    return k == "has_narrative" || k == "blocked_only" || k == "all";
}

} // namespace

const wchar_t* ResourceInterceptor::SecurityHeaders() noexcept
{
    return kSecurityHeaders;
}

std::string PercentDecode(std::string_view s)
{
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i + 2 < s.size() && isxdigit(static_cast<unsigned char>(s[i + 1])) &&
            isxdigit(static_cast<unsigned char>(s[i + 2]))) {
            out.push_back(static_cast<char>(std::stoi(std::string(s.substr(i + 1, 2)), nullptr, 16)));
            i += 2;
        } else if (s[i] == '+') {
            out.push_back(' ');
        } else {
            out.push_back(s[i]);
        }
    }
    return out;
}

// key[]=a&key[]=b → 陣列；重複鍵 → 陣列；已知數值／布林鍵轉型，其餘一律字串（避免 q=123 被誤轉）。
json ParseQuery(std::string_view query)
{
    json out = json::object();
    size_t i = 0;
    while (i <= query.size()) {
        size_t j = query.find('&', i);
        if (j == std::string_view::npos) j = query.size();
        const auto kv = query.substr(i, j - i);
        if (!kv.empty()) {
            const auto eq = kv.find('=');
            std::string key = PercentDecode(kv.substr(0, eq));
            std::string val = eq == std::string_view::npos ? std::string{} : PercentDecode(kv.substr(eq + 1));
            bool isArray = false;
            if (key.size() > 2 && key.compare(key.size() - 2, 2, "[]") == 0) {
                key.resize(key.size() - 2);
                isArray = true;
            }
            json v = val;
            if (IsKnownNumericKey(key)) {
                char* end = nullptr;
                const long long n = std::strtoll(val.c_str(), &end, 10);
                if (end && *end == '\0' && !val.empty()) v = n;
            } else if (IsKnownBoolKey(key)) {
                v = (val == "true" || val == "1");
            }
            if (isArray) {
                if (!out[key].is_array()) out[key] = json::array();
                out[key].push_back(v);
            } else if (out.contains(key)) {
                if (!out[key].is_array()) out[key] = json::array({out[key]});
                out[key].push_back(v);
            } else {
                out[key] = v;
            }
        }
        i = j + 1;
    }
    return out;
}

std::string ReasonPhrase(int s)
{
    switch (s) {
    case 200: return "OK";
    case 201: return "Created";
    case 202: return "Accepted";
    case 204: return "No Content";
    case 207: return "Multi-Status";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 409: return "Conflict";
    case 410: return "Gone";
    case 413: return "Payload Too Large";
    case 422: return "Unprocessable Entity";
    case 501: return "Not Implemented";
    case 502: return "Bad Gateway";
    case 503: return "Service Unavailable";
    case 504: return "Gateway Timeout";
    default: return s < 400 ? "OK" : "Internal Server Error";
    }
}

ResourceInterceptor::ResourceInterceptor(std::shared_ptr<RpcClient> rpc, const EmbeddedAssets* assets, HWND notifyWnd)
    : m_rpc(std::move(rpc)), m_assets(assets), m_notifyWnd(notifyWnd)
{
}

HttpReply ResourceInterceptor::HandleApi(std::string_view method, std::string_view path, std::string_view query,
                                         std::string_view body) const
{
    json pathParams;
    bool methodMismatch = false;
    const Route* route = MatchRoute(method, path, pathParams, methodMismatch);
    if (!route) {
        return methodMismatch ? ErrorReply(405, "METHOD_NOT_ALLOWED", "不支援的 HTTP 方法")
                              : ErrorReply(404, "NO_ROUTE", "找不到對應的 API");
    }
    if (!route->rpc) return ErrorReply(501, "NOT_IMPLEMENTED", "此端點於 M1 提供（M0 不實作即時串流）");

    // params = query → body → 路徑參數（路徑參數最後覆寫，body 不得竄改目標告警 ID）
    json params = ParseQuery(query);
    if (!body.empty()) {
        json b = json::parse(body, nullptr, false);
        if (b.is_discarded() || !b.is_object()) return ErrorReply(400, "INVALID_PARAMS", "請求本文必須是 JSON 物件");
        for (auto& [k, v] : b.items()) params[k] = v;
    }
    for (auto& [k, v] : pathParams.items()) params[k] = v;

    const RpcOutcome r = m_rpc->Call(route->rpc, params, std::chrono::milliseconds(route->timeoutMs));
    if (!r.Ok()) return MapRpcError(r);

    // 成功：預設狀態碼，可由結果的 "_http_status" 覆寫（伺服器端表達 207 / 202 等），覆寫欄位不回傳給前端
    int  status = route->okStatus;
    json result = r.result;
    if (result.is_object()) {
        if (auto it = result.find("_http_status"); it != result.end() && it->is_number_integer()) {
            status = it->get<int>();
            result.erase(it);
        } else if (result.value("overall_result", std::string{}) == "partial_success") {
            status = 207;   // 部分成功（SDD-03 §8.4）
        }
    }
    return HttpReply{status, result.dump(-1, ' ', false, json::error_handler_t::replace)};
}

HRESULT ResourceInterceptor::OnWebResourceRequested(ICoreWebView2Environment* env,
                                                    ICoreWebView2WebResourceRequestedEventArgs* args)
{
    wil::com_ptr<ICoreWebView2WebResourceRequest> req;
    RETURN_IF_FAILED(args->get_Request(req.put()));
    wil::unique_cotaskmem_string uri, method;
    RETURN_IF_FAILED(req->get_Uri(uri.put()));
    RETURN_IF_FAILED(req->get_Method(method.put()));

    // 只處理 https://cairn.local/；其餘交還預設處理（會被 CSP 與 NavigationStarting 擋下）
    constexpr std::wstring_view kOrigin = L"https://cairn.local";
    std::wstring_view u = uri.get();
    if (u.size() < kOrigin.size() || _wcsnicmp(u.data(), kOrigin.data(), kOrigin.size()) != 0) return S_OK;
    std::wstring_view rest = u.substr(kOrigin.size());
    if (!rest.empty() && rest.front() != L'/') return S_OK;   // 例如 https://cairn.local.evil.com
    if (rest.empty()) rest = L"/";

    std::wstring_view wpath = rest;
    std::wstring_view wquery;
    if (const auto f = wpath.find(L'#'); f != std::wstring_view::npos) wpath = wpath.substr(0, f);
    if (const auto q = wpath.find(L'?'); q != std::wstring_view::npos) {
        wquery = wpath.substr(q + 1);
        wpath = wpath.substr(0, q);
    }

    wil::com_ptr<ICoreWebView2WebResourceResponse> resp;

    // ---- 靜態資源 ----
    if (!(wpath.size() >= 8 && wpath.substr(0, 8) == L"/api/v1/") && wpath != L"/api/v1") {
        AssetBlob blob;
        if (!m_assets->Find(wpath, blob)) {
            std::wstring hdr = std::wstring(L"Content-Type: text/plain; charset=utf-8\r\n") + kSecurityHeaders;
            RETURN_IF_FAILED(env->CreateWebResourceResponse(nullptr, 404, L"Not Found", hdr.c_str(), resp.put()));
        } else {
            auto stream = StreamFrom(blob.data, blob.size);
            std::wstring hdr = L"Content-Type: " + blob.mime + L"\r\n" + kSecurityHeaders;
            RETURN_IF_FAILED(env->CreateWebResourceResponse(stream.get(), 200, L"OK", hdr.c_str(), resp.put()));
        }
        return args->put_Response(resp.get());
    }

    // ---- API：讀 body（UI 執行緒）→ deferral → 執行緒池跑 RPC ----
    auto p = std::make_unique<PendingApi>();
    p->self = this;
    p->env = env;
    p->args = args;
    p->notifyWnd = m_notifyWnd;
    p->method = ToUtf8(method.get());
    p->path = ToUtf8(wpath);   // 不先整體解碼：路徑參數值於 MatchRoute 中逐段解碼（避免 %2F 被當成分隔）
    p->query = ToUtf8(wquery);
    if (!ReadContent(req.get(), p->body)) {
        const HttpReply r = ErrorReply(413, "MESSAGE_TOO_LARGE", "請求本文超過 1 MiB");
        auto stream = StreamFrom(r.body.data(), r.body.size());
        std::wstring hdr = std::wstring(L"Content-Type: application/json; charset=utf-8\r\n") + kSecurityHeaders;
        RETURN_IF_FAILED(env->CreateWebResourceResponse(stream.get(), r.status, L"Payload Too Large", hdr.c_str(), resp.put()));
        return args->put_Response(resp.get());
    }
    RETURN_IF_FAILED(args->GetDeferral(p->deferral.put()));
    if (!::TrySubmitThreadpoolCallback(&RunPendingApi, p.get(), nullptr)) {
        p->deferral->Complete();
        return HRESULT_FROM_WIN32(::GetLastError());
    }
    p.release();   // 由 CompleteReply 釋放
    return S_OK;
}

void ResourceInterceptor::CompleteReply(LPARAM pending)
{
    std::unique_ptr<PendingApi> p{reinterpret_cast<PendingApi*>(pending)};
    if (!p) return;
    const std::wstring reason = ToWide(ReasonPhrase(p->reply.status));
    const std::wstring hdr = std::wstring(L"Content-Type: application/json; charset=utf-8\r\n") + kSecurityHeaders;
    auto stream = StreamFrom(p->reply.body.data(), p->reply.body.size());
    wil::com_ptr<ICoreWebView2WebResourceResponse> resp;
    if (SUCCEEDED(p->env->CreateWebResourceResponse(stream.get(), p->reply.status, reason.c_str(), hdr.c_str(), resp.put()))) {
        p->args->put_Response(resp.get());
    }
    p->deferral->Complete();
}

} // namespace cairn::ui
