// tests/svc/JsonRpcFramingTests.cpp
// 長度前綴、分段到達、黏包、超大訊息拒絕（part4 §4.2）+ JSON-RPC 2.0 分派語意。
// 被測程式碼不含 Win32，邏輯可在任何平台執行。
#include <gtest/gtest.h>

#include "rpc/Framing.h"
#include "rpc/JsonRpcDispatcher.h"

using namespace cairn::rpc;

namespace {
std::string Frame(std::string_view s) { return *EncodeFrame(s); }
} // namespace

TEST(JsonRpcFraming, EncodeWritesLittleEndianLength)
{
    const auto f = Frame("abc");
    ASSERT_EQ(f.size(), 7u);
    EXPECT_EQ(static_cast<uint8_t>(f[0]), 3);
    EXPECT_EQ(static_cast<uint8_t>(f[1]), 0);
    EXPECT_EQ(static_cast<uint8_t>(f[2]), 0);
    EXPECT_EQ(static_cast<uint8_t>(f[3]), 0);
    EXPECT_EQ(f.substr(4), "abc");
}

TEST(JsonRpcFraming, EncodeRejectsOversize)
{
    std::string big(kMaxMessageBytes + 1, 'x');
    EXPECT_FALSE(EncodeFrame(big).has_value());
    std::string limit(kMaxMessageBytes, 'x');
    EXPECT_TRUE(EncodeFrame(limit).has_value());
}

TEST(JsonRpcFraming, DecodesByteByByteArrival)
{
    const auto f = Frame(R"({"a":1})");
    FrameDecoder d;
    for (size_t i = 0; i + 1 < f.size(); ++i) {
        d.Feed(std::string_view(&f[i], 1));
        EXPECT_FALSE(d.Next().has_value()) << "不完整訊息不得提前輸出 i=" << i;
    }
    d.Feed(std::string_view(&f.back(), 1));
    auto m = d.Next();
    ASSERT_TRUE(m.has_value());
    EXPECT_EQ(*m, R"({"a":1})");
    EXPECT_FALSE(d.Next().has_value());
}

TEST(JsonRpcFraming, DecodesCoalescedFrames)
{
    FrameDecoder d;
    d.Feed(Frame("one") + Frame("") + Frame("three"));
    EXPECT_EQ(d.Next().value_or("?"), "one");
    EXPECT_EQ(d.Next().value_or("?"), "");
    EXPECT_EQ(d.Next().value_or("?"), "three");
    EXPECT_FALSE(d.Next().has_value());
}

TEST(JsonRpcFraming, SplitHeaderAcrossReads)
{
    const auto f = Frame("hello");
    FrameDecoder d;
    d.Feed(f.substr(0, 2));
    EXPECT_FALSE(d.Next().has_value());
    d.Feed(f.substr(2));
    EXPECT_EQ(d.Next().value_or("?"), "hello");
}

TEST(JsonRpcFraming, OversizeHeaderIsRejectedWithoutReadingBody)
{
    FrameDecoder d;
    const uint32_t n = kMaxMessageBytes + 1;
    const char hdr[4] = {static_cast<char>(n & 0xFF), static_cast<char>((n >> 8) & 0xFF),
                         static_cast<char>((n >> 16) & 0xFF), static_cast<char>((n >> 24) & 0xFF)};
    d.Feed(std::string_view(hdr, 4));
    EXPECT_FALSE(d.Next().has_value());
    EXPECT_EQ(d.GetState(), FrameDecoder::State::TooLarge);
    // 之後餵任何資料都不再輸出（呼叫端必須關閉連線）
    d.Feed(Frame("x"));
    EXPECT_FALSE(d.Next().has_value());
    EXPECT_EQ(d.Buffered(), 0u);
}

TEST(JsonRpcDispatch, RoutesAndEchoesId)
{
    JsonRpcDispatcher disp;
    disp.Register("health.get", [](const Json&, const RpcContext&) { return RpcOutcome::Ok(Json{{"ok", true}}); });
    auto r = disp.HandleMessage(R"({"jsonrpc":"2.0","id":7,"method":"health.get"})", {});
    ASSERT_TRUE(r);
    const auto j = Json::parse(*r);
    EXPECT_EQ(j["jsonrpc"], "2.0");
    EXPECT_EQ(j["id"], 7);
    EXPECT_EQ(j["result"]["ok"], true);
}

TEST(JsonRpcDispatch, UnknownMethod)
{
    JsonRpcDispatcher disp;
    const auto j = Json::parse(*disp.HandleMessage(R"({"jsonrpc":"2.0","id":"a","method":"nope"})", {}));
    EXPECT_EQ(j["error"]["code"], kMethodNotFound);
    EXPECT_EQ(j["error"]["data"]["code"], "METHOD_NOT_FOUND");
}

TEST(JsonRpcDispatch, ParseErrorAndInvalidRequest)
{
    JsonRpcDispatcher disp;
    auto j = Json::parse(*disp.HandleMessage("{not json", {}));
    EXPECT_EQ(j["error"]["code"], kParseError);
    j = Json::parse(*disp.HandleMessage(R"({"id":1,"method":"x"})", {}));
    EXPECT_EQ(j["error"]["code"], kInvalidRequest);
}

TEST(JsonRpcDispatch, NotificationHasNoResponse)
{
    JsonRpcDispatcher disp;
    int calls = 0;
    disp.Register("ping", [&](const Json&, const RpcContext&) {
        ++calls;
        return RpcOutcome::Ok(nullptr);
    });
    EXPECT_FALSE(disp.HandleMessage(R"({"jsonrpc":"2.0","method":"ping"})", {}).has_value());
    EXPECT_EQ(calls, 1);
}

TEST(JsonRpcDispatch, HandlerExceptionBecomesInternalError)
{
    JsonRpcDispatcher disp;
    disp.Register("boom", [](const Json&, const RpcContext&) -> RpcOutcome { throw std::runtime_error("x"); });
    const auto j = Json::parse(*disp.HandleMessage(R"({"jsonrpc":"2.0","id":1,"method":"boom"})", {}));
    EXPECT_EQ(j["error"]["data"]["code"], "INTERNAL");
}

TEST(JsonRpcDispatch, AppErrorCarriesDataCode)
{
    JsonRpcDispatcher disp;
    disp.Register("x", [](const Json&, const RpcContext&) {
        return RpcOutcome::Fail(RpcError::App("TOKEN_EXPIRED", "expired", Json{{"hint", "prepare again"}}));
    });
    const auto j = Json::parse(*disp.HandleMessage(R"({"jsonrpc":"2.0","id":1,"method":"x"})", {}));
    EXPECT_EQ(j["error"]["code"], kAppError);
    EXPECT_EQ(j["error"]["data"]["code"], "TOKEN_EXPIRED");
    EXPECT_EQ(j["error"]["data"]["hint"], "prepare again");
}

TEST(JsonRpcDispatch, InvalidUtf8InResultDoesNotThrow)
{
    JsonRpcDispatcher disp;
    disp.Register("bad", [](const Json&, const RpcContext&) { return RpcOutcome::Ok(Json(std::string("\xff\xfe"))); });
    auto r = disp.HandleMessage(R"({"jsonrpc":"2.0","id":1,"method":"bad"})", {});
    ASSERT_TRUE(r.has_value());
    EXPECT_NO_THROW((void)Json::parse(*r));
}
