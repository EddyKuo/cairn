// src/svc/host/AnalysisTasks.h                namespace cairn::host
// 把工作投遞到 AnalysisThread 執行（SDD-01 §2.5.3 鐵則：只有 AnalysisThread 可碰 ProcessTree / ScoreBoard /
// 規則狀態；其他執行緒一律以訊息傳遞取得快照或請求變更）。
//
//   RPC 執行緒： auto r = tasks.Run<T>([&](engine::AnalysisEngine& e) { return ...; }, 2s);
//   AnalysisThread：每輪迴圈 tasks.Drain(engine)
//
// 逾時回傳 Timeout（AnalysisThread 卡住或已停止）。任務本身仍可能稍後執行 —— 因此任務函式不得捕捉
// 呼叫端堆疊上的參考，一律以值捕捉（Run 內部以 shared_ptr<promise> 保證生命週期）。
#pragma once
#include <chrono>
#include <deque>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <type_traits>

#include "base/Result.h"

namespace cairn::engine {
class AnalysisEngine;
}

namespace cairn::host {

class AnalysisTasks {
public:
    using Task = std::function<void(engine::AnalysisEngine&)>;

    // 非阻塞投遞（不關心結果）。已關閉時回 false。
    bool Post(Task t)
    {
        std::lock_guard lk{m_mutex};
        if (m_closed) return false;
        m_tasks.push_back(std::move(t));
        return true;
    }

    // 投遞並等待結果。fn 的回傳型別 R 必須可複製或移動。
    template <class Fn, class R = std::invoke_result_t<Fn, engine::AnalysisEngine&>>
    Result<R> Run(Fn fn, std::chrono::milliseconds timeout)
        requires(!std::is_void_v<R>)
    {
        auto prom = std::make_shared<std::promise<R>>();
        auto fut  = prom->get_future();
        if (!Post([prom, fn = std::move(fn)](engine::AnalysisEngine& e) mutable {
                try {
                    prom->set_value(fn(e));
                } catch (...) {
                    prom->set_exception(std::current_exception());
                }
            })) {
            return MakeError(ErrorCode::ServiceUnavailable, "AnalysisThread 已停止");
        }
        if (fut.wait_for(timeout) != std::future_status::ready) {
            return MakeError(ErrorCode::Timeout, "AnalysisThread 未在時限內回應");
        }
        try {
            return fut.get();
        } catch (const std::exception& ex) {
            return MakeError(ErrorCode::NotInitialized, ex.what());
        }
    }

    template <class Fn>
    Status RunVoid(Fn fn, std::chrono::milliseconds timeout)
    {
        auto r = Run([fn = std::move(fn)](engine::AnalysisEngine& e) mutable {
            fn(e);
            return true;
        }, timeout);
        if (!r) return r.GetError();
        return Ok();
    }

    // AnalysisThread 呼叫：執行目前佇列中的全部任務。回傳執行數。
    size_t Drain(engine::AnalysisEngine& e)
    {
        std::deque<Task> batch;
        {
            std::lock_guard lk{m_mutex};
            batch.swap(m_tasks);
        }
        for (auto& t : batch) t(e);
        return batch.size();
    }

    // 停止接收新任務；未執行的任務被丟棄（其 promise 析構 → 等待者得到 broken_promise → Timeout/錯誤）。
    void Close()
    {
        std::lock_guard lk{m_mutex};
        m_closed = true;
        m_tasks.clear();
    }

    [[nodiscard]] size_t Pending() const
    {
        std::lock_guard lk{m_mutex};
        return m_tasks.size();
    }

private:
    mutable std::mutex m_mutex;
    std::deque<Task>   m_tasks;
    bool               m_closed = false;
};

} // namespace cairn::host
