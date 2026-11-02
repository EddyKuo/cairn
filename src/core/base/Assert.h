// src/core/base/Assert.h
#pragma once
#include <cstdio>
#include <cstdlib>

// 前置條件違反即程式錯誤。Debug 與 Release 皆生效（安全產品寧可崩潰留下 dump，
// 也不要在不一致的狀態下繼續做阻擋決策）。
#define CAIRN_ASSERT(cond)                                                            \
    do {                                                                              \
        if (!(cond)) {                                                                \
            std::fprintf(stderr, "CAIRN_ASSERT failed: %s (%s:%d)\n", #cond, __FILE__, \
                         __LINE__);                                                   \
            std::abort();                                                             \
        }                                                                             \
    } while (0)
