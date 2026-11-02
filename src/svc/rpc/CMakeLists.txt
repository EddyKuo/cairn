# cairn_rpc：Named Pipe 伺服器 + 長度前綴框架 + JSON-RPC 2.0 分派（傳輸層）。
# RPC handlers 需要所有模組，編入 CairnAgent.exe（見 ../host.cmake），不放在此庫，避免 core.* 橫向相依（L-2）。
add_library(cairn_rpc STATIC
    Framing.cpp
    JsonRpcDispatcher.cpp
    PipeServer.cpp)
target_include_directories(cairn_rpc PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)
target_link_libraries(cairn_rpc PUBLIC cairn_svc_common advapi32.lib)
