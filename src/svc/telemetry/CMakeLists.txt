# cairn_telemetry —— 事件訂閱、XML 正規化、事件管線（CONVENTIONS C-2.2）
#   可攜部分（無 windows.h）：EventXml / SysmonXmlParser / EventPipeline / BookmarkStore
#   Win32 部分：EvtChannelSource / ProcessSnapshot / SysmonProbe
add_library(cairn_telemetry STATIC
    EventXml.cpp
    SysmonXmlParser.cpp
    EventPipeline.cpp
    BookmarkStore.cpp
    EvtChannelSource.cpp
    ProcessSnapshot.cpp
    SysmonProbe.cpp)

target_include_directories(cairn_telemetry PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)
target_link_libraries(cairn_telemetry
    PUBLIC  cairn_common cairn_svc_common
    PRIVATE wevtapi.lib bcrypt.lib version.lib advapi32.lib)
