////////////////////////////////////////////////////////////////////////
/// @file       log.cpp
/// @brief      日志类实现文件
/// @details    日志类实现文件
/// @author     王超
/// @version    1.0
/// @date       2021/05/20
/// @copyright  (c) 2021-2031 。保留所有权利
////////////////////////////////////////////////////////////////////////
#include "log.h"
#include <vector>
#include <unistd.h>

spd_logger& GetInstance() {
    static spd_logger m_instance;
    return m_instance;
}

spd_logger::spd_logger()
{
    if (::access("logs", 0) == -1) 
    {
       ::mkdir("logs", 0775);
    }

    //设置为异步日志
    //spdlog::set_async_mode(32768);  // 必须为 2 的幂
    std::vector<spdlog::sink_ptr> sinkList;

    if (1)
    {
        /* 输出到标准输出 */
        auto consoleSink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        consoleSink->set_level(spdlog::level::debug);
        //consoleSink->set_pattern("[multi_sink_example] [%^%l%$] %v");
        //consoleSink->set_pattern("[%m-%d %H:%M:%S.%e][%^%L%$]  %v");
        /* 设置打印行号 */
        //consoleSink->set_pattern("%Y-%m-%d %H:%M:%S.%e [%l] thread[%t] - [%s:%# - %!],%v");  /* 输出函数名 */
        consoleSink->set_pattern("%Y-%m-%d %H:%M:%S.%e [%l] T[%t] - [%s:%#],%v");
        sinkList.push_back(consoleSink);
    }
    

    /* 创建回滚日志，每个日志100mb,共三个 */
    //auto dailySink = std::make_shared<spdlog::sinks::daily_file_sink_mt>("logs/log.log", 5, 30);
    auto dailySink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>("logs/mixer.log", 1024 * 1024 * 100, 5);

    dailySink->set_level(spdlog::level::debug);
    sinkList.push_back(dailySink);

    m_logger = std::make_shared<spdlog::logger>("both", begin(sinkList), end(sinkList));
    //register it if you need to access it globally
    spdlog::register_logger(m_logger);

    // 设置日志记录级别
    m_logger->set_level(spdlog::level::debug);

    //设置当触发 err 或更严重的错误时立刻刷新日志到  disk .
    m_logger->flush_on(spdlog::level::warn);

    spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%L] T[%t]-[%s:%#] %v");
    spdlog::flush_every(std::chrono::seconds(2));  /* 两秒刷新日志 */
}

spd_logger::~spd_logger()
{
    spdlog::drop_all();
}


void spd_logger::SetLogeLevel(spdlog::level::level_enum log_level)
{
    m_logger->set_level(log_level);
}


