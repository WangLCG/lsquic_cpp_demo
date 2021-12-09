////////////////////////////////////////////////////////////////////////
/// @file       log.h
/// @brief      日志类声明文件
/// @details    日志类声明文件
/// @author     王超
/// @version    1.0
/// @date       2021/05/20
/// @copyright  (c) 2021-2031 。保留所有权利
////////////////////////////////////////////////////////////////////////
#pragma once

#include <string>
#include <memory>
#include "spdlog.h"
#include "sinks/daily_file_sink.h"
#include "sinks/stdout_color_sinks.h"
#include "sinks/rotating_file_sink.h"

using namespace std;

class spd_logger
{
public:
        spd_logger();
        ~spd_logger();
        
        std::shared_ptr<spdlog::logger> GetLogger()
        {
            return m_logger;
        }

        void SetLogeLevel(spdlog::level::level_enum log_level);
        
        spd_logger(const spd_logger&) = delete;
        spd_logger& operator=(const spd_logger&) = delete;
        
private:
        std::shared_ptr<spdlog::logger> m_logger;

};

spd_logger& GetInstance();

#define SPDLOG_LOGGER_CALL_(level, ...) GetInstance().GetLogger()->log(spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION}, level, __VA_ARGS__)
#define SPDLOG_SET_LEVEL(level) GetInstance().GetLogger()->set_level(level)

#define LOG_TRACE(...)  SPDLOG_LOGGER_CALL_(spdlog::level::trace,__VA_ARGS__)
#define LOG_DEBUG(...)  SPDLOG_LOGGER_CALL_(spdlog::level::debug,__VA_ARGS__)
#define LOG_INFO(...)   SPDLOG_LOGGER_CALL_(spdlog::level::info,__VA_ARGS__)
#define LOG_WARN(...)   SPDLOG_LOGGER_CALL_(spdlog::level::warn,__VA_ARGS__)
#define LOG_ERROR(...)  SPDLOG_LOGGER_CALL_(spdlog::level::err,__VA_ARGS__)
#define LOG_CRITICAL(...) SPDLOG_LOGGER_CALL_(spdlog::level::critical,__VA_ARGS__)

#define LogCriticalIf(b, ...)               \
    do {                  \
            if ((b)) {                    \
             SPDLOG_LOGGER_CALL_(spdlog::level::critical,__VA_ARGS__); \
        }                                      \
    } while (0)


