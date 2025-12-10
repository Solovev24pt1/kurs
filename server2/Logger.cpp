/**
 * @file Logger.cpp
 * @author Соловьев Арсений Евгеньевич
 * @date 01.12.2025
 * @copyright ПГУ
 * @brief Реализация класса Logger
 * @details Методы записи логов с временными метками.
 */

#include "server.h"
#include <fstream>
#include <chrono>
#include <ctime>

/**
 * @brief Запись сообщения в лог
 * @param msg Текст сообщения
 * @param critical Флаг критичности (true — критическая ошибка)
 */
 
void Logger::log(const std::string& msg, bool critical) const {
    if (log_file_.empty()) {
        std::cout << msg << std::endl;
        return;
    }
    
    std::ofstream file(log_file_, std::ios::app);
    if (!file.is_open()) return;

    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    char timestamp[20];
    std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", std::localtime(&t));
    
    file << "[" << timestamp << "] " << (critical ? "CRITICAL" : "INFO") 
         << ": " << msg << std::endl;
}
