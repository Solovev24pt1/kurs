/**
 * @file Logger.cpp
 * @author Соловьев Арсений Евгеньевич
 * @version 1.0
 * @date 1.12.25
 * @copyright ПГУ ИБСТ
 * @brief Реализация класса Logger для ведения журнала событий
 */

#include "server.h"
#include <fstream>
#include <chrono>
#include <ctime>

/**
 * @brief Записывает сообщение в журнал
 * @param msg Текст сообщения для записи
 * @param critical Флаг критичности сообщения (true для критических ошибок)
 * @details Записывает сообщение в файл журнала с временной меткой и уровнем важности.
 *          Если файл лога не указан, сообщение выводится только на консоль.
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
