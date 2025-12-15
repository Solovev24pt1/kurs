/**
 * @file main.cpp
 * @author Соловьев Арсений Евгеньевич
 * @version 1.0
 * @date 1.12.25
 * @copyright ПГУ ИБСТ
 * @brief Основной файл серверного приложения
 */

#include "server.h"

/**
 * @brief Точка входа в программу
 * @param argc Количество аргументов командной строки
 * @param argv Массив аргументов командной строки
 * @return Код завершения программы (0 - успешно, 1 - ошибка)
 * @details Инициализирует и запускает сервер
 */
 
int main(int argc, char* argv[]) {
    Server server;
    
    if (!server.init(argc, argv)) {
        return 1;
    }
    
    if (!server.start()) {
        return 1;
    }
    
    return 0;
}
