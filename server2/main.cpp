/**
 * @file main.cpp
 * @author Соловьев Арсений Евгеньевич
 * @date 01.12.2025
 * @copyright ПГУ
 * @brief Главный модуль серверного приложения
 * @details Точка входа в программу. Создаёт и запускает экземпляр сервера.
 */

#include "server.h"

/**
 * @brief Главная функция программы
 * @param argc Количество аргументов командной строки
 * @param argv Массив строк аргументов командной строки
 * @return Код завершения программы (0 — успех, иначе — ошибка)
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
