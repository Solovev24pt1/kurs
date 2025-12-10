/**
 * @file server.h
 * @author Соловьев Арсений Евгеньевич
 * @date 01.12.2025
 * @copyright ПГУ
 * @brief Заголовочный файл серверного приложения
 * @details Объявления классов Logger, ClientDB, ClientSession и Server.
 */

#ifndef SERVER_H
#define SERVER_H

#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <chrono>
#include <ctime>
#include <cstdint>
#include <cstring>
#include <unordered_map>
#include <algorithm>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <iomanip>

/**
 * @brief Класс для логирования событий сервера
 * @details Записывает сообщения в файл логов с временной меткой и уровнем критичности.
 */
class Logger {
    std::string log_file_; ///< Имя файла для записи логов
public:
    /**
     * @brief Конструктор класса Logger
     * @param log_file Имя файла логов (по умолчанию пустая строка — вывод в консоль)
     */
    Logger(const std::string& log_file = "") : log_file_(log_file) {}
    
    /**
     * @brief Запись сообщения в лог
     * @param msg Текст сообщения
     * @param critical Флаг критичности (true — критическая ошибка)
     */
    void log(const std::string& msg, bool critical = false) const;
};

/**
 * @brief Класс для работы с базой данных клиентов
 * @details Загружает пары логин-пароль из файла и выполняет аутентификацию.
 */
class ClientDB {
    std::unordered_map<std::string, std::string> clients_; ///< Хранилище клиентов
public:
    /**
     * @brief Загрузка базы клиентов из файла
     * @param filename Имя файла с базой
     * @return true — успешно, false — ошибка
     */
    bool load(const std::string& filename);
    
    /**
     * @brief Аутентификация по логину и паролю
     * @param login Логин клиента
     * @param password Пароль клиента
     * @return true — аутентификация успешна, false — ошибка
     */
    bool auth(const std::string& login, const std::string& password) const;
    
    /**
     * @brief Аутентификация с использованием хеша
     * @param login Логин клиента
     * @param received_hash Полученный хеш от клиента
     * @param salt Соль, использованная при хешировании
     * @return true — аутентификация успешна, false — ошибка
     */
    bool authWithHash(const std::string& login, const std::string& received_hash, const std::string& salt) const;
    
    /**
     * @brief Получение количества клиентов в базе
     * @return Количество загруженных клиентов
     */
    size_t getClientCount() const { return clients_.size(); }
};

/**
 * @brief Класс сессии с клиентом
 * @details Обрабатывает аутентификацию и обмен данными с одним клиентом.
 */
class ClientSession {
    int sock_;        ///< Сокет соединения с клиентом
    ClientDB& db_;    ///< Ссылка на базу клиентов
    Logger& logger_;  ///< Ссылка на логгер
    
    bool sendAll(const void* buf, size_t len);
    bool recvAll(void* buf, size_t len);
    bool auth();
    bool processVectors();

public:
    /**
     * @brief Конструктор сессии
     * @param sock Сокет соединения
     * @param db База клиентов
     * @param logger Логгер
     */
    ClientSession(int sock, ClientDB& db, Logger& logger);
    
    /**
     * @brief Запуск сессии
     * @details Выполняет аутентификацию и обработку данных клиента.
     */
    void run();
};

/**
 * @brief Основной класс сервера
 * @details Управляет запуском, остановкой и обработкой входящих соединений.
 */
class Server {
    std::string client_db_file_; ///< Файл базы клиентов
    std::string log_file_;       ///< Файл логов
    std::string address_ = "127.0.0.1"; ///< IP-адрес сервера
    ClientDB db_;                ///< База клиентов
    Logger logger_;              ///< Логгер
    int server_sock_ = -1;       ///< Сокет сервера
    bool running_ = false;       ///< Флаг работы сервера

public: 
    /**
     * @brief Разбор аргументов командной строки
     * @param argc Количество аргументов
     * @param argv Массив аргументов
     * @return true — успешно, false — ошибка
     */
    bool parseArgs(int argc, char* argv[]);

private:
    /**
     * @brief Вывод справки по использованию программы
     */
    void printHelp() const {
        std::cout << "Использование: ./server -d db.txt -LU log.txt -a 127.0.0.1 -p 33333" << std::endl;
        std::cout << "Параметры:" << std::endl;
        std::cout << "  -d <file>    Файл базы клиентов (обязательный)" << std::endl;
        std::cout << "  -LU <file>   Файл логов (обязательный)" << std::endl;
        std::cout << "  -a <addr>    IP-адрес для привязки" << std::endl;
        std::cout << "  -h           Показать эту справку" << std::endl;
    }

public:
    /**
     * @brief Деструктор сервера
     * @details Останавливает сервер при уничтожении объекта.
     */
    ~Server();
    
    /**
     * @brief Инициализация сервера
     * @param argc Количество аргументов
     * @param argv Массив аргументов
     * @return true — успешно, false — ошибка
     */
    bool init(int argc, char* argv[]);
    
    /**
     * @brief Запуск сервера
     * @return true — сервер запущен, false — ошибка
     */
    bool start();
    
    /**
     * @brief Остановка сервера
     */
    void stop();
};

#endif
