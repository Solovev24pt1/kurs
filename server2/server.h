/**
 * @file server.h
 * @author Соловьев Арсений Евгеньевич
 * @version 1.0
 * @date 1.12.25
 * @copyright ПГУ ИБСТ
 * @brief Заголовочный файл серверной части клиент-серверного приложения
 * @details Содержит объявления классов для работы сервера: Logger, ClientDB, 
 *          ClientSession и Server. Сервер предназначен для обработки клиентских 
 *          подключений с аутентификацией и вычислениями над векторами данных.
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
#include <limits>

/**
 * @class Logger
 * @brief Класс для ведения журнала событий сервера
 * @details Предоставляет функционал для записи сообщений в файл лога
 *          с временными метками и уровнями важности
 */
 
class Logger {
    std::string log_file_; ///< Имя файла для записи журнала
public:

    /**
     * @brief Конструктор класса Logger
     * @param log_file Имя файла для записи журнала. Если пустая строка,
     *                 сообщения выводятся только на консоль.
     */
     
    Logger(const std::string& log_file = "") : log_file_(log_file) {}
    
    /**
     * @brief Запись сообщения в журнал
     * @param[in] msg Текст сообщения для записи
     * @param[in] critical Флаг критичности сообщения (true для критических ошибок)
     * @details Сообщение записывается в файл лога с временной меткой и уровнем важности.
     *          Если файл лога не указан, сообщение выводится только на консоль.
     */
     
    void log(const std::string& msg, bool critical = false) const;
};

/**
 * @class ClientDB
 * @brief Класс для работы с базой данных клиентов
 * @details Хранит и управляет данными аутентификации клиентов (логины и пароли)
 */
 
class ClientDB {
    std::unordered_map<std::string, std::string> clients_; ///< Хранилище пар логин-пароль
public:

    /**
     * @brief Загрузка базы данных клиентов из файла
     * @param[in] filename Имя файла с базой данных
     * @return true в случае успешной загрузки, false в случае ошибки
     * @details Файл должен содержать пары логин-пароль, разделенные пробелом,
     *          по одной паре на строку
     */
     
    bool load(const std::string& filename);
    
    /**
     * @brief Аутентификация клиента по логину и паролю
     * @param[in] login Логин клиента
     * @param[in] password Пароль клиента
     * @return true если аутентификация успешна, false в противном случае
     * @details Проверяет наличие логина в базе и совпадение пароля
     */
     
    bool auth(const std::string& login, const std::string& password) const;
    
    /**
     * @brief Аутентификация клиента по хешу
     * @param[in] login Логин клиента
     * @param[in] received_hash Полученный хеш от клиента
     * @param[in] salt Соль, использованная для хеширования
     * @return true если аутентификация успешна, false в противном случае
     * @details Вычисляет хеш SHA256 от соли и пароля, сравнивает с полученным хешем
     */
     
    bool authWithHash(const std::string& login, const std::string& received_hash, 
                     const std::string& salt) const;
    
    /**
     * @brief Получение количества клиентов в базе
     * @return Количество клиентов
     */
     
    size_t getClientCount() const { return clients_.size(); }
};

/**
 * @class ClientSession
 * @brief Класс для обработки клиентской сессии
 * @details Обрабатывает одно клиентское подключение: аутентификацию, 
 *          прием данных и отправку результатов
 */
 
class ClientSession {
    int sock_; ///< Дескриптор сокета клиента
    ClientDB& db_; ///< Ссылка на базу данных клиентов
    Logger& logger_; ///< Ссылка на объект логгера
    
    /**
     * @brief Отправка всех данных через сокет
     * @param[in] buf Указатель на данные для отправки
     * @param[in] len Количество байт для отправки
     * @return true в случае успешной отправки всех данных, false в случае ошибки
     */
     
    bool sendAll(const void* buf, size_t len);
    
    /**
     * @brief Прием всех данных через сокет
     * @param[out] buf Указатель на буфер для приема данных
     * @param[in] len Количество байт для приема
     * @return true в случае успешного приема всех данных, false в случае ошибки
     */
     
    bool recvAll(void* buf, size_t len);
    
    /**
     * @brief Аутентификация клиента
     * @return true в случае успешной аутентификации, false в случае ошибки
     * @details Ожидает сообщение аутентификации от клиента, проверяет его
     *          и выполняет аутентификацию через базу данных
     */
     
    bool auth();
    
    /**
     * @brief Обработка векторов данных от клиента
     * @return true в случае успешной обработки, false в случае ошибки
     * @details Принимает векторы целых чисел, вычисляет среднее арифметическое
     *          каждого вектора с проверкой переполнения и отправляет результат обратно
     */
     
    bool processVectors();

public:

    /**
     * @brief Конструктор класса ClientSession
     * @param[in] sock Дескриптор сокета клиента
     * @param[in] db Ссылка на базу данных клиентов
     * @param[in] logger Ссылка на объект логгера
     */
     
    ClientSession(int sock, ClientDB& db, Logger& logger);
    
    /**
     * @brief Запуск обработки клиентской сессии
     * @details Основной метод обработки клиента: выполняет аутентификацию,
     *          затем обрабатывает данные и закрывает соединение
     */
    void run();
};

/**
 * @class Server
 * @brief Основной класс сервера
 * @details Управляет работой сервера: инициализация, запуск, остановка
 *          и обработка клиентских подключений
 */
 
class Server {
    std::string client_db_file_; ///< Имя файла базы клиентов
    std::string log_file_; ///< Имя файла журнала
    std::string address_ = "127.0.0.1"; ///< IP-адрес сервера (по умолчанию localhost)
    int port_ = 0; ///< Порт сервера
    ClientDB db_; ///< Объект базы данных клиентов
    Logger logger_; ///< Объект логгера
    int server_sock_ = -1; ///< Дескриптор серверного сокета
    bool running_ = false; ///< Флаг работы сервера (true - работает, false - остановлен)

public: 

    /**
     * @brief Разбор аргументов командной строки
     * @param[in] argc Количество аргументов командной строки
     * @param[in] argv Массив аргументов командной строки
     * @return true в случае успешного разбора, false в случае ошибки
     * @details Парсит аргументы и устанавливает соответствующие параметры сервера
     */
     
    bool parseArgs(int argc, char* argv[]);

private:

    /**
     * @brief Вывод справки по использованию программы
     * @details Выводит на экран информацию о параметрах командной строки
     */
     
    void printHelp() const {
        std::cout << "Использование: ./server -d db.txt -LU log.txt -a 127.0.0.1 -p 33333" << std::endl;
        std::cout << "Параметры:" << std::endl;
        std::cout << "    -d <file>    Файл базы клиентов (обязательный)" << std::endl;
        std::cout << "    -LU <file>   Файл логов (обязательный)" << std::endl;
        std::cout << "    -a <addr>    IP-адрес для привязки" << std::endl;
        std::cout << "    -p <port>    Порт для прослушивания (обязательный)" << std::endl;
        std::cout << "    -h           Показать эту справку" << std::endl;
    }

public:

    /**
     * @brief Деструктор класса Server
     * @details Останавливает сервер и освобождает ресурсы
     */
     
    ~Server();
    
    /**
     * @brief Инициализация сервера
     * @param[in] argc Количество аргументов командной строки
     * @param[in] argv Массив аргументов командной строки
     * @return true в случае успешной инициализации, false в случае ошибки
     * @details Инициализирует сервер: разбирает аргументы, загружает базу клиентов,
     *          настраивает логгер и проверяет параметры
     */
     
    bool init(int argc, char* argv[]);
    
    /**
     * @brief Запуск сервера
     * @return true в случае успешного запуска, false в случае ошибки
     * @details Создает сокет, привязывает к адресу, начинает прослушивание
     *          и обрабатывает клиентские подключения в бесконечном цикле
     */
     
    bool start();
    
    /**
     * @brief Остановка сервера
     * @details Устанавливает флаг остановки и закрывает серверный сокет
     */
     
    void stop();
};

#endif // SERVER_H
