/**
 * @file server.cpp
 * @author Соловьев Арсений Евгеньевич
 * @version 1.0
 * @date 1.12.25
 * @copyright ПГУ ИБСТ
 * @brief Реализация класса Server
 */

#include "server.h"
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>

/**
 * @brief Деструктор класса Server
 * @details Останавливает сервер и освобождает ресурсы.
 */
 
Server::~Server() { stop(); }

/**
 * @brief Разбирает аргументы командной строки
 * @param argc Количество аргументов
 * @param argv Массив аргументов
 * @return true в случае успешного разбора, false в случае ошибки
 * @details Поддерживает параметры: -d (файл базы), -LU (файл логов),
 *          -a (адрес), -p (порт), -h (справка).
 */
 
bool Server::parseArgs(int argc, char* argv[]) {
    if (argc == 1 || (argc == 2 && strcmp(argv[1], "-h") == 0)) {
        printHelp();
        return false;
    }
    
    bool port_specified = false;
    bool address_specified = false;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
            client_db_file_ = argv[++i];
        } else if (strcmp(argv[i], "-LU") == 0 && i + 1 < argc) {
            log_file_ = argv[++i];
        } else if (strcmp(argv[i], "-a") == 0 && i + 1 < argc) {
            address_ = argv[++i];
            address_specified = true;
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            port_specified = true;
            try {
                int port = std::stoi(argv[++i]);
                if (port < 1 || port > 65535) {
                    std::cerr << "Ошибка: неверный порт" << std::endl;
                    return false;
                }
                port_ = port;
            } catch (const std::exception& e) {
                std::cerr << "Ошибка: неверный формат порта" << std::endl;
                return false;
            }
        }
    }
    
    if (client_db_file_.empty()) {
        std::cerr << "Ошибка: не указан файл базы клиентов" << std::endl;
        printHelp();
        return false;
    }
    
    if (log_file_.empty()) {
        std::cerr << "Ошибка: не указан файл логов" << std::endl;
        printHelp();
        return false;
    }
    
    if (!address_specified) {
        address_ = "127.0.0.1";
    }
    
    if (!port_specified) {
        std::cerr << "Ошибка: не указан порт (параметр -p)" << std::endl;
        printHelp();
        return false;
    }
    
    return true;
}

/**
 * @brief Инициализирует сервер
 * @param argc Количество аргументов
 * @param argv Массив аргументов
 * @return true в случае успешной инициализации, false в случае ошибки
 * @details Выполняет разбор аргументов, проверку порта, инициализацию логгера
 *          и загрузку базы данных клиентов.
 */
 
bool Server::init(int argc, char* argv[]) {
    if (!parseArgs(argc, argv)) return false;
    
    if (port_ < 1 || port_ > 65535) {
        std::cerr << "Ошибка: некорректный порт " << port_ << ". Должен быть в диапазоне 1-65535" << std::endl;
        return false;
    }
    
    logger_ = Logger(log_file_);
    
    if (!db_.load(client_db_file_)) {
        logger_.log("Ошибка загрузки базы клиентов: " + client_db_file_, true);
        return false;
    }
    
    std::cout << "Загружено клиентов: " << db_.getClientCount() << std::endl;
    
    return true;
}

/**
 * @brief Запускает сервер
 * @return true в случае успешного запуска, false в случае ошибки
 * @details Создает TCP-сокет, привязывает к адресу, начинает прослушивание
 *          и обрабатывает клиентские подключения в бесконечном цикле.
 */
 
bool Server::start() {
    server_sock_ = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock_ < 0) {
        logger_.log("Ошибка создания сокета", true);
        return false;
    }
    
    int opt = 1;
    if (setsockopt(server_sock_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        logger_.log("Ошибка установки SO_REUSEADDR", false);
    }
    
    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port_);
    
    if (inet_pton(AF_INET, address_.c_str(), &addr.sin_addr) <= 0) {
        logger_.log("Ошибка преобразования адреса: " + address_, true);
        close(server_sock_);
        return false;
    }
    
    if (bind(server_sock_, (sockaddr*)&addr, sizeof(addr)) < 0) {
        logger_.log("Ошибка привязки сокета к адресу " + address_ + ":" + std::to_string(port_), true);
        close(server_sock_);
        return false;
    }
    
    if (listen(server_sock_, 10) < 0) {
        logger_.log("Ошибка прослушивания", true);
        close(server_sock_);
        return false;
    }
    
    running_ = true;
    
    std::cout << "Сервер запущен на " << address_ << ":" << port_ << std::endl;
    std::cout << "Ожидание подключений..." << std::endl;
    
    logger_.log("Сервер запущен на " + address_ + ":" + std::to_string(port_));
    
    while (running_) {
        sockaddr_in client_addr;
        socklen_t len = sizeof(client_addr);
        int client_sock = accept(server_sock_, (sockaddr*)&client_addr, &len);
        
        if (client_sock < 0) {
            if (running_) {
                logger_.log("Ошибка принятия соединения", false);
            }
            continue;
        }
        
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
        
        std::cout << "Новое соединение от " 
                  << client_ip << ":" 
                  << ntohs(client_addr.sin_port) << std::endl;
        
        logger_.log("Новое соединение от " + 
                   std::string(client_ip) + ":" +
                   std::to_string(ntohs(client_addr.sin_port)));
        
        ClientSession session(client_sock, db_, logger_);
        session.run();
        
        std::cout << "Соединение закрыто" << std::endl;
    }
    
    return true;
}

/**
 * @brief Останавливает сервер
 * @details Устанавливает флаг остановки и закрывает серверный сокет.
 */
 
void Server::stop() {
    running_ = false;
    if (server_sock_ != -1) {
        close(server_sock_);
        server_sock_ = -1;
    }
    logger_.log("Сервер остановлен");
}
