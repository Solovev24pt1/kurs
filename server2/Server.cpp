/**
 * @file server.cpp
 * @author Соловьев Арсений Евгеньевич
 * @date 01.12.2025
 * @copyright ПГУ
 * @brief Реализация класса Server
 * @details Методы инициализации, запуска и остановки сервера.
 */

#include "server.h"
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/stat.h>

/**
 * @brief Деструктор Server
 */
Server::~Server() { stop(); }

/**
 * @brief Разбор аргументов командной строки
 * @param argc Количество аргументов
 * @param argv Массив аргументов
 * @return true — успешно, false — ошибка
 */
bool Server::parseArgs(int argc, char* argv[]) {
    if (argc == 1 || (argc == 2 && strcmp(argv[1], "-h") == 0)) {
        printHelp();
        return false;
    }
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0) {
            if (i + 1 < argc) {
                client_db_file_ = argv[++i];
            } else {
                std::cerr << "Ошибка: для параметра -d не указан файл базы клиентов" << std::endl;
                return false;
            }
        } else if (strcmp(argv[i], "-LU") == 0) {
            if (i + 1 < argc) {
                std::string log_file = argv[++i];
                if (log_file != "log.txt") {
                    std::cerr << "Ошибка: файл логов должен называться 'log.txt', указан '" << log_file << "'" << std::endl;
                    return false;
                }
                log_file_ = log_file;
            } else {
                std::cerr << "Ошибка: для параметра -LU не указан файл логов" << std::endl;
                return false;
            }
        } else if (strcmp(argv[i], "-a") == 0) {
            if (i + 1 < argc) {
                address_ = argv[++i];
            } else {
                std::cerr << "Ошибка: для параметра -a не указан IP-адрес" << std::endl;
                return false;
            }
        } else if (strcmp(argv[i], "-p") == 0) {
            if (i + 1 < argc) {
                try {
                    int port = std::stoi(argv[++i]);
                    if (port != 33333) {
                        std::cerr << "Ошибка: указан порт " << port << ", но сервер работает только на порту 33333" << std::endl;
                        return false;
                    }
                    
                } catch (const std::exception& e) {
                    std::cerr << "Ошибка: неверный формат порта '" << argv[i] << "'" << std::endl;
                    return false;
                }
            } else {
                std::cerr << "Ошибка: для параметра -p не указан номер порта" << std::endl;
                return false;
            }
        } else {
            std::cerr << "Ошибка: неизвестный параметр '" << argv[i] << "'" << std::endl;
            printHelp();
            return false;
        }
    }
    
    if (client_db_file_.empty()) {
        std::cerr << "Ошибка: не указан файл базы клиентов (параметр -d)" << std::endl;
        printHelp();
        return false;
    }
    
    if (log_file_.empty()) {
        std::cerr << "Ошибка: не указан файл логов (параметр -LU)" << std::endl;
        printHelp();
        return false;
    }
    
    return true;
}

/**
 * @brief Инициализация сервера
 * @param argc Количество аргументов
 * @param argv Массив аргументов
 * @return true — успешно, false — ошибка
 */
bool Server::init(int argc, char* argv[]) {
    if (!parseArgs(argc, argv)) return false;
    
    std::ofstream log_test(log_file_, std::ios::app);
    if (!log_test.is_open()) {
        std::cerr << "Ошибка: невозможно открыть файл логов '" << log_file_ << "' для записи" << std::endl;
        return false;
    }
    log_test.close();
    
    logger_ = Logger(log_file_);
    
    if (!db_.load(client_db_file_)) {
        std::cerr << "Ошибка: невозможно загрузить файл базы клиентов '" << client_db_file_ << "'" << std::endl;
        logger_.log("Ошибка загрузки базы клиентов: " + client_db_file_, true);
        return false;
    }
    
    std::cout << "Загружено клиентов: " << db_.getClientCount() << std::endl;
    
    return true;
}

/**
 * @brief Запуск сервера
 * @return true — сервер запущен, false — ошибка
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
    addr.sin_port = htons(33333);
    
    if (inet_pton(AF_INET, address_.c_str(), &addr.sin_addr) <= 0) {
        logger_.log("Ошибка преобразования адреса: " + address_, true);
        close(server_sock_);
        return false;
    }
    
    if (bind(server_sock_, (sockaddr*)&addr, sizeof(addr)) < 0) {
        logger_.log("Ошибка привязки сокета к адресу " + address_ + ":33333", true);
        close(server_sock_);
        return false;
    }
    
    if (listen(server_sock_, 10) < 0) {
        logger_.log("Ошибка прослушивания", true);
        close(server_sock_);
        return false;
    }
    
    running_ = true;
    
    std::cout << "Сервер запущен на " << address_ << ":33333" << std::endl;
    std::cout << "Ожидание подключений..." << std::endl;
    
    logger_.log("Сервер запущен на " + address_ + ":33333");
    
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
 * @brief Остановка сервера
 */
void Server::stop() {
    running_ = false;
    if (server_sock_ != -1) {
        close(server_sock_);
        server_sock_ = -1;
    }
    logger_.log("Сервер остановлен");
}
