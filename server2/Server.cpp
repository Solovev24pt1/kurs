#include "server.h"
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>

Server::~Server() { stop(); }

bool Server::parseArgs(int argc, char* argv[]) {
    if (argc == 1 || (argc == 2 && strcmp(argv[1], "-h") == 0)) {
        printHelp();
        return false;
    }
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
            client_db_file_ = argv[++i];
        } else if (strcmp(argv[i], "-LU") == 0 && i + 1 < argc) {
            log_file_ = argv[++i];
        } else if (strcmp(argv[i], "-a") == 0 && i + 1 < argc) {
            address_ = argv[++i];
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            int port = std::stoi(argv[++i]);
            if (port != 33333) {
                std::cerr << "Ошибка: указан порт " << port << ", но сервер работает только на порту 33333" << std::endl;
                return false;
            }
          
        } else if (strcmp(argv[i], "-p") == 0) {
            std::cerr << "Ошибка: для параметра -p не указано значение" << std::endl;
            return false;
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
    
    return true;
}

bool Server::init(int argc, char* argv[]) {
    if (!parseArgs(argc, argv)) return false;
    
    logger_ = Logger(log_file_);
    
    if (!db_.load(client_db_file_)) {
        logger_.log("Ошибка загрузки базы клиентов: " + client_db_file_, true);
        return false;
    }
    
    std::cout << "Загружено клиентов: " << db_.getClientCount() << std::endl;
    
    return true;
}

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

void Server::stop() {
    running_ = false;
    if (server_sock_ != -1) {
        close(server_sock_);
        server_sock_ = -1;
    }
    logger_.log("Сервер остановлен");
}
