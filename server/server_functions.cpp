#include "server.h"


bool ServerConfig::parseArguments(int argc, char* argv[]) {
    if (argc == 1) {
        printHelp();
        return false;
    }
    
    if (argc == 2 && strcmp(argv[1], "-h") == 0) {
        printHelp();
        return false;
    }
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-S") == 0 && i + 1 < argc) {
            client_db_file_ = argv[++i];
        } else if (strcmp(argv[i], "-H") == 0 && i + 1 < argc) {
            hash_type_ = argv[++i];
        } else if (strcmp(argv[i], "-T") == 0 && i + 1 < argc) {
            data_type_ = argv[++i];
        }
    }
    
    if (client_db_file_.empty()) {
        std::cerr << "Ошибка: не указан файл базы клиентов" << std::endl;
        return false;
    }
    
    return true;
}

// справка
void ServerConfig::printHelp() const {
    std::cout << "Использование: ./server_static -T float -H SHA1 -S client" << std::endl;
    std::cout << "Параметры:" << std::endl;
    std::cout << "  -S <file>    Файл базы клиентов (обязательный)" << std::endl;
    std::cout << "  -H <hash>    Используемая хэш-функция" << std::endl;
    std::cout << "  -T <type>    Тип данных" << std::endl;
    std::cout << "  -h           Показать эту справку" << std::endl;
    std::cout << std::endl << "Сервер всегда работает на порту 33333" << std::endl;
}


bool ClientSession::receiveAuthentication(std::string& login, std::string& salt, std::string& hash) {
    char buffer[1024];
    ssize_t bytes_received = recv(client_socket_, buffer, sizeof(buffer) - 1, 0);
    if (bytes_received <= 0) {
        return false;
    }
    buffer[bytes_received] = '\0';
    
    char login_buf[50], salt_buf[17], hash_buf[65];
    if (sscanf(buffer, "%49s %16s %64s", login_buf, salt_buf, hash_buf) != 3) {
        return false;
    }
    
    login = login_buf;
    salt = salt_buf;
    hash = hash_buf;
    
    return true;
}

bool ClientSession::authenticate() {
    std::string login, salt, received_hash;
    
    if (!receiveAuthentication(login, salt, received_hash)) {
        send(client_socket_, "ERR", 3, 0);
        return false;
    }
    
    if (salt.length() != 16) {
        send(client_socket_, "ERR", 3, 0);
        return false;
    }
    
    if (client_db_.authenticate(login, received_hash)) {
        send(client_socket_, "OK", 2, 0);
        logger_.log("Клиент " + login + " аутентифицирован", false);
        return true;
    } else {
        send(client_socket_, "ERR", 3, 0);
        logger_.log("Ошибка аутентификации для клиента " + login, false);
        return false;
    }
}

bool ClientSession::processVectors() {
    uint32_t num_vectors;
    
    if (!NetworkUtils::recvAll(client_socket_, &num_vectors, sizeof(num_vectors))) {
        return false;
    }
    
    num_vectors = NetworkUtils::networkToHost(num_vectors);
    
    uint32_t num_results = num_vectors;
    uint32_t num_results_net = NetworkUtils::hostToNetwork(num_results);
    
    if (!NetworkUtils::sendAll(client_socket_, &num_results_net, sizeof(num_results_net))) {
        return false;
    }
    
    for (uint32_t i = 0; i < num_vectors; i++) {
        uint32_t vector_size;
        
        if (!NetworkUtils::recvAll(client_socket_, &vector_size, sizeof(vector_size))) {
            return false;
        }
        vector_size = NetworkUtils::networkToHost(vector_size);
        
        Vector vector;
        std::vector<int64_t> data(vector_size);
        
        if (!NetworkUtils::recvAll(client_socket_, data.data(), vector_size * sizeof(int64_t))) {
            return false;
        }
        
        for (uint32_t j = 0; j < vector_size; j++) {
            data[j] = NetworkUtils::networkToHost(data[j]);
        }
        
        vector.setData(data);
        int64_t average = VectorProcessor::calculateAverage(vector);
        
        average = NetworkUtils::hostToNetwork(average);
        if (!NetworkUtils::sendAll(client_socket_, &average, sizeof(average))) {
            return false;
        }
    }
    
    return true;
}

void ClientSession::run() {
    if (authenticate()) {
        if (processVectors()) {
            logger_.log("Обработка векторов завершена успешно", false);
        } else {
            logger_.log("Ошибка обработки векторов", false);
        }
    }
}


bool Server::initialize(int argc, char* argv[]) {
    if (!config_.parseArguments(argc, argv)) {
        return false;
    }
    
    logger_.setLogFile(config_.getLogFile());
    
    if (!client_db_.loadFromFile(config_.getClientDbFile())) {
        std::cerr << "Ошибка загрузки базы клиентов" << std::endl;
        return false;
    }
    
    std::cout << "Загружено " << client_db_.getClientCount() 
              << " клиентов из базы данных" << std::endl;
    
    return true;
}

bool Server::createSocket() {
    server_socket_ = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket_ < 0) {
        logger_.log("Ошибка создания сокета", true);
        return false;
    }
    
    int opt = 1;
    if (setsockopt(server_socket_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        logger_.log("Ошибка setsockopt", true);
        close(server_socket_);
        return false;
    }
    
    return true;
}

bool Server::bindSocket() {
    sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(config_.getPort());
    
    if (bind(server_socket_, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        logger_.log("Ошибка привязки сокета", true);
        close(server_socket_);
        return false;
    }
    
    return true;
}

bool Server::listenForConnections() {
    if (listen(server_socket_, 10) < 0) {
        logger_.log("Ошибка прослушивания", true);
        close(server_socket_);
        return false;
    }
    
    return true;
}

void Server::handleClient(int client_socket) {
    sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    getpeername(client_socket, (struct sockaddr*)&client_addr, &client_len);
    
    std::cout << "Новое соединение от " << inet_ntoa(client_addr.sin_addr) 
              << ":" << ntohs(client_addr.sin_port) << std::endl;
    
    ClientSession session(client_socket, client_db_, logger_);
    session.run();
    
    close(client_socket);
    std::cout << "Соединение закрыто" << std::endl;
}

bool Server::start() {
    if (!createSocket() || !bindSocket() || !listenForConnections()) {
        return false;
    }
    
    std::cout << "Сервер запущен на порту " << config_.getPort() << std::endl;
    logger_.log("Сервер запущен", false);
    
    running_ = true;
    
    while (running_) {
        sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int client_socket = accept(server_socket_, (struct sockaddr *)&client_addr, &client_len);
        if (client_socket < 0) {
            if (running_) {
                logger_.log("Ошибка принятия соединения", false);
            }
            continue;
        }
        
        handleClient(client_socket);
    }
    
    return true;
}

void Server::stop() {
    running_ = false;
    if (server_socket_ != -1) {
        close(server_socket_);
        server_socket_ = -1;
    }
    logger_.log("Сервер остановлен", false);
}
