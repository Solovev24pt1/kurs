#include "server.h"

void Logger::log(const std::string& msg, bool critical) const {
    std::ofstream file(log_file_, std::ios::app);
    if (!file.is_open()) return;

    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    char timestamp[20];
    std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", std::localtime(&t));
    
    file << "[" << timestamp << "] " << (critical ? "CRITICAL" : "INFO") 
         << ": " << msg << std::endl;
}

bool ClientDB::load(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) return false;

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;
        std::istringstream iss(line);
        std::string login, hash;
        if (iss >> login >> hash && hash.length() == 64) {
            clients_[login] = hash;
        }
    }
    return true;
}

bool ClientDB::auth(const std::string& login, const std::string& hash) const {
    auto it = clients_.find(login);
    return it != clients_.end() && it->second == hash;
}

ClientSession::ClientSession(int sock, ClientDB& db, Logger& logger) 
    : sock_(sock), db_(db), logger_(logger) {}

bool ClientSession::sendAll(const void* buf, size_t len) {
    const char* ptr = static_cast<const char*>(buf);
    while (len > 0) {
        ssize_t sent = send(sock_, ptr, len, 0);
        if (sent <= 0) return false;
        ptr += sent;
        len -= sent;
    }
    return true;
}

bool ClientSession::recvAll(void* buf, size_t len) {
    char* ptr = static_cast<char*>(buf);
    while (len > 0) {
        ssize_t received = recv(sock_, ptr, len, 0);
        if (received <= 0) return false;
        ptr += received;
        len -= received;
    }
    return true;
}

bool ClientSession::auth() {
    char buf[1024];
    ssize_t received = recv(sock_, buf, sizeof(buf) - 1, 0);
    if (received <= 0) return false;
    buf[received] = '\0';
    
    char login[50], salt[17], hash[65];
    if (sscanf(buf, "%49s %16s %64s", login, salt, hash) != 3) {
        send(sock_, "ERR", 3, 0);
        return false;
    }
    
    if (!db_.auth(login, hash)) {
        send(sock_, "ERR", 3, 0);
        return false;
    }
    
    send(sock_, "OK", 2, 0);
    logger_.log("Клиент аутентифицирован: " + std::string(login));
    return true;
}

bool ClientSession::processVectors() {
    uint32_t num_vectors;
    if (!recvAll(&num_vectors, sizeof(num_vectors))) return false;
    num_vectors = ntohl(num_vectors);
    
    uint32_t num_results = htonl(num_vectors);
    if (!sendAll(&num_results, sizeof(num_results))) return false;
    
    for (uint32_t i = 0; i < num_vectors; i++) {
        uint32_t size;
        if (!recvAll(&size, sizeof(size))) return false;
        size = ntohl(size);
        
        std::vector<int64_t> data(size);
        if (!recvAll(data.data(), size * sizeof(int64_t))) return false;
        
        int64_t sum = 0;
        for (auto& val : data) {
            val = be64toh(val);
            if (sum > 0 && val > INT64_MAX - sum) sum = INT64_MIN;
            else if (sum < 0 && val < INT64_MIN - sum) sum = INT64_MIN;
            else sum += val;
        }
        int64_t avg = (sum == INT64_MIN) ? INT64_MIN : sum / static_cast<int64_t>(size);
        
        avg = htobe64(avg);
        if (!sendAll(&avg, sizeof(avg))) return false;
    }
    return true;
}

void ClientSession::run() {
    if (!auth()) {
        close(sock_);
        return;
    }
    
    if (processVectors()) {
        logger_.log("Обработка векторов завершена успешно");
    } else {
        logger_.log("Ошибка обработки векторов", false);
    }
    
    close(sock_);
}

Server::~Server() { stop(); }

bool Server::parseArgs(int argc, char* argv[]) {
    if (argc == 1 || (argc == 2 && strcmp(argv[1], "-h") == 0)) {
        printHelp();
        return false;
    }
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-S") == 0 && i + 1 < argc) {
            client_db_file_ = argv[++i];
        } else if (strcmp(argv[i], "-H") == 0 && i + 1 < argc) {
            i++; // Пропускаем параметр хэш-функции
        } else if (strcmp(argv[i], "-T") == 0 && i + 1 < argc) {
            i++; // Пропускаем параметр типа данных
        }
    }
    
    if (client_db_file_.empty()) {
        std::cerr << "Ошибка: не указан файл базы клиентов" << std::endl;
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
    setsockopt(server_sock_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port_);
    
    if (bind(server_sock_, (sockaddr*)&addr, sizeof(addr)) < 0) {
        logger_.log("Ошибка привязки сокета к порту " + std::to_string(port_), true);
        close(server_sock_);
        return false;
    }
    
    if (listen(server_sock_, 10) < 0) {
        logger_.log("Ошибка прослушивания", true);
        close(server_sock_);
        return false;
    }
    
    running_ = true;
    
    std::cout << "Сервер запущен на порту " << port_ << std::endl;
    std::cout << "Ожидание подключений..." << std::endl;
    
    logger_.log("Сервер запущен на порту " + std::to_string(port_));
    
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
        
        std::cout << "Новое соединение от " 
                  << inet_ntoa(client_addr.sin_addr) << ":" 
                  << ntohs(client_addr.sin_port) << std::endl;
        
        logger_.log("Новое соединение от " + 
                   std::string(inet_ntoa(client_addr.sin_addr)) + ":" +
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
