#include "server.h"
#include <endian.h>
#include <cctype>

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

bool ClientDB::load(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Ошибка открытия файла базы данных: " << filename << std::endl;
        return false;
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;
        std::istringstream iss(line);
        std::string login, password;
        if (iss >> login >> password) {
            clients_[login] = password;
            std::cout << "Загружен клиент: " << login << std::endl;
        }
    }
    return true;
}

bool ClientDB::auth(const std::string& login, const std::string& password) const {
    auto it = clients_.find(login);
    if (it == clients_.end()) {
        std::cout << "Клиент не найден: " << login << std::endl;
        return false;
    }
    
    bool result = (it->second == password);
    std::cout << "Аутентификация " << login << ": " << (result ? "УСПЕХ" : "НЕУДАЧА") << std::endl;
    return result;
}

bool ClientDB::authWithHash(const std::string& login, const std::string& received_hash, const std::string& salt) const {
    auto it = clients_.find(login);
    if (it == clients_.end()) {
        std::cout << "Клиент не найден в базе: '" << login << "'" << std::endl;
        std::cout << "Доступные логины в базе:" << std::endl;
        for (const auto& client : clients_) {
            std::cout << "  '" << client.first << "'" << std::endl;
        }
        return false;
    }
    
    std::string password = it->second;
    std::cout << "Найден пароль для логина '" << login << "': '" << password << "'" << std::endl;
    
    // Вычисляем ожидаемый хеш: SHA256(salt + password)
    std::string data = salt + password;
    
    std::cout << "Соль (hex): ";
    for (char c : salt) {
        printf("%02x", (unsigned char)c);
    }
    std::cout << std::endl;
    
    std::cout << "Данные для хеширования (соль+пароль): '";
    for (char c : data) {
        if (std::isprint((unsigned char)c)) {
            std::cout << c;
        } else {
            printf("\\x%02x", (unsigned char)c);
        }
    }
    std::cout << "'" << std::endl;
    std::cout << "Длина данных: " << data.length() << std::endl;
    
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)data.c_str(), data.length(), hash);
    
    // Конвертируем в hex строку
    std::stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    std::string expected_hash = ss.str();
    
    // Приводим к нижнему регистру для сравнения
    std::transform(expected_hash.begin(), expected_hash.end(), expected_hash.begin(), ::tolower);
    std::string received_hash_lower = received_hash;
    std::transform(received_hash_lower.begin(), received_hash_lower.end(), received_hash_lower.begin(), ::tolower);
    
    std::cout << "Ожидаемый хеш:  " << expected_hash << std::endl;
    std::cout << "Полученный хеш: " << received_hash_lower << std::endl;
    std::cout << "Длина ожидаемого хеша: " << expected_hash.length() << std::endl;
    std::cout << "Длина полученного хеша: " << received_hash_lower.length() << std::endl;
    
    bool result = (expected_hash == received_hash_lower);
    std::cout << "Аутентификация '" << login << "': " << (result ? "УСПЕХ" : "НЕУДАЧА") << std::endl;
    
    if (!result) {
        std::cout << "Хеши не совпадают!" << std::endl;
        // Выводим различия
        for (size_t i = 0; i < std::min(expected_hash.length(), received_hash_lower.length()); i++) {
            if (expected_hash[i] != received_hash_lower[i]) {
                std::cout << "Первое отличие на позиции " << i << ": ожидалось '" << expected_hash[i] 
                         << "', получено '" << received_hash_lower[i] << "'" << std::endl;
                break;
            }
        }
    }
    
    return result;
}

ClientSession::ClientSession(int sock, ClientDB& db, Logger& logger) 
    : sock_(sock), db_(db), logger_(logger) {}

bool ClientSession::sendAll(const void* buf, size_t len) {
    const char* ptr = static_cast<const char*>(buf);
    while (len > 0) {
        ssize_t sent = send(sock_, ptr, len, 0);
        if (sent <= 0) {
            logger_.log("Ошибка отправки данных", false);
            return false;
        }
        ptr += sent;
        len -= sent;
    }
    return true;
}

bool ClientSession::recvAll(void* buf, size_t len) {
    char* ptr = static_cast<char*>(buf);
    while (len > 0) {
        ssize_t received = recv(sock_, ptr, len, 0);
        if (received <= 0) {
            logger_.log("Ошибка приема данных", false);
            return false;
        }
        ptr += received;
        len -= received;
    }
    return true;
}

bool ClientSession::auth() {
    char buf[1024];
    ssize_t received = recv(sock_, buf, sizeof(buf) - 1, 0);
    if (received <= 0) {
        logger_.log("Ошибка приема данных аутентификации", false);
        return false;
    }
    buf[received] = '\0';
    
    std::string message(buf, received);
    std::cout << "Получено сообщение аутентификации: " << message << std::endl;
    std::cout << "Длина сообщения: " << message.length() << std::endl;
    
    // Проверяем минимальную длину (user + соль 16 + хеш 64 = 84 байта)
    if (message.length() < 84) {
        logger_.log("Неверная длина сообщения аутентификации: " + std::to_string(message.length()), false);
        send(sock_, "ERR", 3, 0);
        return false;
    }
    
    // Проверяем, что сообщение начинается с "user"
    if (message.substr(0, 4) != "user") {
        logger_.log("Сообщение не начинается с 'user'", false);
        send(sock_, "ERR", 3, 0);
        return false;
    }
    
    // Извлекаем логин, соль и хеш
    std::string login = "user";  // фиксированный логин
    std::string salt = message.substr(4, 16);
    std::string received_hash = message.substr(20, 64);
    
    std::cout << "Логин: '" << login << "', Длина логина: " << login.length() << std::endl;
    std::cout << "Соль: " << salt << ", Длина соли: " << salt.length() << std::endl;
    std::cout << "Полученный хеш: " << received_hash << ", Длина хеша: " << received_hash.length() << std::endl;
    
    // Проверяем что соль и хеш содержат только hex символы
    auto is_hex = [](const std::string& str) {
        for (char c : str) {
            if (!std::isxdigit(c)) return false;
        }
        return true;
    };
    
    if (!is_hex(salt) || salt.length() != 16) {
        logger_.log("Неверный формат соли", false);
        send(sock_, "ERR", 3, 0);
        return false;
    }
    
    if (!is_hex(received_hash) || received_hash.length() != 64) {
        logger_.log("Неверный формат хеша", false);
        send(sock_, "ERR", 3, 0);
        return false;
    }
    
    // Используем метод для аутентификации с хешем
    if (!db_.authWithHash(login, received_hash, salt)) {
        logger_.log("Аутентификация не удалась для: " + login, false);
        send(sock_, "ERR", 3, 0);
        return false;
    }
    
    send(sock_, "OK", 2, 0);
    logger_.log("Клиент аутентифицирован: " + login);
    return true;
}

bool ClientSession::processVectors() {
    // Принимаем количество векторов (4 байта)
    uint32_t num_vectors;
    if (!recvAll(&num_vectors, sizeof(uint32_t))) {
        logger_.log("Ошибка приема количества векторов", false);
        return false;
    }
    
    // Конвертируем из little-endian
    num_vectors = le32toh(num_vectors);
    
    std::cout << "Обработка " << num_vectors << " векторов" << std::endl;
    
    if (num_vectors == 0) {
        logger_.log("Получено 0 векторов", false);
        return false;
    }
    
    if (num_vectors > 100) {
        logger_.log("Слишком большое количество векторов: " + std::to_string(num_vectors), false);
        return false;
    }
    
   
    
    for (uint32_t i = 0; i < num_vectors; i++) {
        std::cout << "=== Обработка вектора " << i + 1 << " ===" << std::endl;
        
        // Принимаем размер вектора (4 байта)
        uint32_t size;
        if (!recvAll(&size, sizeof(uint32_t))) {
            logger_.log("Ошибка приема размера вектора " + std::to_string(i + 1), false);
            return false;
        }
        
        // Конвертируем размер вектора из little-endian
        size = le32toh(size);
        
        std::cout << "Размер вектора " << i + 1 << ": " << size << std::endl;
        
        if (size == 0) {
            // Для пустого вектора отправляем 0 (8 байт)
            int64_t result = 0;
            result = htole64(result);
            if (!sendAll(&result, sizeof(int64_t))) {
                logger_.log("Ошибка отправки результата для пустого вектора", false);
                return false;
            }
            std::cout << "Пустой вектор " << i + 1 << ", результат: 0" << std::endl;
            continue;
        }
        
        if (size > 100000) {
            logger_.log("Слишком большой размер вектора: " + std::to_string(size), false);
            return false;
        }
        
        // Выделяем память для данных вектора
        std::vector<int64_t> data(size);
        
        // Принимаем данные вектора (size * 8 байт)
        size_t total_bytes = size * sizeof(int64_t);
        std::cout << "Ожидается " << total_bytes << " байт данных для вектора " << i + 1 << std::endl;
        
        if (!recvAll(data.data(), total_bytes)) {
            logger_.log("Ошибка приема данных вектора " + std::to_string(i + 1) + 
                       ", ожидалось " + std::to_string(total_bytes) + " байт", false);
            return false;
        }
        
        // Конвертируем все элементы из little-endian
        for (auto& val : data) {
            val = le64toh(val);
        }
        
        // Вычисляем сумму
        int64_t sum = 0;
        for (const auto& val : data) {
            sum += val;
        }
        
        // Вычисляем среднее арифметическое
        int64_t avg = sum / static_cast<int64_t>(size);
        
        // Детальный вывод для отладки
        std::cout << "Вектор " << i + 1 << " данные: ";
        for (size_t j = 0; j < size; j++) {
            std::cout << data[j];
            if (j < size - 1) std::cout << ", ";
        }
        std::cout << std::endl;
        std::cout << "Сумма: " << sum << ", Среднее арифметическое: " << avg << std::endl;
        
        // ОТПРАВЛЯЕМ 8 БАЙТ (int64_t) - СРЕДНЕЕ АРИФМЕТИЧЕСКОЕ
        int64_t result_to_send = htole64(avg);
        std::cout << "Отправка среднего арифметического для вектора " << i + 1 << ": " << avg << " (8 байт)" << std::endl;
        
        if (!sendAll(&result_to_send, sizeof(int64_t))) {
            logger_.log("Ошибка отправки результата вектора " + std::to_string(i + 1), false);
            return false;
        }
        
        std::cout << "Успешно обработан вектор " << i + 1 << std::endl;
    }
    
    std::cout << "Обработка всех " << num_vectors << " векторов завершена успешно" << std::endl;
    return true;
}
void ClientSession::run() {
    std::cout << "=== ЗАПУСК СЕССИИ ДЛЯ КЛИЕНТА ===" << std::endl;
    
    if (!auth()) {
        logger_.log("Ошибка аутентификации", false);
        close(sock_);
        return;
    }
    
    std::cout << "Аутентификация успешна, обработка векторов..." << std::endl;
    
    if (processVectors()) {
        logger_.log("Обработка векторов завершена успешно");
        std::cout << "=== СЕССИЯ ЗАВЕРШЕНА УСПЕШНО ===" << std::endl;
    } else {
        logger_.log("Ошибка обработки векторов", false);
        std::cout << "=== СЕССИЯ ЗАВЕРШЕНА С ОШИБКАМИ ===" << std::endl;
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
        if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
            client_db_file_ = argv[++i];
        } else if (strcmp(argv[i], "-LU") == 0 && i + 1 < argc) {
            log_file_ = argv[++i];
        } else if (strcmp(argv[i], "-a") == 0 && i + 1 < argc) {
            address_ = argv[++i];
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            port_ = std::stoi(argv[++i]);
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

void Server::stop() {
    running_ = false;
    if (server_sock_ != -1) {
        close(server_sock_);
        server_sock_ = -1;
    }
    logger_.log("Сервер остановлен");
}
