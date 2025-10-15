#include "server.h"

int parse_arguments(int argc, char* argv[], ServerParams& params) {
    if (argc == 1) {
        print_help();
        return 1;
    }
    
    if (argc == 2 && strcmp(argv[1], "-h") == 0) {
        print_help();
        return 1;
    }
    
    params.port = 33333;
    params.log_file = "server.log";
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-S") == 0 && i + 1 < argc) {
            params.client_db_file = argv[++i];
        } else if (strcmp(argv[i], "-H") == 0 && i + 1 < argc) {
           
            i++; 
        } else if (strcmp(argv[i], "-T") == 0 && i + 1 < argc) {
          
            i++;
        }
    }
    
    if (params.client_db_file.empty()) {
        std::cerr << "Ошибка: не указан файл базы клиентов" << std::endl;
        return 1;
    }
    
    return 0;
}

void print_help() {
    std::cout << "Использование: ./server_static -T float -H SHA1 -S client" << std::endl;
    std::cout << "Параметры:" << std::endl;
    std::cout << "  -S <file>    Файл базы клиентов (обязательный)" << std::endl;
    std::cout << "  -H <hash>    Используемая хэш-функция" << std::endl;
    std::cout << "  -T <type>    Тип данных" << std::endl;
    std::cout << "  -h           Показать эту справку" << std::endl;
    std::cout << std::endl << "Сервер всегда работает на порту 33333" << std::endl;
}

int load_client_db(const std::string& filename, ClientDatabase& db) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Ошибка открытия файла базы клиентов: " << filename << std::endl;
        return -1;
    }
    
    std::string line;
    while (std::getline(file, line)) {
       
        if (line.empty() || line[0] == '#' || line[0] == '\n') continue;
        
        std::istringstream iss(line);
        std::string login, password_hash;
        
        if (iss >> login >> password_hash) {
          
            if (password_hash.length() != HASH_HEX_SIZE) {
                std::cerr << "Предупреждение: некорректная длина хэша для пользователя " << login << std::endl;
                continue;
            }
            
            ClientInfo client;
            client.login = login;
            client.password_hash = password_hash;
            db.clients.push_back(client);
        }
    }
    
    std::cout << "Загружено " << db.clients.size() << " клиентов из базы данных" << std::endl;
    return 0;
}

void free_client_db(ClientDatabase& db) {
    db.clients.clear();
}

int authenticate_client(int client_socket, ClientDatabase& db) {
    char buffer[BUFFER_SIZE];
    ssize_t bytes_received;
    
    bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
    if (bytes_received <= 0) {
        return -1;
    }
    buffer[bytes_received] = '\0';
    
    char login[MAX_LOGIN_LENGTH];
    char salt_hex[SALT_HEX_SIZE + 1];
    char received_hash[HASH_HEX_SIZE + 1];
    
    if (sscanf(buffer, "%49s %16s %64s", login, salt_hex, received_hash) != 3) {
        send(client_socket, "ERR", 3, 0);
        return -1;
    }
    
    if (strlen(salt_hex) != SALT_HEX_SIZE) {
        send(client_socket, "ERR", 3, 0);
        return -1;
    }
    
    bool user_found = false;
    std::string expected_hash;
    
    for (const auto& client : db.clients) {
        if (client.login == login) {
            expected_hash = client.password_hash;
            user_found = true;
            break;
        }
    }
    
    if (!user_found) {
        send(client_socket, "ERR", 3, 0);
        return -1;
    }
    
    if (strcmp(received_hash, expected_hash.c_str()) == 0) {
        send(client_socket, "OK", 2, 0);
        return 0;
    } else {
        send(client_socket, "ERR", 3, 0);
        return -1;
    }
}


int process_client_vectors(int client_socket) {
    uint32_t num_vectors;
    
   
    if (!recv_all(client_socket, &num_vectors, sizeof(num_vectors))) {
        return -1;
    }
    
  
    num_vectors = ntohl(num_vectors);
    
    uint32_t num_results = num_vectors;
    uint32_t num_results_net = htonl(num_results);
    if (!send_all(client_socket, &num_results_net, sizeof(num_results_net))) {
        return -1;
    }
    
    for (uint32_t i = 0; i < num_vectors; i++) {
        uint32_t vector_size;
        
        if (!recv_all(client_socket, &vector_size, sizeof(vector_size))) {
            return -1;
        }
        vector_size = ntohl(vector_size);
        
        Vector vector;
        vector.size = vector_size;
        vector.data.resize(vector_size);
        
        if (!recv_all(client_socket, vector.data.data(), vector_size * sizeof(int64_t))) {
            return -1;
        }
        
       
        for (uint32_t j = 0; j < vector_size; j++) {
            vector.data[j] = be64toh(vector.data[j]);
        }
        
   
        int64_t average = calculate_vector_average(vector);
        
        average = htobe64(average);
        if (!send_all(client_socket, &average, sizeof(average))) {
            return -1;
        }
    }
    
    return 0;
}

int64_t calculate_vector_average(const Vector& vector) {
    if (vector.data.empty()) {
        return 0;
    }
    
    int64_t sum = 0;
    
    for (const auto& value : vector.data) {
        if (sum > 0 && value > INT64_MAX - sum) {
           
            return INT64_MIN; 
        }
        if (sum < 0 && value < INT64_MIN - sum) {
           
            return INT64_MIN; 
        }
        sum += value;
    }
    
    return sum / static_cast<int64_t>(vector.data.size());
}

void log_message(const std::string& log_file, const std::string& message, bool is_critical) {
    std::ofstream file(log_file, std::ios::app);
    if (!file.is_open()) {
        return;
    }
    
    auto now = std::chrono::system_clock::now();
    std::time_t time = std::chrono::system_clock::to_time_t(now);
    std::tm* tm_info = std::localtime(&time);
    
    char timestamp[20];
    std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    file << "[" << timestamp << "] " << (is_critical ? "CRITICAL" : "INFO") 
         << ": " << message << std::endl;
}

int start_server(ServerParams& params, ClientDatabase& db) {
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Ошибка создания сокета");
        return -1;
    }
    
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("Ошибка setsockopt");
        close(server_socket);
        return -1;
    }
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(params.port);
    
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Ошибка привязки сокета");
        close(server_socket);
        return -1;
    }
    
    if (listen(server_socket, MAX_CLIENTS) < 0) {
        perror("Ошибка прослушивания");
        close(server_socket);
        return -1;
    }
    
    std::cout << "Сервер запущен на порту " << params.port << std::endl;
    
    while (true) {
        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_len);
        if (client_socket < 0) {
            log_message(params.log_file, "Ошибка принятия соединения", false);
            continue;
        }
        
        std::cout << "Новое соединение от " << inet_ntoa(client_addr.sin_addr) 
                  << ":" << ntohs(client_addr.sin_port) << std::endl;
    
        if (authenticate_client(client_socket, db) == 0) {
            std::cout << "Клиент аутентифицирован" << std::endl;
            
         
            if (process_client_vectors(client_socket) == 0) {
                std::cout << "Обработка векторов завершена успешно" << std::endl;
            } else {
                log_message(params.log_file, "Ошибка обработки векторов", false);
            }
        } else {
            std::cout << "Ошибка аутентификации клиента" << std::endl;
        }
        
        close(client_socket);
        std::cout << "Соединение закрыто" << std::endl;
    }
    
    close(server_socket);
    return 0;
}


bool send_all(int socket, const void* buffer, size_t length) {
    const char* ptr = static_cast<const char*>(buffer);
    while (length > 0) {
        ssize_t sent = send(socket, ptr, length, 0);
        if (sent <= 0) return false;
        ptr += sent;
        length -= sent;
    }
    return true;
}


bool recv_all(int socket, void* buffer, size_t length) {
    char* ptr = static_cast<char*>(buffer);
    while (length > 0) {
        ssize_t received = recv(socket, ptr, length, 0);
        if (received <= 0) return false;
        ptr += received;
        length -= received;
    }
    return true;
}


std::string sha256_hash(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data.c_str(), data.length());
    SHA256_Final(hash, &sha256);
    
    return bytes_to_hex(hash, SHA256_DIGEST_LENGTH);
}


std::string bytes_to_hex(const unsigned char* data, size_t length) {
    std::string hex;
    hex.reserve(length * 2);
    
    for (size_t i = 0; i < length; ++i) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", data[i]);
        hex.append(buf);
    }
    
    return hex;
}
