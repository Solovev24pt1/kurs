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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/sha.h>

class Logger {
private:
    std::string log_file_;

public:
    Logger(const std::string& log_file = "server.log") : log_file_(log_file) {}
    
    void log(const std::string& message, bool is_critical = false) const {
        std::ofstream file(log_file_, std::ios::app);
        if (!file.is_open()) return;

        auto now = std::chrono::system_clock::now();
        std::time_t time = std::chrono::system_clock::to_time_t(now);
        std::tm* tm_info = std::localtime(&time);
        
        char timestamp[20];
        std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
        
        file << "[" << timestamp << "] " << (is_critical ? "CRITICAL" : "INFO") 
             << ": " << message << std::endl;
    }
    
    void setLogFile(const std::string& log_file) { log_file_ = log_file; }
    std::string getLogFile() const { return log_file_; }
};

class ClientInfo {
private:
    std::string login_;
    std::string password_hash_;

public:
    ClientInfo(const std::string& login, const std::string& password_hash)
        : login_(login), password_hash_(password_hash) {}
    
    std::string getLogin() const { return login_; }
    std::string getPasswordHash() const { return password_hash_; }
    
    void setLogin(const std::string& login) { login_ = login; }
    void setPasswordHash(const std::string& hash) { password_hash_ = hash; }
    
    bool authenticate(const std::string& input_hash) const {
        return password_hash_ == input_hash;
    }
};

class ClientDatabase {
private:
    std::vector<ClientInfo> clients_;
    std::unordered_map<std::string, ClientInfo*> client_map_; 

public:
    bool loadFromFile(const std::string& filename) {
        std::ifstream file(filename);
        if (!file.is_open()) {
            return false;
        }

        std::string line;
        while (std::getline(file, line)) {
            if (line.empty() || line[0] == '#' || line[0] == '\n') continue;

            std::istringstream iss(line);
            std::string login, password_hash;
            
            if (iss >> login >> password_hash) {
                if (password_hash.length() == 64) { 
                    addClient(ClientInfo(login, password_hash));
                }
            }
        }

        return true;
    }
    
    void addClient(const ClientInfo& client) {
        clients_.push_back(client);
        client_map_[client.getLogin()] = &clients_.back();
    }
    
    ClientInfo* findClient(const std::string& login) const {
        auto it = client_map_.find(login);
        return (it != client_map_.end()) ? it->second : nullptr;
    }
    
    bool authenticate(const std::string& login, const std::string& password_hash) const {
        ClientInfo* client = findClient(login);
        return client && client->authenticate(password_hash);
    }
    
    size_t getClientCount() const { return clients_.size(); }
    const std::vector<ClientInfo>& getClients() const { return clients_; }
};

class Vector {
private:
    std::vector<int64_t> data_;
    uint32_t size_;

public:
    Vector() : size_(0) {}
    Vector(const std::vector<int64_t>& data) : data_(data), size_(data.size()) {}
    
    void setData(const std::vector<int64_t>& data) {
        data_ = data;
        size_ = data.size();
    }
    
    void addValue(int64_t value) {
        data_.push_back(value);
        size_ = data_.size();
    }
    
    const std::vector<int64_t>& getData() const { return data_; }
    uint32_t getSize() const { return size_; }
    
    void clear() {
        data_.clear();
        size_ = 0;
    }
};

class VectorProcessor {
public:
    static int64_t calculateAverage(const Vector& vector) {
        const std::vector<int64_t>& data = vector.getData();
        if (data.empty()) return 0;

        int64_t sum = 0;
        
        for (const auto& value : data) {
            if (sum > 0 && value > INT64_MAX - sum) {
                return INT64_MIN; 
            }
            if (sum < 0 && value < INT64_MIN - sum) {
                return INT64_MIN; 
            }
            sum += value;
        }

        return sum / static_cast<int64_t>(data.size());
    }
};

class NetworkUtils {
public:
    static bool sendAll(int socket, const void* buffer, size_t length) {
        const char* ptr = static_cast<const char*>(buffer);
        while (length > 0) {
            ssize_t sent = send(socket, ptr, length, 0);
            if (sent <= 0) return false;
            ptr += sent;
            length -= sent;
        }
        return true;
    }

    static bool recvAll(int socket, void* buffer, size_t length) {
        char* ptr = static_cast<char*>(buffer);
        while (length > 0) {
            ssize_t received = recv(socket, ptr, length, 0);
            if (received <= 0) return false;
            ptr += received;
            length -= received;
        }
        return true;
    }

    static uint32_t hostToNetwork(uint32_t value) { return htonl(value); }
    static uint32_t networkToHost(uint32_t value) { return ntohl(value); }
    
    static int64_t hostToNetwork(int64_t value) { return htobe64(value); }
    static int64_t networkToHost(int64_t value) { return be64toh(value); }
};

class ServerConfig {
private:
    std::string client_db_file_;
    std::string log_file_;
    int port_;
    std::string hash_type_;
    std::string data_type_;

public:
    ServerConfig() : client_db_file_(""), log_file_("server.log"), port_(33333),
                    hash_type_("SHA256"), data_type_("int64_t") {}
    
    std::string getClientDbFile() const { return client_db_file_; }
    std::string getLogFile() const { return log_file_; }
    int getPort() const { return port_; }
    std::string getHashType() const { return hash_type_; }
    std::string getDataType() const { return data_type_; }
    
    void setClientDbFile(const std::string& file) { client_db_file_ = file; }
    void setLogFile(const std::string& file) { log_file_ = file; }
    void setPort(int port) { port_ = port; }
    void setHashType(const std::string& type) { hash_type_ = type; }
    void setDataType(const std::string& type) { data_type_ = type; }
    
    bool parseArguments(int argc, char* argv[]);
    void printHelp() const;
};

class ClientSession {
private:
    int client_socket_;
    ClientDatabase& client_db_;
    Logger& logger_;
    
public:
    ClientSession(int client_socket, ClientDatabase& db, Logger& logger)
        : client_socket_(client_socket), client_db_(db), logger_(logger) {}
    
    bool authenticate();
    bool processVectors();
    void run();
    
private:
    bool receiveAuthentication(std::string& login, std::string& salt, std::string& hash);
};

class Server {
private:
    ServerConfig config_;
    ClientDatabase client_db_;
    Logger logger_;
    int server_socket_;
    bool running_;
    
public:
    Server() : server_socket_(-1), running_(false) {}
    ~Server() { stop(); }
    
    bool initialize(int argc, char* argv[]);
    bool start();
    void stop();
    bool isRunning() const { return running_; }
    
private:
    bool createSocket();
    bool bindSocket();
    bool listenForConnections();
    void handleClient(int client_socket);
};


