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
    std::string log_file_;
public:
    Logger(const std::string& log_file = "server.log") : log_file_(log_file) {}
    void log(const std::string& msg, bool critical = false) const;
};

class ClientDB {
    std::unordered_map<std::string, std::string> clients_;
public:
    bool load(const std::string& filename);
    bool auth(const std::string& login, const std::string& hash) const;
    size_t getClientCount() const { return clients_.size(); }
};

class ClientSession {
    int sock_;
    ClientDB& db_;
    Logger& logger_;
    
    bool sendAll(const void* buf, size_t len);
    bool recvAll(void* buf, size_t len);
    bool auth();
    bool processVectors();

public:
    ClientSession(int sock, ClientDB& db, Logger& logger);
    void run();
};

class Server {
    std::string client_db_file_ = "client.db";
    std::string log_file_ = "server.log";
    int port_ = 33333;
    ClientDB db_;
    Logger logger_;
    int server_sock_ = -1;
    bool running_ = false;

    bool parseArgs(int argc, char* argv[]);

    void printHelp() const {
        std::cout << "Использование: ./server_static -T float -H SHA1 -S client" << std::endl;
        std::cout << "Параметры:" << std::endl;
        std::cout << "  -S <file>    Файл базы клиентов (обязательный)" << std::endl;
        std::cout << "  -H <hash>    Используемая хэш-функция" << std::endl;
        std::cout << "  -T <type>    Тип данных" << std::endl;
        std::cout << "  -h           Показать эту справку" << std::endl;
        std::cout << std::endl << "Сервер всегда работает на порту 33333" << std::endl;
    }

public:
    ~Server();
    bool init(int argc, char* argv[]);
    bool start();
    void stop();
};

