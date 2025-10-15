#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <chrono>
#include <ctime>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/sha.h>

const int MAX_CLIENTS = 10;
const int BUFFER_SIZE = 1024;
const int SALT_SIZE = 8;
const int SALT_HEX_SIZE = 16;
const int HASH_SIZE = 32;
const int HASH_HEX_SIZE = 64;
const int MAX_LOGIN_LENGTH = 50;

struct ClientInfo {
    std::string login;
    std::string password_hash;
};

struct ClientDatabase {
    std::vector<ClientInfo> clients;
};

struct ServerParams {
    std::string client_db_file;
    std::string log_file;
    int port;
};

struct Vector {
    std::vector<int64_t> data;
    uint32_t size;
};


int parse_arguments(int argc, char* argv[], ServerParams& params);
void print_help();
int load_client_db(const std::string& filename, ClientDatabase& db);
void free_client_db(ClientDatabase& db);
int authenticate_client(int client_socket, ClientDatabase& db);
int process_client_vectors(int client_socket);
int64_t calculate_vector_average(const Vector& vector);
void log_message(const std::string& log_file, const std::string& message, bool is_critical);
int start_server(ServerParams& params, ClientDatabase& db);

bool send_all(int socket, const void* buffer, size_t length);
bool recv_all(int socket, void* buffer, size_t length);
std::string sha256_hash(const std::string& data);
std::string bytes_to_hex(const unsigned char* data, size_t length);

