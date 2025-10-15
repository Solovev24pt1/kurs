#include "server.h"

int main(int argc, char* argv[]) {
    ServerParams params;
    ClientDatabase client_db;
    
    if (parse_arguments(argc, argv, params) != 0) {
        return 1;
    }
    

    if (load_client_db(params.client_db_file, client_db) != 0) {
        std::cerr << "Ошибка загрузки базы клиентов" << std::endl;
        return 1;
    }
    
    log_message(params.log_file, "Сервер запущен", false);
    
    if (start_server(params, client_db) != 0) {
        log_message(params.log_file, "Ошибка запуска сервера", true);
        free_client_db(client_db);
        return 1;
    }
    
    free_client_db(client_db);
    log_message(params.log_file, "Сервер остановлен", false);
    return 0;
}
