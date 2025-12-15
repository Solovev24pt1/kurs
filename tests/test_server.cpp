#include "../server2/server.h"
#include <UnitTest++/UnitTest++.h>
#include <sstream>
#include <cstring>
#include <cstdlib>
#include <fcntl.h>

// ==================== ФИКСТУРЫ ДЛЯ ТЕСТОВ ====================

struct ClientDBFixture {
    ClientDB db;
    
    ClientDBFixture() {
        db.load("db.txt");
    }
};

struct ServerFixture {
    Server server;
    
    ServerFixture() {
        // Базовая инициализация сервера
    }
};

struct LoggerFixture {
    Logger logger;
    
    LoggerFixture() : logger("test.log") {
    }
};

// ==================== ТЕСТЫ ДЛЯ ClientDB ====================

SUITE(ClientDBTest) {
    
    // ТЕСТ 3: Тест загрузки существующего файла БД
    TEST_FIXTURE(ClientDBFixture, LoadExistingFile) {
        CHECK(db.getClientCount() > 0);
    }
    
    // ТЕСТ 2: Тест успешной аутентификации
    TEST_FIXTURE(ClientDBFixture, AuthWithRealCredentials) {
        CHECK(db.auth("user", "P@ssW0rd"));
    }
    
    // ТЕСТ 8: Тест неудачной аутентификации
    TEST_FIXTURE(ClientDBFixture, AuthFailureWithWrongPassword) {
        CHECK(!db.auth("user", "wrong_password"));
    }
    
    // ТЕСТ 12: Тест аутентификации несуществующего пользователя
    TEST_FIXTURE(ClientDBFixture, AuthNonExistentUser) {
        CHECK(!db.auth("nonexistent_user", "any_password"));
    }
}

// ==================== ТЕСТЫ ДЛЯ Logger ====================

SUITE(LoggerTest) {
    
    // ТЕСТ 4: Тест логирования в консоль
    TEST_FIXTURE(LoggerFixture, LogToConsole) {
        logger.log("Console test message");
        CHECK(true);
    }
    
    // ТЕСТ 5: Тест критического логирования
    TEST_FIXTURE(LoggerFixture, LogCriticalToConsole) {
        logger.log("Critical console error", true);
        CHECK(true);
    }
}

// ==================== ТЕСТЫ ДЛЯ Server ====================

SUITE(ServerTest) {
    
    // ТЕСТ 6: Тест парсинга полных аргументов
    TEST_FIXTURE(ServerFixture, ParseRealArgs) {
        char* argv[] = {
            (char*)"server", 
            (char*)"-d", (char*)"db.txt", 
            (char*)"-LU", (char*)"log.txt",
            (char*)"-a", (char*)"127.0.0.1",
            (char*)"-p", (char*)"33333"
        };
        
        CHECK(server.parseArgs(9, argv));
    }
    
    // ТЕСТ 7: Тест парсинга минимальных аргументов 
    TEST_FIXTURE(ServerFixture, ParseMinimalRealArgs) {
        char* argv[] = {
            (char*)"server", 
            (char*)"-d", (char*)"db.txt", 
            (char*)"-LU", (char*)"log.txt",
            (char*)"-p", (char*)"8080" 
        };
        
        CHECK(server.parseArgs(7, argv)); 
    }
    
    // ТЕСТ 1: Тест вызова справки
    TEST_FIXTURE(ServerFixture, ParseHelp) {
        char* argv[] = {(char*)"server", (char*)"-h"};
        
        CHECK(!server.parseArgs(2, argv)); 
    }
    
    // ТЕСТ 9: Тест инициализации сервера 
    TEST_FIXTURE(ServerFixture, ServerInitWithRealConfig) {
        char* argv[] = {
            (char*)"server", 
            (char*)"-d", (char*)"db.txt", 
            (char*)"-LU", (char*)"log.txt",
            (char*)"-p", (char*)"9090"  
        };
        
        bool result = server.init(7, argv); 
        CHECK(result);
    }
}

// ==================== ТЕСТЫ ДЛЯ ClientSession ====================

struct ClientSessionFixture {
    ClientDB db;
    Logger logger;
    int sockfd[2];
    
    ClientSessionFixture() : logger("test.log") {
        db.load("db.txt");
        socketpair(AF_UNIX, SOCK_STREAM, 0, sockfd);
    }
    
    ~ClientSessionFixture() {
        close(sockfd[0]);
        close(sockfd[1]);
    }
};

SUITE(ClientSessionTest) {
    
    // ТЕСТ 10: Тест создания клиентской сессии
    TEST_FIXTURE(ClientSessionFixture, CreateClientSessionWithRealData) {
        ClientSession session(sockfd[0], db, logger);
        CHECK(true);
    }
}

// ==================== ГРАНИЧНЫЕ ТЕСТЫ ====================

SUITE(EdgeCaseTest) {
    
    // ТЕСТ 11: Тест загрузки несуществующего файла БД
    TEST(LoadNonExistentFile) {
        ClientDB db;
        CHECK(!db.load("nonexistent_file.txt"));
    }
    
    // ТЕСТ 13: Тест парсинга неверных аргументов
    TEST_FIXTURE(ServerFixture, ParseInvalidArgs) {
        char* argv[] = {(char*)"server"};
        CHECK(!server.parseArgs(1, argv));
    }
    
    // ТЕСТ 14: Тест отсутствия обязательных параметров
    TEST_FIXTURE(ServerFixture, ParseMissingRequiredArgs) {
        char* argv[] = {
            (char*)"server",
            (char*)"-d", (char*)"db.txt"
           
        };
        CHECK(!server.parseArgs(3, argv));
    }
}

// ==================== ГЛАВНАЯ ФУНКЦИЯ ТЕСТОВ ====================

int main() {
   
    std::stringstream null_stream;
    std::streambuf* old_cout = std::cout.rdbuf(null_stream.rdbuf());
    std::streambuf* old_cerr = std::cerr.rdbuf(null_stream.rdbuf());
    
  
    int result = UnitTest::RunAllTests();
    

    std::cout.rdbuf(old_cout);
    std::cerr.rdbuf(old_cerr);
    
   
    if (result == 0) {
        std::cout << "Все тесты прошли успешно!" << std::endl;
    } else {
        std::cout << "Тесты не прошли. Код ошибки: " << result << std::endl;
    }
    
    return result;
}
