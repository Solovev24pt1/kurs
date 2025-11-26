#include "../server2/server.h"
#include <UnitTest++/UnitTest++.h>
#include <sstream>
#include <cstring>

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
    
    TEST_FIXTURE(ClientDBFixture, LoadExistingFile) {
        CHECK(db.getClientCount() > 0);
    }
    
    TEST_FIXTURE(ClientDBFixture, AuthWithRealCredentials) {
        CHECK(db.auth("user", "P@ssW0rd"));
    }
    
    TEST_FIXTURE(ClientDBFixture, AuthFailureWithWrongPassword) {
        CHECK(!db.auth("user", "wrong_password"));
    }
    
    TEST_FIXTURE(ClientDBFixture, AuthNonExistentUser) {
        CHECK(!db.auth("nonexistent_user", "any_password"));
    }
}

// ==================== ТЕСТЫ ДЛЯ Logger ====================

SUITE(LoggerTest) {
    
    TEST_FIXTURE(LoggerFixture, LogToConsole) {
        logger.log("Console test message");
        CHECK(true);
    }
    
    TEST_FIXTURE(LoggerFixture, LogCriticalToConsole) {
        logger.log("Critical console error", true);
        CHECK(true);
    }
}

// ==================== ТЕСТЫ ДЛЯ Server ====================

SUITE(ServerTest) {
    
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
    
    TEST_FIXTURE(ServerFixture, ParseMinimalRealArgs) {
        char* argv[] = {
            (char*)"server", 
            (char*)"-d", (char*)"db.txt", 
            (char*)"-LU", (char*)"log.txt"
        };
        
        CHECK(server.parseArgs(5, argv));
    }
    
    TEST_FIXTURE(ServerFixture, ParseHelp) {
        char* argv[] = {(char*)"server", (char*)"-h"};
        
        CHECK(!server.parseArgs(2, argv)); 
    }
    
    TEST_FIXTURE(ServerFixture, ServerInitWithRealConfig) {
        char* argv[] = {
            (char*)"server", 
            (char*)"-d", (char*)"db.txt", 
            (char*)"-LU", (char*)"log.txt"
        };
        
        bool result = server.init(5, argv);
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
    
    TEST_FIXTURE(ClientSessionFixture, CreateClientSessionWithRealData) {
        ClientSession session(sockfd[0], db, logger);
        CHECK(true);
    }
}

// ==================== ГРАНИЧНЫЕ ТЕСТЫ ====================

SUITE(EdgeCaseTest) {
    
    TEST(LoadNonExistentFile) {
        ClientDB db;
        CHECK(!db.load("nonexistent_file.txt"));
    }
    
    TEST_FIXTURE(ServerFixture, ParseInvalidArgs) {
        char* argv[] = {(char*)"server"};
        CHECK(!server.parseArgs(1, argv));
    }
    
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
