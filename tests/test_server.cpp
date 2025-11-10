#include "../server2/server.h"
#include <UnitTest++/UnitTest++.h>
#include <sstream>
#include <cstring>

// ==================== ТЕСТЫ ДЛЯ ClientDB ====================

SUITE(ClientDBTest) {
    
    TEST(LoadExistingFile) {
        ClientDB db;
        CHECK(db.load("db.txt"));
        CHECK(db.getClientCount() > 0);
    }
    
    TEST(AuthWithRealCredentials) {
        ClientDB db;
        db.load("db.txt");
        CHECK(db.auth("user", "P@ssW0rd"));
    }
    
    TEST(AuthFailureWithWrongPassword) {
        ClientDB db;
        db.load("db.txt");
        CHECK(!db.auth("user", "wrong_password"));
    }
}

// ==================== ТЕСТЫ ДЛЯ Logger ====================

SUITE(LoggerTest) {
    
    TEST(LogToConsole) {
        Logger logger("");
        logger.log("Console test message");
        CHECK(true);
    }
    
    TEST(LogCriticalToConsole) {
        Logger logger("");
        logger.log("Critical console error", true);
        CHECK(true);
    }
}

// ==================== ТЕСТЫ ДЛЯ Server ====================

SUITE(ServerTest) {
    
    TEST(ParseRealArgs) {
        Server server;
        char* argv[] = {
            (char*)"server", 
            (char*)"-d", (char*)"db.txt", 
            (char*)"-LU", (char*)"test_log",
            (char*)"-a", (char*)"127.0.0.1",
            (char*)"-p", (char*)"33333"
        };
        
        CHECK(server.parseArgs(9, argv));
    }
    
    TEST(ParseMinimalRealArgs) {
        Server server;
        char* argv[] = {
            (char*)"server", 
            (char*)"-d", (char*)"db.txt", 
            (char*)"-LU", (char*)"test_log"
        };
        
        CHECK(server.parseArgs(5, argv));
    }
    
    TEST(ParseHelp) {
        Server server;
        char* argv[] = {(char*)"server", (char*)"-h"};
        
        CHECK(!server.parseArgs(2, argv)); 
    }
    
    TEST(ServerInitWithRealConfig) {
        Server server;
        char* argv[] = {
            (char*)"server", 
            (char*)"-d", (char*)"db.txt", 
            (char*)"-LU", (char*)"test_log"
        };
        
        bool result = server.init(5, argv);
        CHECK(result);
    }
}

// ==================== ТЕСТЫ ДЛЯ ClientSession ====================

SUITE(ClientSessionTest) {
    
    TEST(CreateClientSessionWithRealData) {
        ClientDB db;
        db.load("db.txt");
        Logger logger("test.log");
        
        int sockfd[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockfd) == 0) {
            ClientSession session(sockfd[0], db, logger);
            
            close(sockfd[0]);
            close(sockfd[1]);
            
            CHECK(true);
        } else {
            CHECK(false);
        }
    }
}

// ==================== ГРАНИЧНЫЕ ТЕСТЫ ====================

SUITE(EdgeCaseTest) {
    
    TEST(LoadNonExistentFile) {
   
        std::stringstream error_buffer;
        std::streambuf* original_cerr = std::cerr.rdbuf(error_buffer.rdbuf());
        
        ClientDB db;
        CHECK(!db.load("nonexistent_file.txt"));
     
        std::cerr.rdbuf(original_cerr);
    }
    
    TEST(AuthNonExistentUser) {
        ClientDB db;
        db.load("db.txt");
        CHECK(!db.auth("nonexistent_user", "any_password"));
    }
    
    TEST(ParseInvalidArgs) {

        std::stringstream error_buffer;
        std::streambuf* original_cerr = std::cerr.rdbuf(error_buffer.rdbuf());
        
        Server server;
        char* argv[] = {(char*)"server"};
        CHECK(!server.parseArgs(1, argv));
        
     
        std::cerr.rdbuf(original_cerr);
    }
    
    TEST(ParseMissingRequiredArgs) {
        std::stringstream error_buffer;
        std::streambuf* original_cerr = std::cerr.rdbuf(error_buffer.rdbuf());
        
        Server server;
        char* argv[] = {
            (char*)"server",
            (char*)"-d", (char*)"db.txt"
        };
        CHECK(!server.parseArgs(3, argv));
        
        // Восстанавливаем stderr
        std::cerr.rdbuf(original_cerr);
    }
}

// ==================== ГЛАВНАЯ ФУНКЦИЯ ТЕСТОВ ====================

int main() {
    std::cout.setf(std::ios::unitbuf);
    
    std::cout << "=========================================" << std::endl;
    std::cout << "ТЕСТИРОВАНИЕ" << std::endl;
    std::cout << "=========================================" << std::endl;
   
    std::stringstream output_buffer;
    std::stringstream error_buffer;
    std::streambuf* old_cout = std::cout.rdbuf(output_buffer.rdbuf());
    std::streambuf* old_cerr = std::cerr.rdbuf(error_buffer.rdbuf());
    
    int result = UnitTest::RunAllTests();
    
    std::cout.rdbuf(old_cout);
    std::cerr.rdbuf(old_cerr);
    
    std::cout << "=========================================" << std::endl;
    std::cout << "ТЕСТИРОВАНИЕ ЗАВЕРШЕНО" << std::endl;
    std::cout << "=========================================" << std::endl;
    
    return result;
}
