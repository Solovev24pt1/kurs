/**
 * @file ClientSession.cpp
 * @author Соловьев Арсений Евгеньевич
 * @version 1.0
 * @date 1.12.25
 * @copyright ПГУ ИБСТ
 * @brief Реализация класса ClientSession для обработки клиентских подключений
 */

#include "server.h"
#include <endian.h>
#include <cctype>
#include <unistd.h>

/**
 * @brief Конструктор класса ClientSession
 * @param sock Дескриптор сокета клиента
 * @param db Ссылка на базу данных клиентов
 * @param logger Ссылка на объект логгера
 * @details Инициализирует объект ClientSession с переданными параметрами.
 */
 
ClientSession::ClientSession(int sock, ClientDB& db, Logger& logger) 
    : sock_(sock), db_(db), logger_(logger) {}

/**
 * @brief Гарантированно отправляет все данные через сокет
 * @param buf Указатель на данные для отправки
 * @param len Количество байт для отправки
 * @return true в случае успешной отправки всех данных, false в случае ошибки
 * @details Использует цикл для отправки всех данных, даже если системный вызов send
 *          возвращает меньше данных, чем запрошено.
 */
 
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

/**
 * @brief Гарантированно принимает все данные через сокет
 * @param buf Указатель на буфер для приема данных
 * @param len Количество байт для приема
 * @return true в случае успешного приема всех данных, false в случае ошибки
 * @details Использует цикл для приема всех данных, даже если системный вызов recv
 *          возвращает меньше данных, чем запрошено.
 */
 
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

/**
 * @brief Выполняет аутентификация клиента
 * @return true в случае успешной аутентификации, false в случае ошибки
 * @details Ожидает сообщение аутентификации от клиента (84 байта: "user" + соль 16B + хеш 64B),
 *          проверяет формат и вызывает проверку хеша через ClientDB.
 */
 
bool ClientSession::auth() {
    char buf[1024];
    ssize_t received = recv(sock_, buf, sizeof(buf) - 1, 0);
    if (received <= 0) {
        logger_.log("Ошибка приема данных аутентификации", false);
        close(sock_);
        return false;
    }
    buf[received] = '\0';
    
    std::string message(buf, received);
    std::cout << "Получено сообщение аутентификации: " << message << std::endl;
    std::cout << "Длина сообщения: " << message.length() << std::endl;
    
    if (message.length() < 84) {
        logger_.log("Неверная длина сообщения аутентификации: " + std::to_string(message.length()), false);
        send(sock_, "ERR", 3, 0);
        close(sock_);
        return false;
    }
    
    if (message.substr(0, 4) != "user") {
        logger_.log("Сообщение не начинается с 'user'", false);
        send(sock_, "ERR", 3, 0);
        close(sock_);
        return false;
    }
    
    std::string login = "user";
    std::string salt = message.substr(4, 16);
    std::string received_hash = message.substr(20, 64);
    
    std::cout << "Логин: '" << login << "', Длина логина: " << login.length() << std::endl;
    std::cout << "Соль: " << salt << ", Длина соли: " << salt.length() << std::endl;
    std::cout << "Полученный хеш: " << received_hash << ", Длина хеш: " << received_hash.length() << std::endl;
    
    auto is_hex = [](const std::string& str) {
        for (char c : str) {
            if (!std::isxdigit(c)) return false;
        }
        return true;
    };
    
    if (!is_hex(salt) || salt.length() != 16) {
        logger_.log("Неверный формат соли", false);
        send(sock_, "ERR", 3, 0);
        close(sock_);
        return false;
    }
    
    if (!is_hex(received_hash) || received_hash.length() != 64) {
        logger_.log("Неверный формат хеша", false);
        send(sock_, "ERR", 3, 0);
        close(sock_);
        return false;
    }
    
    if (!db_.authWithHash(login, received_hash, salt)) {
        logger_.log("Аутентификация не удалась для: " + login, false);
        send(sock_, "ERR", 3, 0);
        close(sock_);
        return false;
    }
    
    send(sock_, "OK", 2, 0);
    logger_.log("Клиент аутентифицирован: " + login);
    return true;
}

/**
 * @brief Обрабатывает векторы данных от клиента
 * @return true в случае успешной обработки всех векторов, false в случае ошибки
 * @details Принимает векторы чисел в формате little-endian, вычисляет среднее арифметическое
 *          каждого вектора с проверкой переполнения. Отправляет результаты в двух форматах:
 *          1. После каждого вектора (для совместимости с текущим клиентом)
 *          2. В конце все результаты с заголовком (в соответствии с ТЗ 4.2.5)
 */
 
bool ClientSession::processVectors() {
    // Принимаем количество векторов (4 байта)
    uint32_t num_vectors;
    if (!recvAll(&num_vectors, sizeof(uint32_t))) {
        logger_.log("Ошибка приема количества векторов", false);
        return false;
    }
    
    num_vectors = le32toh(num_vectors);
    
    std::cout << "Клиент указал, что отправит " << num_vectors << " векторов" << std::endl;
    
    if (num_vectors == 0) {
        logger_.log("Получено 0 векторов", false);
        
        uint32_t zero_results = htole32(0);
        if (!sendAll(&zero_results, sizeof(uint32_t))) {
            logger_.log("Ошибка отправки количества результатов", false);
            return false;
        }
        return true;
    }
    
    if (num_vectors > 100) {
        logger_.log("Слишком большое количество векторов: " + std::to_string(num_vectors), false);
        return false;
    }
    
    // Вектор для накопления всех результатов
    std::vector<int64_t> all_results;
    all_results.reserve(num_vectors);
    
    for (uint32_t i = 0; i < num_vectors; i++) {
        std::cout << "\n=== ОБРАБОТКА ВЕКТОРА " << i + 1 << " из " << num_vectors << " ===" << std::endl;
        
        uint32_t size;
        if (!recvAll(&size, sizeof(uint32_t))) {
            logger_.log("Ошибка приема размера вектора " + std::to_string(i + 1), false);
            return false;
        }
        
        size = le32toh(size);
        
        std::cout << "Размер вектора " << i + 1 << ": " << size << std::endl;
        
        if (size == 0) {
            // Для пустого вектора результат = 0
            all_results.push_back(0);
            std::cout << "Пустой вектор, результат: 0" << std::endl;
            
            // Отправляем результат немедленно (для совместимости)
            int64_t zero_result = htole64(0);
            if (!sendAll(&zero_result, sizeof(int64_t))) {
                logger_.log("Ошибка отправки результата для пустого вектора", false);
                return false;
            }
            std::cout << "Отправлен результат для пустого вектора: 0 (8 байт)" << std::endl;
            
            continue;
        }
        
        if (size > 100000) {
            logger_.log("Слишком большой размер вектора: " + std::to_string(size), false);
            return false;
        }
        
        std::vector<int64_t> data(size);
        
        size_t total_bytes = size * sizeof(int64_t);
        std::cout << "Ожидается " << total_bytes << " байт данных для вектора " << i + 1 << std::endl;
        
        if (!recvAll(data.data(), total_bytes)) {
            logger_.log("Ошибка приема данных вектора " + std::to_string(i + 1) + 
                       ", ожидалось " + std::to_string(total_bytes) + " байт", false);
            return false;
        }
        
        std::cout << "Успешно получены данные вектора " << i + 1 << std::endl;
        
        for (auto& val : data) {
            val = le64toh(val);
        }
        
      
        int64_t sum = 0;
        bool overflow_up = false;
        bool overflow_down = false;
        
        for (const auto& val : data) {
            if (val > 0) {
              
                if (val > std::numeric_limits<int64_t>::max() - sum) {
                    overflow_up = true;
                    break;
                }
            } else if (val < 0) {
                
                if (val < std::numeric_limits<int64_t>::min() - sum) {
                    overflow_down = true;
                    break;
                }
            }
           
            sum += val;
        }
        
        int64_t avg;
        if (overflow_up) {
            
            avg = 0x8000000000000000LL; 
            std::cout << "Обнаружено переполнение вверх, результат: " << avg << std::endl;
        } else if (overflow_down) {
            
            avg = std::numeric_limits<int64_t>::min();  
            std::cout << "Обнаружено переполнение вниз, результат: " << avg << std::endl;
        } else {
            avg = sum / static_cast<int64_t>(size);
            std::cout << "Сумма: " << sum << ", Среднее арифметическое: " << avg << std::endl;
        }
        
        
        all_results.push_back(avg);
        
        
        int64_t result_to_send = htole64(avg);
        std::cout << "Отправка результата для вектора " << i + 1 << ": " << avg << " (8 байт)" << std::endl;
        
        if (!sendAll(&result_to_send, sizeof(int64_t))) {
            logger_.log("Ошибка отправки результата вектора " + std::to_string(i + 1), false);
            return false;
        }
        
        std::cout << "Вектор " << i + 1 << " успешно обработан" << std::endl;
    }
    
    std::cout << "\nВсе " << num_vectors << " векторов успешно обработаны" << std::endl;
    

    uint32_t num_results = htole32(static_cast<uint32_t>(all_results.size()));
    std::cout << "Отправка количества результатов: " << all_results.size() << " (4 байта)" << std::endl;
    
   
    sendAll(&num_results, sizeof(uint32_t));
    
    
    for (size_t i = 0; i < all_results.size(); i++) {
        int64_t result_to_send = htole64(all_results[i]);
        std::cout << "Дополнительная отправка результата " << i + 1 << ": " 
                  << all_results[i] << " (8 байт)" << std::endl;
        sendAll(&result_to_send, sizeof(int64_t));
    }
    
    std::cout << "Дополнительная отправка завершена" << std::endl;
    
    return true;
}

/**
 * @brief Запускает обработку клиентской сессии
 * @details Основной метод обработки клиента: выполняет аутентификацию,
 *          затем обрабатывает данные и закрывает соединение.
 */
 
void ClientSession::run() {
    std::cout << "\n========================================" << std::endl;
    std::cout << "=== ЗАПУСК СЕССИИ ДЛЯ НОВОГО КЛИЕНТА ===" << std::endl;
    std::cout << "========================================\n" << std::endl;
    
    if (!auth()) {
        logger_.log("Ошибка аутентификации", false);
        return;
    }
    
    std::cout << "Аутентификация успешна, ожидание векторов..." << std::endl;
    
    if (processVectors()) {
        logger_.log("Обработка векторов завершена успешно");
        std::cout << "\n========================================" << std::endl;
        std::cout << "=== СЕССИЯ ЗАВЕРШЕНА УСПЕШНО ===" << std::endl;
        std::cout << "========================================\n" << std::endl;
    } else {
        logger_.log("Ошибка обработки векторов", false);
        std::cout << "\n========================================" << std::endl;
        std::cout << "=== СЕССИЯ ЗАВЕРШЕНА С ОШИБКАМИ ===" << std::endl;
        std::cout << "========================================\n" << std::endl;
    }
    
    close(sock_);
}
