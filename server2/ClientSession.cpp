/**
 * @file ClientSession.cpp
 * @author Соловьев Арсений Евгеньевич
 * @date 01.12.2025
 * @copyright ПГУ
 * @brief Реализация класса ClientSession
 * @details Методы для работы с отдельной сессией клиента.
 */

#include "server.h"
#include <endian.h>
#include <cctype>
#include <unistd.h>
#include <sys/socket.h>
#include <cerrno>

/**
 * @brief Конструктор сессии
 * @param sock Сокет соединения
 * @param db База клиентов
 * @param logger Логгер
 */
 
ClientSession::ClientSession(int sock, ClientDB& db, Logger& logger) 
    : sock_(sock), db_(db), logger_(logger) {}

/**
 * @brief Отправка всех данных
 * @param buf Указатель на данные
 * @param len Размер данных
 * @return true — успешно, false — ошибка
 */
 
bool ClientSession::sendAll(const void* buf, size_t len) {
    const char* ptr = static_cast<const char*>(buf);
    size_t total_sent = 0;
    
    while (len > 0) {
        ssize_t sent = send(sock_, ptr, len, 0);
        if (sent < 0) {
            std::cerr << "Ошибка send(): " << strerror(errno) << std::endl;
            logger_.log("Ошибка отправки данных: " + std::string(strerror(errno)), false);
            return false;
        } else if (sent == 0) {
            std::cerr << "Соединение закрыто при отправке" << std::endl;
            logger_.log("Соединение закрыто при отправке", false);
            return false;
        }
        
        ptr += sent;
        len -= sent;
        total_sent += sent;
    }
    
    return true;
}

/**
 * @brief Приём всех данных
 * @param buf Указатель на буфер
 * @param len Размер данных
 * @return true — успешно, false — ошибка
 */
 
bool ClientSession::recvAll(void* buf, size_t len) {
    char* ptr = static_cast<char*>(buf);
    size_t total_received = 0;
    
    while (len > 0) {
        ssize_t received = recv(sock_, ptr, len, 0);
        if (received < 0) {
            std::cerr << "Ошибка recv(): " << strerror(errno) << std::endl;
            logger_.log("Ошибка приема данных: " + std::string(strerror(errno)), false);
            return false;
        } else if (received == 0) {
            std::cerr << "Соединение закрыто при приеме" << std::endl;
            logger_.log("Соединение закрыто при приеме", false);
            return false;
        }
        
        ptr += received;
        len -= received;
        total_received += received;
    }
    
    return true;
}

/**
 * @brief Аутентификация клиента
 * @return true — успешно, false — ошибка
 */
 
bool ClientSession::auth() {
    char buf[1024];
    ssize_t received = recv(sock_, buf, sizeof(buf) - 1, 0);
    if (received <= 0) {
        std::cerr << "Ошибка приема данных аутентификации: " << strerror(errno) << std::endl;
        logger_.log("Ошибка приема данных аутентификации", false);
        return false;
    }
    buf[received] = '\0';
    
    std::string message(buf, received);
    std::cout << "Получено сообщение аутентификации: " << message << std::endl;
    std::cout << "Длина сообщения: " << message.length() << std::endl;
    
    // Проверяем минимальную длину (user + соль 16 + хеш 64 = 84 байта)
    if (message.length() < 84) {
        std::cerr << "Неверная длина сообщения аутентификации: " << message.length() << std::endl;
        logger_.log("Неверная длина сообщения аутентификации: " + std::to_string(message.length()), false);
        send(sock_, "ERR", 3, 0);
        return false;
    }
    
    // Проверяем, что сообщение начинается с "user"
    if (message.substr(0, 4) != "user") {
        std::cerr << "Сообщение не начинается с 'user'" << std::endl;
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
        std::cerr << "Неверный формат соли" << std::endl;
        logger_.log("Неверный формат соли", false);
        send(sock_, "ERR", 3, 0);
        return false;
    }
    
    if (!is_hex(received_hash) || received_hash.length() != 64) {
        std::cerr << "Неверный формат хеша" << std::endl;
        logger_.log("Неверный формат хеша", false);
        send(sock_, "ERR", 3, 0);
        return false;
    }
    
    // Используем метод для аутентификации с хешем
    if (!db_.authWithHash(login, received_hash, salt)) {
        std::cerr << "Аутентификация не удалась" << std::endl;
        logger_.log("Аутентификация не удалась для: " + login, false);
        send(sock_, "ERR", 3, 0);
        return false;
    }
    
    if (send(sock_, "OK", 2, 0) != 2) {
        std::cerr << "Ошибка отправки OK" << std::endl;
        logger_.log("Ошибка отправки подтверждения аутентификации", false);
        return false;
    }
    
    std::cout << "Аутентификация успешна, отправлено OK" << std::endl;
    logger_.log("Клиент аутентифицирован: " + login);
    return true;
}

/**
 * @brief Обработка векторов данных от клиента
 * @return true — успешно, false — ошибка
 */
 
bool ClientSession::processVectors() {
    // Принимаем количество векторов (4 байта)
    uint32_t num_vectors;
    std::cout << "\nОжидание количества векторов (4 байта)..." << std::endl;
    
    if (!recvAll(&num_vectors, sizeof(uint32_t))) {
        std::cerr << "Ошибка приема количества векторов" << std::endl;
        logger_.log("Ошибка приема количества векторов", false);
        return false;
    }
    
    // Конвертируем из little-endian
    num_vectors = le32toh(num_vectors);
    
    std::cout << "Будет обработано " << num_vectors << " векторов" << std::endl;
    
    if (num_vectors == 0) {
        std::cout << "Клиент запросил обработку 0 векторов" << std::endl;
        logger_.log("Получен запрос на обработку 0 векторов");
        return true;  // Нет векторов - просто завершаем успешно
    }
    
    if (num_vectors > 100) {
        std::cerr << "Слишком большое количество векторов: " << num_vectors << std::endl;
        logger_.log("Слишком большое количество векторов: " + std::to_string(num_vectors), false);
        return false;
    }
    
    for (uint32_t i = 0; i < num_vectors; i++) {
        std::cout << "\n=== Обработка вектора " << i + 1 << " из " << num_vectors << " ===" << std::endl;
        
        // Принимаем размер вектора (4 байта)
        uint32_t size;
        std::cout << "Ожидание размера вектора (4 байта)..." << std::endl;
        
        if (!recvAll(&size, sizeof(uint32_t))) {
            std::cerr << "Ошибка приема размера вектора " << i + 1 << std::endl;
            logger_.log("Ошибка приема размера вектора " + std::to_string(i + 1), false);
            return false;
        }
        
       
        size = le32toh(size);
        
        std::cout << "Размер вектора " << i + 1 << ": " << size << " элементов" << std::endl;
        
        if (size == 0) {
            // Для пустого вектора отправляем результат 0 (8 байт)
            std::cout << "Пустой вектор, отправляем результат 0" << std::endl;
            int64_t result = 0;
            result = htole64(result);
            if (!sendAll(&result, sizeof(int64_t))) {
                std::cerr << "Ошибка отправки результата для пустого вектора" << std::endl;
                logger_.log("Ошибка отправки результата для пустого вектора", false);
                return false;
            }
            continue;
        }
        
        if (size > 100000) {
            std::cerr << "Слишком большой размер вектора: " << size << std::endl;
            logger_.log("Слишком большой размер вектора: " + std::to_string(size), false);
            return false;
        }
        
        // Выделяем память для данных вектора
        std::vector<int64_t> data(size);
        
        // Принимаем данные вектора (size * 8 байт)
        size_t total_bytes = size * sizeof(int64_t);
        std::cout << "Ожидается " << total_bytes << " байт данных (" 
                  << size << " элементов по " << sizeof(int64_t) << " байт)" << std::endl;
        
        if (!recvAll(data.data(), total_bytes)) {
            std::cerr << "Ошибка приема данных вектора " << i + 1 
                     << ", ожидалось " << total_bytes << " байт" << std::endl;
            logger_.log("Ошибка приема данных вектора " + std::to_string(i + 1) + 
                       ", ожидалось " + std::to_string(total_bytes) + " байт", false);
            return false;
        }
        
      
        for (auto& val : data) {
            val = le64toh(val);
        }
        
        // Вычисляем сумму
        int64_t sum = 0;
        bool overflow_detected = false;
        for (const auto& val : data) {
           
            if ((val > 0 && sum > INT64_MAX - val) || 
                (val < 0 && sum < INT64_MIN - val)) {
                overflow_detected = true;
                break;
            }
            sum += val;
        }
        
      
        int64_t avg = 0;
        if (!overflow_detected && size > 0) {
            avg = sum / static_cast<int64_t>(size);
        } else if (overflow_detected) {
            avg = (sum > 0) ? INT64_MAX : INT64_MIN;
        }
        
        
        if (size <= 10) {
            
            std::cout << "Вектор " << i + 1 << " данные: ";
            for (size_t j = 0; j < size; j++) {
                std::cout << data[j];
                if (j < size - 1) std::cout << ", ";
            }
            std::cout << std::endl;
        } else {
           
            std::cout << "Вектор " << i + 1 << " данные (первые 3 из " << size << "): ";
            for (size_t j = 0; j < 3; j++) {
                std::cout << data[j];
                if (j < 2) std::cout << ", ";
            }
            std::cout << ", ..." << std::endl;
        }
        
        std::cout << "Сумма: " << sum << ", Среднее арифметическое: " << avg << std::endl;
        
        if (overflow_detected) {
            std::cout << "Обнаружено переполнение!" << std::endl;
        }
        

        int64_t result_to_send = htole64(avg);
        std::cout << "Отправка результата для вектора " << i + 1 << ": " << avg 
                  << " (" << sizeof(int64_t) << " байт)" << std::endl;
        
        if (!sendAll(&result_to_send, sizeof(int64_t))) {
            std::cerr << "Ошибка отправки результата вектора " << i + 1 << std::endl;
            logger_.log("Ошибка отправки результата вектора " + std::to_string(i + 1), false);
            return false;
        }
        
        std::cout << "Вектор " << i + 1 << " успешно обработан и результат отправлен" << std::endl;
    }
    
    std::cout << "\nОбработка всех " << num_vectors << " векторов завершена успешно" << std::endl;
    logger_.log("Обработка векторов завершена успешно, обработано: " + std::to_string(num_vectors));
    
    return true;
}

/**
 * @brief Запуск сессии клиента
 */
 
void ClientSession::run() {
    std::cout << "\n=== ЗАПУСК СЕССИИ ДЛЯ КЛИЕНТА ===" << std::endl;
    
    if (!auth()) {
        std::cerr << "Ошибка аутентификации, закрытие соединения" << std::endl;
        logger_.log("Ошибка аутентификации", false);
        close(sock_);
        return;
    }
    
    std::cout << "\nАутентификация успешна, обработка векторов..." << std::endl;
    
    if (processVectors()) {
        std::cout << "\n=== СЕССИЯ ЗАВЕРШЕНА УСПЕШНО ===" << std::endl;
    } else {
        std::cerr << "\nОшибка обработки векторов" << std::endl;
        logger_.log("Ошибка обработки векторов", false);
        std::cout << "=== СЕССИЯ ЗАВЕРШЕНА С ОШИБКАМИ ===" << std::endl;
    }
    
    std::cout << "Закрытие соединения...\n" << std::endl;
    close(sock_);
}
