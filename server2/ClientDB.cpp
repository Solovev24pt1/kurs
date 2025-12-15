/**
 * @file ClientDB.cpp
 * @author Соловьев Арсений Евгеньевич
 * @version 1.0
 * @date 1.12.25
 * @copyright ПГУ ИБСТ
 * @brief Реализация класса ClientDB для работы с базой данных клиентов
 */

#include "server.h"
#include <fstream>
#include <sstream>
#include <openssl/sha.h>
#include <iomanip>
#include <algorithm>

/**
 * @brief Загружает базу данных клиентов из файла
 * @param filename Имя файла с базой данных
 * @return true в случае успешной загрузки, false в случае ошибки
 * @details Загружает пары логин-пароль из текстового файла.
 *          Каждая строка файла должна содержать логин и пароль, разделенные пробелом.
 *          Пустые строки и строки, начинающиеся с '#', игнорируются.
 */
 
bool ClientDB::load(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Ошибка открытия файла базы данных: " << filename << std::endl;
        return false;
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;
        std::istringstream iss(line);
        std::string login, password;
        if (iss >> login >> password) {
            clients_[login] = password;
            std::cout << "Загружен клиент: " << login << std::endl;
        }
    }
    return true;
}

/**
 * @brief Аутентифицирует клиента по логину и паролю
 * @param login Логин клиента
 * @param password Пароль клиента
 * @return true если аутентификация успешна, false в противном случае
 * @details Проверяет наличие логина в базе и совпадение пароля.
 *          Выводит результат проверки в стандартный вывод.
 */
 
bool ClientDB::auth(const std::string& login, const std::string& password) const {
    auto it = clients_.find(login);
    if (it == clients_.end()) {
        std::cout << "Клиент не найден: " << login << std::endl;
        return false;
    }
    
    bool result = (it->second == password);
    std::cout << "Аутентификация " << login << ": " << (result ? "УСПЕХ" : "НЕУДАЧА") << std::endl;
    return result;
}

/**
 * @brief Аутентифицирует клиента по хешу с использованием соли
 * @param login Логин клиента
 * @param received_hash Полученный хеш от клиента
 * @param salt Соль, использованная для хеширования
 * @return true если аутентификация успешна, false в противном случае
 * @details Вычисляет хеш SHA256 от соли и пароля, сравнивает с полученным хешем.
 *          Используется в основном протоколе аутентификации сервера.
 */
 
bool ClientDB::authWithHash(const std::string& login, const std::string& received_hash, const std::string& salt) const {
    auto it = clients_.find(login);
    if (it == clients_.end()) {
        std::cout << "Клиент не найден в базе: '" << login << "'" << std::endl;
        std::cout << "Доступные логины в базе:" << std::endl;
        for (const auto& client : clients_) {
            std::cout << "  '" << client.first << "'" << std::endl;
        }
        return false;
    }
    
    std::string password = it->second;
    std::cout << "Найден пароль для логина '" << login << "': '" << password << "'" << std::endl;
    
    std::string data = salt + password;
    
    std::cout << "Соль (hex): ";
    for (char c : salt) {
        printf("%02x", (unsigned char)c);
    }
    std::cout << std::endl;
    
    std::cout << "Данные для хеширования (соль+пароль): '";
    for (char c : data) {
        if (std::isprint((unsigned char)c)) {
            std::cout << c;
        } else {
            printf("\\x%02x", (unsigned char)c);
        }
    }
    std::cout << "'" << std::endl;
    std::cout << "Длина данных: " << data.length() << std::endl;
    
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)data.c_str(), data.length(), hash);
    
    std::stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    std::string expected_hash = ss.str();
    
    // Приводим к нижнему регистру для сравнения
    std::transform(expected_hash.begin(), expected_hash.end(), expected_hash.begin(), ::tolower);
    std::string received_hash_lower = received_hash;
    std::transform(received_hash_lower.begin(), received_hash_lower.end(), received_hash_lower.begin(), ::tolower);
    
    std::cout << "Ожидаемый хеш:  " << expected_hash << std::endl;
    std::cout << "Полученный хеш: " << received_hash_lower << std::endl;
    std::cout << "Длина ожидаемого хеша: " << expected_hash.length() << std::endl;
    std::cout << "Длина полученного хеша: " << received_hash_lower.length() << std::endl;
    
    bool result = (expected_hash == received_hash_lower);
    std::cout << "Аутентификация '" << login << "': " << (result ? "УСПЕХ" : "НЕУДАЧА") << std::endl;
    
    if (!result) {
        std::cout << "Хеши не совпадают!" << std::endl;
        // Выводим различия
        for (size_t i = 0; i < std::min(expected_hash.length(), received_hash_lower.length()); i++) {
            if (expected_hash[i] != received_hash_lower[i]) {
                std::cout << "Первое отличие на позиции " << i << ": ожидалось '" << expected_hash[i] 
                         << "', получено '" << received_hash_lower[i] << "'" << std::endl;
                break;
            }
        }
    }
    
    return result;
}
