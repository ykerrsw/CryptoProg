#include <iostream>
#include <fstream>
#include <string>

#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/sha.h>
#include <cryptopp/pwdbased.h> 
#include <cryptopp/osrng.h>

using namespace CryptoPP;

void encrypt(const std::string& inputFile, const std::string& outputFile, const std::string& password) {
    // Создаем блок байтов для ключа шифрования
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);                                                            
   
    // Создаем объект PBKDF2 для выработки ключа из пароля
    PKCS12_PBKDF<SHA256> pbkdf;
    pbkdf.DeriveKey(key, key.size(), 0, (byte*)password.data(), password.size(), NULL, 0, 1000, 0.0f);

    // Генерация случайного вектора инициализации
    AutoSeededRandomPool prng; 
    SecByteBlock iv(AES::BLOCKSIZE);
    prng.GenerateBlock(iv, iv.size());

    // Сохранение вектора в файл
    std::string iv_file = "hash.txt"; 
    StringSource(iv, iv.size(), true,
                 new HexEncoder(
                     new FileSink(iv_file.c_str())));                        
    std::clog << "hash сгенерирован и сохранён в: " << iv_file << std::endl;

    // Шифруем файл
    CBC_Mode<AES>::Encryption enc(key, key.size(), iv);
    FileSource fs(inputFile.c_str(), true,
                  new StreamTransformationFilter(enc,
                  new FileSink(outputFile.c_str())));
    std::clog << "Файл " << inputFile << " зашифрован и сохранён в: " << outputFile << std::endl;
}

void decrypt(const std::string& inputFile, const std::string& outputFile, const std::string& password) {
    // Создаем блок байтов для ключа шифрования
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);                                                            
   
    // Создаем объект PBKDF2 для выработки ключа из пароля
    PKCS12_PBKDF<SHA256> pbkdf;
    pbkdf.DeriveKey(key, key.size(), 0, (byte*)password.data(), password.size(), NULL, 0, 1000, 0.0f);

    // Чтение вектора инициализации из файла
    SecByteBlock iv(AES::BLOCKSIZE);
    std::string iv_file = "hash.txt"; 
    FileSource(iv_file.c_str(), true,
               new HexDecoder(
                   new ArraySink(iv, iv.size())));
    std::clog << "hash считан из: " << iv_file << std::endl;

    // Расшифровываем файл
    CBC_Mode<AES>::Decryption dec(key, key.size(), iv);
    FileSource fs(inputFile.c_str(), true,
                  new StreamTransformationFilter(dec,
                  new FileSink(outputFile.c_str())));
    std::clog << "Файл " << inputFile << " расшифрован и сохранён в: " << outputFile << std::endl;
}

int main() {
    std::string mode, inputFile, outputFile, password;
    std::cout << "Введите режим работы: e(encrypt) or d(decrypt): ";
    std::cin >> mode;
    std::cout << "Введите путь к входному файлу: ";
    std::cin >> inputFile;
    std::cout << "Введите путь к выходному файлу: ";
    std::cin >> outputFile;
    std::cout << "Введите пароль: ";
    std::cin >> password;

    if (mode == "e") {
        encrypt(inputFile, outputFile, password);
    } 
    else if (mode == "d") {
        decrypt(inputFile, outputFile, password);
    } 
    else {
        std::cout << "Неверный режим" << std::endl;
    }

    return 0;
}
