#include "header.h"
namespace CPP = CryptoPP;

std::string Hash::generate_salt() {
    int salt_size = 12;
    CPP::byte salt[salt_size];
    CPP::AutoSeededRandomPool prng;
    prng.GenerateBlock(salt, salt_size);
    std::string salt_16;
    CPP::HexEncoder encoder(new CPP::StringSink(salt_16));
    encoder.Put(salt, salt_size);
    encoder.MessageEnd(); //Важно! Завершаем кодирование
    return salt_16;
}

std::string Hash::hashing(const std::string& salt, const std::string& ish) {
    CPP::SHA256 sha256;
    std::string hash_16;
    CPP::StringSource(salt + ish, true,
                      new CPP::HashFilter(sha256,
                                          new CPP::HexEncoder(new CPP::StringSink(hash_16))));
    return hash_16;
}
