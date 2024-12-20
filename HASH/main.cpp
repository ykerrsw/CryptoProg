#include <iostream>
#include <string>
#include <fstream>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include "header.h"
using namespace std;

constexpr int salt_size = 12; // размер соли в байтах
int main(int argc, char *argv[]) {
    
    
    
     string line;
     ifstream file("auth_base.txt");
     if (!file.is_open()) {
        std::cerr << "Ошибка при открытии файла " << strerror(errno) << std::endl;
        return 0; }
        
     string mass = "";
     while (std::getline(file, line)) 
    {
        mass += line + "\n";
    }

    file.close();
    

    
    Hash test;
    string rez = test.generate_salt();
    string rez_hash = test.hashing(rez, mass);
    cout<<"Хеш содержимого файла: "<< rez_hash;
    return 0;
    
         }
