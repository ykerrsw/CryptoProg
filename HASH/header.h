#include <iostream>
#include <string> 
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>
using namespace std;

class Hash{
private:
public:
    string generate_salt();
    string hashing(const std::string& salt, const std::string& ish);};