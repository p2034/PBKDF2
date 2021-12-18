#include <iostream>
#include <stdexcept>
#include <cstdlib>
#include <ctime>


#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>

#include <iomanip>
#include <sstream>


#include "hmac.h"
#include "sha256.h"
#include "pbkdf2.h"



std::string PBKDF2_HMAC_SHA_256_string(std::string pass, std::string salt, 
                                       uint32_t iterations, size_t size) {
  uint8_t * digest = new uint8_t[size];

  PKCS5_PBKDF2_HMAC(pass.c_str(), pass.length(), 
                    reinterpret_cast<const uint8_t *>(salt.c_str()), salt.length(),
                    iterations, EVP_sha256(), size, digest);

  std::stringstream hexRes;
  hexRes << std::setfill('0') << std::hex;
	for(int i = 0; i < size; i++)
		hexRes << std::setw(2) << (unsigned int) digest[i];

  return hexRes.str();
}



uint8_t* hmac_sha256(const uint8_t* data, uint64_t dataSize, const uint8_t* key, uint64_t keySize) {
  return hmac(sha256, SHA256_HASH_SIZE, SHA256_BLOCK_SIZE, data, dataSize, key, keySize);
}




void test_rand_pbkdf2(uint64_t passwordSize, uint64_t saltSize, uint64_t keySize) {
  srand(time(0));
  uint8_t* password = new uint8_t[passwordSize];
  for (int i = 0; i < passwordSize; i++)
    password[i] = rand()%256;

  uint8_t* salt = new uint8_t[saltSize];
  for (int i = 0; i < saltSize; i++)
    salt[i] = rand()%256;

  uint8_t* key = pbkdf2(hmac_sha256, SHA256_HASH_SIZE, password, passwordSize, salt, saltSize, 2000, keySize);

  for (int i = 0; i < keySize; i++)
    std::cout << std::hex << (int)key[i] << " ";
  std::cout << std::endl;
}



void test_const_pbkdf2(uint64_t keySize) {

  std::string strpass = "text";
  uint64_t passwordSize = strpass.length();
  std::string strsalt = "salt";
  uint64_t saltSize = strsalt.length();
  
  uint8_t* password = new uint8_t[passwordSize];
  for (int i = 0; i < passwordSize; i++)
    password[i] = strpass[i];

  uint8_t* salt = new uint8_t[saltSize];
  for (int i = 0; i < saltSize; i++)
    salt[i] = strsalt[i];

  uint8_t* key = pbkdf2(hmac_sha256, SHA256_HASH_SIZE, password, passwordSize, salt, saltSize, 2000, keySize);

  for (int i = 0; i < keySize; i++)
    std::cout << std::hex << (int)key[i] << " ";
  std::cout << std::endl;

  std::cout << PBKDF2_HMAC_SHA_256_string(strpass, strsalt, 2000, keySize)  << "\n";
}



int main() {
  try {
    //test_rand_pbkdf2(32, 8, 32);
    test_const_pbkdf2(32);

  } catch(const std::exception& excpt) {
    std::cout << excpt.what() << "\n";
  }

	return 0;
}