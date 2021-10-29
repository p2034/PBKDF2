#include <iostream>
#include <stdexcept>
#include <cstdlib>
#include <ctime>

#include "../src/pbkdf2/oop/pbkdf2.h"

#define HASH_SIZE 32

uint8_t* testPRF(const uint8_t*, uint16_t, const uint8_t*, uint16_t) {
  uint16_t hashSize = HASH_SIZE;
  uint8_t* hash = new uint8_t[hashSize];
  for (int i = 0; i < hashSize; i++)
    hash[i] = i;
  
  return hash;
}



void test_rand_pbkdf2(uint16_t passwordSize, uint16_t saltSize, uint16_t keySize) {
  PBKDF2 pbkdf2(testPRF, HASH_SIZE, 2000, keySize);

  srand(time(0));
  uint8_t* password = new uint8_t[passwordSize];
  for (int i = 0; i < passwordSize; i++)
    password[i] = rand()%256;

  uint8_t* salt = new uint8_t[saltSize];
  for (int i = 0; i < saltSize; i++)
    salt[i] = rand()%256;

  uint8_t* key = pbkdf2.get(password, passwordSize, salt, saltSize);

  for (int i = 0; i < keySize; i++)
    std::cout << (int)key[i] << " ";
  std::cout << std::endl;
}



void test_const_pbkdf2(uint16_t passwordSize, uint16_t saltSize, uint16_t keySize) {
  PBKDF2 pbkdf2(testPRF, HASH_SIZE, 2000, keySize);

  uint8_t* password = new uint8_t[passwordSize];
  for (int i = 0; i < passwordSize; i++)
    password[i] = i;

  uint8_t* salt = new uint8_t[saltSize];
  for (int i = 0; i < saltSize; i++)
    salt[i] = i;

  uint8_t* key = pbkdf2.get(password, passwordSize, salt, saltSize);

  for (int i = 0; i < keySize; i++)
    std::cout << (int)key[i] << " ";
  std::cout << std::endl;
}




int main() {
  try {
    test_const_pbkdf2(20, 8, 32);

  } catch(const std::exception& excpt) {
    std::cout << excpt.what() << "\n";
  }

	return 0;
}