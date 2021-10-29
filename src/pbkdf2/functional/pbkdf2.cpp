// Copyright (c) 2021 Kandakov Danil (p2034 or the_lll_end)
// https://github.com/p2034



/**
 * @file
 * @brief functional implementation of pbkdf2
 */

#include <cstdint>
#include <cstring>
#include <stdexcept>



/**
 * @brief get i-th block
 *
 * @param [in] PRF hash function with key
 * @param [in] hSize size of value from PRF
 * @param [in] password master password which we must convert into key
 * @param [in] pSize password size
 * @param [in] salt salt for PRF
 * @param [in] sSize salt size
 * @param [in] index index of block
 * @param [in] itnum number of iterations
 *
 * @return key array[ hSize ]
 * 
 * Functions used hash algorithm for getting one of blocks for key in pbkdf2
 */
static uint8_t* pbkdf2_getBlock(uint8_t* (*PRF)(const uint8_t*, uint16_t, const uint8_t*, uint16_t), uint16_t hSize,
                  const uint8_t* password, uint16_t pSize,
                  const uint8_t* salt, uint16_t sSize,
                  uint16_t index, uint16_t itnum) {
  uint8_t* block = new uint8_t[hSize];
  uint8_t* prevHash;
  uint8_t* nextHash;

  // get first hash
  uint16_t siSize = sSize + sizeof(uint16_t);
  uint8_t* si = new uint8_t[siSize];
  std::memcpy(si, salt, sSize);
  std::memcpy(&(si[sSize]), &index, sizeof(uint16_t));

  prevHash = PRF(password, pSize, si, siSize);
  delete[] si;

  // copy first hash in block
  std::memcpy(block, prevHash, hSize);

  for (int i = 0; i < itnum; i++) {
    nextHash = PRF(password, pSize, prevHash, hSize);
    // xor for block with next hash
    for (int j = 0; j < hSize; j++)
      block[j] = block[j] ^ nextHash[j];

    delete[] prevHash;
    prevHash = nextHash;
  }
  delete[] prevHash;

  return block;
}



/**
 * @brief get number of blocks in key
 *
 * @param [in] kSize size of key
 * @param [in] hSize size of hash
 * @param [out] lastBlockSize size of last block in pbkdf2 algorithm
 * 
 * @return number of blocks in pbkdf2 algorithm
 */
static uint16_t pbkdf2_numberOfBlocks(uint16_t kSize, uint16_t hSize, uint16_t& lastBlockSize) {
  uint16_t num; ///< number of blocks in key
  
  num = kSize / hSize;
  lastBlockSize = kSize % hSize;

  if (lastBlockSize != 0)
    ++num;
  else
    lastBlockSize = hSize;

  return num;
}



/**
 * @brief main function of pbkdf2 implementation
 *
 * @param [in] PRF hash function with key
 * @param [in] hSize size of value from PRF
 * @param [in] password master password which we must convert into key
 * @param [in] pSize password size
 * @param [in] salt salt for PRF
 * @param [in] sSize salt size
 * @param [in] itnum number of iterations
 * @param [in] kSize size of key we need
 *
 * @return array[ kSize ]
 */
uint8_t* pbkdf2(uint8_t* (*PRF)(const uint8_t*, uint16_t, const uint8_t*, uint16_t), uint16_t hSize,
                const uint8_t* password, uint16_t pSize,
                const uint8_t* salt, uint16_t sSize,
                uint16_t itnum, uint16_t kSize) {
  if (hSize == 0)
    throw std::invalid_argument("Hash size can't be 0");
  if (itnum == 0)
    throw std::invalid_argument("Iteration number can't be 0");
  if (kSize == 0)
    throw std::invalid_argument("Key size can't be 0");
  if (sSize == 0)
    throw std::invalid_argument("Salt size can't be 0");
  if (pSize == 0)
    throw std::invalid_argument("Password size can't be 0");

  uint8_t* key = new uint8_t[kSize];

  uint16_t lastBlockSize;
  uint16_t numOfBlocks = pbkdf2_numberOfBlocks(kSize, hSize, lastBlockSize);

  // set blocks in key
  for (int i = 0; i < (numOfBlocks - 1); i++) {
    uint8_t* block = pbkdf2_getBlock(PRF, hSize, password, pSize, salt, sSize, i, itnum);
    std::memcpy(&(key[hSize * i]), block, hSize);
    delete block;
  }
  // set last block with different size
  uint8_t* block = pbkdf2_getBlock(PRF, hSize, password, pSize, salt, sSize, numOfBlocks - 1, itnum);
  std::memcpy(&(key[hSize * (numOfBlocks - 1)]), block, lastBlockSize);

  return key;
}