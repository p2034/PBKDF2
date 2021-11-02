// Copyright (c) 2021 Kandakov Danil (p2034 or the_lll_end)
// https://github.com/p2034



/**
 * @file
 * @brief oop implementation of pbkdf2
 */

#include <cstdint>
#include <cstring>
#include <stdexcept>

#include "pbkdf2.h"



/**
 * @brief init
 *
 * @param [in] PRF hash function with key
 * @param [in] hSize size of value from PRF
 * @param [in] itnum number of iterations
 * @param [in] kSize size of key we need
 *
 * @return array[ hSize ]
 * 
 * Functions used hash algorithm for getting one of blocks for key in pbkdf2
 */
PBKDF2::PBKDF2(uint8_t* (*PRF)(const uint8_t*, uint64_t, const uint8_t*, uint64_t), uint64_t hSize, 
               uint64_t itnum, uint64_t kSize) {
  if (itnum == 0)
    throw std::invalid_argument("Iteration number can't be 0");
  if (kSize == 0)
    throw std::invalid_argument("Key size can't be 0");
  if (hSize == 0)
    throw std::invalid_argument("Hash size can't be 0");
  
  PRF_ = PRF;
  hSize_ = hSize;
  itnum_ = itnum;
  kSize_ = kSize;
  
  // get blocks info
  numberOfBlocks_ = kSize_ / hSize_;
  lastBlockSize_ = kSize_ % hSize_;

  if (lastBlockSize_ != 0)
    ++numberOfBlocks_;
  else
    lastBlockSize_ = hSize_;
}



/**
 * @brief get index-th block
 *
 * @param [in] password master password which we must convert into key
 * @param [in] pSize password size
 * @param [in] salt salt for PRF
 * @param [in] sSize salt size
 * @param [in] index index of block
 *
 * @return array[ hSize ]
 * 
 * Functions used hash algorithm for getting one of blocks for key in pbkdf2
 */
uint8_t* PBKDF2::getBlock(const uint8_t* password, uint64_t pSize, 
                          const uint8_t* salt, uint64_t sSize, uint64_t index) {
  uint8_t* block = new uint8_t[hSize_];
  uint8_t* prevHash;
  uint8_t* nextHash;

  // get first hash
  uint64_t siSize = sSize + sizeof(uint64_t);
  uint8_t* si = new uint8_t[siSize];
  std::memcpy(si, salt, sSize);
  std::memcpy(&(si[sSize]), &index, sizeof(uint64_t));

  prevHash = PRF_(password, pSize, si, siSize);
  delete[] si;

  // copy first hash in block
  std::memcpy(block, prevHash, hSize_);

  for (int i = 0; i < itnum_; i++) {
    nextHash = PRF_(password, pSize, prevHash, hSize_);
    // xor for block with next hash
    for (int j = 0; j < hSize_; j++)
      block[j] = block[j] ^ nextHash[j];

    delete[] prevHash;
    prevHash = nextHash;
  }
  delete[] prevHash;

  return block;
}



/**
 * @brief main function of pbkdf2 implementation
 *
 * @param [in] password master password which we must convert into key
 * @param [in] pSize password size
 * @param [in] salt salt for PRF
 * @param [in] sSize salt size
 *
 * @return key array[ kSize ]
 */
uint8_t* PBKDF2::get(const uint8_t* password, uint64_t pSize, const uint8_t* salt, uint64_t sSize) {
  if (sSize == 0)
    throw std::invalid_argument("Salt size can't be 0");
  if (pSize == 0)
    throw std::invalid_argument("Password size can't be 0");

  uint8_t* key = new uint8_t[kSize_];

  // set blocks in key
  for (int i = 0; i < (numberOfBlocks_ - 1); i++) {
    uint8_t* block = this->getBlock(password, pSize, salt, sSize, i);
    std::memcpy(&(key[hSize_ * i]), block, hSize_);
    delete block;
  }
  // set last block with different size
  uint8_t* block = this->getBlock(password, pSize, salt, sSize, numberOfBlocks_ - 1);
  std::memcpy(&(key[hSize_ * (numberOfBlocks_ - 1)]), block, lastBlockSize_);

  return key;
}