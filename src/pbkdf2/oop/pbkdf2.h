// Copyright (c) 2021 Kandakov Danil (p2034 or the_lll_end)
// https://github.com/p2034



/**
 * @file
 * @brief oop implementation of pbkdf2
 */

#ifndef PBKDF2_H
#define PBKDF2_H


/**
 * @class PBKDF2
 * @brief get key using hashing algorithm
 */
class PBKDF2 {
private:
  uint64_t itnum_; ///< number of iteration 
  uint64_t kSize_; ///< key size

  uint64_t hSize_; ///< hash size
  uint8_t* (*PRF_)(const uint8_t*, uint64_t, const uint8_t*, uint64_t); ///< hash function

  uint64_t lastBlockSize_; // size of last block
  uint64_t numberOfBlocks_; ///< number of blocks in key

  // get index-th block
  uint8_t* getBlock(const uint8_t* password, uint64_t pSize, const uint8_t* salt, uint64_t sSize, uint64_t index);

public:
  // init and save hash function, iteration num, key size and hash size
  PBKDF2(uint8_t* (*PRF)(const uint8_t*, uint64_t, const uint8_t*, uint64_t), uint64_t hSize, 
         uint64_t itnum, uint64_t kSize);

  // get key by using pbkdf2 with password and salt
  uint8_t* get(const uint8_t* password, uint64_t pSize, const uint8_t* salt, uint64_t sSize);
};



#endif