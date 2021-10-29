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
  uint16_t itnum_; ///< number of iteration 
  uint16_t kSize_; ///< key size

  uint16_t hSize_; ///< hash size
  uint8_t* (*PRF_)(const uint8_t*, uint16_t, const uint8_t*, uint16_t); ///< hash function

  uint16_t lastBlockSize_; // size of last block
  uint16_t numberOfBlocks_; ///< number of blocks in key

  // get index-th block
  uint8_t* getBlock(const uint8_t* password, uint16_t pSize, const uint8_t* salt, uint16_t sSize, uint16_t index);

public:
  // init and save hash function, iteration num, key size and hash size
  PBKDF2(uint8_t* (*PRF)(const uint8_t*, uint16_t, const uint8_t*, uint16_t), uint16_t hSize, 
         uint16_t itnum, uint16_t kSize);

  // get key by using pbkdf2 with password and salt
  uint8_t* get(const uint8_t* password, uint16_t pSize, const uint8_t* salt, uint16_t sSize);
};



#endif