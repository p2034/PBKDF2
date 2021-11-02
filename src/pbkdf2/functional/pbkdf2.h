// Copyright (c) 2021 Kandakov Danil (p2034 or the_lll_end)
// https://github.com/p2034



/**
 * @file
 * @brief functional implementation of pbkdf2
 */

#ifndef PBKDF2_H
#define PBKDF2_H



// get i-th block for pbkdf2
static uint8_t* pbkdf2_getBlock(uint8_t* (*PRF)(const uint8_t*, uint64_t, const uint8_t*, uint64_t), uint64_t hSize,
                  const uint8_t* password, uint64_t pSize,
                  const uint8_t* salt, uint64_t sSize,
                  uint64_t index, uint64_t itnum);



// get number of blocks in key
static uint64_t pbkdf2_numberOfBlocks(uint64_t kSize, uint64_t hSize, uint64_t& lastBlockSize);



// main function of pbkdf2 implementation
uint8_t* pbkdf2(uint8_t* (*PRF)(const uint8_t*, uint64_t, const uint8_t*, uint64_t), uint64_t hSize,
                const uint8_t* password, uint64_t pSize,
                const uint8_t* salt, uint64_t sSize,
                uint64_t itnum, uint64_t kSize);



#endif