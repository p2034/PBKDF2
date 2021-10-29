// Copyright (c) 2021 Kandakov Danil (p2034 or the_lll_end)
// https://github.com/p2034



/**
 * @file
 * @brief functional implementation of pbkdf2
 */

#ifndef PBKDF2_H
#define PBKDF2_H



// get i-th block for pbkdf2
static uint8_t* pbkdf2_getBlock(uint8_t* (*PRF)(const uint8_t*, uint16_t, const uint8_t*, uint16_t), uint16_t hSize,
                  const uint8_t* password, uint16_t pSize,
                  const uint8_t* salt, uint16_t sSize,
                  uint16_t index, uint16_t itnum);



// get number of blocks in key
static uint16_t pbkdf2_numberOfBlocks(uint16_t kSize, uint16_t hSize, uint16_t& lastBlockSize);



// main function of pbkdf2 implementation
uint8_t* pbkdf2(uint8_t* (*PRF)(const uint8_t*, uint16_t, const uint8_t*, uint16_t), uint16_t hSize,
                const uint8_t* password, uint16_t pSize,
                const uint8_t* salt, uint16_t sSize,
                uint16_t itnum, uint16_t kSize);



#endif