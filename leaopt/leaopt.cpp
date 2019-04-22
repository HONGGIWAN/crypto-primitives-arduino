/**
 * MIT License
 * 
 * Copyright (c) 2018 Ilwoong Jeong, https://github.com/ilwoong
 * 
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */


#include "lea.h"
#include <string.h>

const static size_t LEA128_ROUNDS = 24;
const static size_t LEA192_ROUNDS = 28;
const static size_t LEA256_ROUNDS = 32;

const static uint32_t DELTA[8]= {
    0xc3efe9db, 0x44626b02, 0x79e27c8a, 0x78df30ec,
    0x715ea49e, 0xc785da0a, 0xe04ef22a, 0xe5c40957,
};

static inline uint32_t rot32r1(uint32_t value)
{
    return (value >> 1) | (value << 31);
}

static inline uint32_t rot32r8(uint32_t value)
{
    return (value >> 8) | (value >> 24);
}

static inline uint32_t rot32r9(uint32_t value)
{
    return rot32r8(rot32r1(value));
}

static inline uint32_t rot32l1(uint32_t value)
{
    return (value << 1) | (value >> 31);
}

static inline uint32_t rot32l8(uint32_t value)
{
    return (value << 8) | (value >> 24);
}

static inline uint32_t rot32l9(uint32_t value)
{
    return rot32l8(rot32l1(value));
}

static inline uint32_t rol32(uint32_t value, size_t rot)
{
    return (value << rot) | (value >> (32 - rot));
}

static inline uint32_t ror32(uint32_t value, size_t rot)
{
    return (value >> rot) | (value << (32 - rot));
}

/**
 * LEA 128-bit block, 128-bit key 
 */
void lea128_keygen(uint8_t* out, const uint8_t* mk)
{
    const uint32_t* t = (const uint32_t*) mk;
    uint32_t* rk = (uint32_t*) out;
    
    uint32_t t0 = t[0];
    uint32_t t1 = t[1];
    uint32_t t2 = t[2];
    uint32_t t3 = t[3];

    for(size_t round = 0; round < LEA128_ROUNDS; ++round) {
        uint32_t delta = DELTA[round & 3];
        
        t0 = rol32(t0 + rol32(delta, round), 1);
        t1 = rol32(t1 + rol32(delta, round + 1), 3);
        t2 = rol32(t2 + rol32(delta, round + 2), 6);
        t3 = rol32(t3 + rol32(delta, round + 3), 11);

        rk[0] = t0;
        rk[1] = t1;
        rk[2] = t2;
        rk[3] = t1;
        rk[4] = t3;
        rk[5] = t1;
        rk += 6;
    }
}

void lea128_encrypt(uint8_t* out, const uint8_t* in, const uint8_t* rks)
{
    const uint32_t* rk = (const uint32_t*) rks;
    const uint32_t* block = (const uint32_t*) in;
    uint32_t* outblk = (uint32_t*) out;

    uint32_t b0 = block[0];
    uint32_t b1 = block[1];
    uint32_t b2 = block[2];
    uint32_t b3 = block[3];

    for (size_t round = 0; round < LEA128_ROUNDS; round += 4)
    {
        b3 = ror32((b2 ^ rk[4]) + (b3 ^ rk[5]), 3);
        b2 = ror32((b1 ^ rk[2]) + (b2 ^ rk[3]), 5);
        b1 = rot32l9((b0 ^ rk[0]) + (b1 ^ rk[1]));
        rk += 6;

        b0 = ror32((b3 ^ rk[4]) + (b0 ^ rk[5]), 3);
        b3 = ror32((b2 ^ rk[2]) + (b3 ^ rk[3]), 5);
        b2 = rot32l9((b1 ^ rk[0]) + (b2 ^ rk[1]));
        rk += 6;

        b1 = ror32((b0 ^ rk[4]) + (b1 ^ rk[5]), 3);
        b0 = ror32((b3 ^ rk[2]) + (b0 ^ rk[3]), 5);
        b3 = rot32l9((b2 ^ rk[0]) + (b3 ^ rk[1]));
        rk += 6;

        b2 = ror32((b1 ^ rk[4]) + (b2 ^ rk[5]), 3);
        b1 = ror32((b0 ^ rk[2]) + (b1 ^ rk[3]), 5);
        b0 = rot32l9((b3 ^ rk[0]) + (b0 ^ rk[1]));
        rk += 6;
    }

    outblk[0] = b0;
    outblk[1] = b1;
    outblk[2] = b2;
    outblk[3] = b3;
}

void lea128_decrypt(uint8_t* out, const uint8_t* in, const uint8_t* rks)
{
    const uint32_t* rk = (const uint32_t*) rks;
    const uint32_t* block = (const uint32_t*) in;
    uint32_t* outblk = (uint32_t*) out;

    uint32_t b0 = block[0];
    uint32_t b1 = block[1];
    uint32_t b2 = block[2];
    uint32_t b3 = block[3];

    rk += 6 * (LEA128_ROUNDS - 1);
    for (size_t round = 0; round < LEA128_ROUNDS; round += 4)
    {
        b0 = (rot32r9(b0) - (b3 ^ rk[0])) ^ rk[1];
        b1 = (rol32(b1, 5) - (b0 ^ rk[2])) ^ rk[3];
        b2 = (rol32(b2, 3) - (b1 ^ rk[4])) ^ rk[5];
        rk -= 6;

        b3 = (rot32r9(b3) - (b2 ^ rk[0])) ^ rk[1];
        b0 = (rol32(b0, 5) - (b3 ^ rk[2])) ^ rk[3];
        b1 = (rol32(b1, 3) - (b0 ^ rk[4])) ^ rk[5];
        rk -= 6;

        b2 = (rot32r9(b2) - (b1 ^ rk[0])) ^ rk[1];
        b3 = (rol32(b3, 5) - (b2 ^ rk[2])) ^ rk[3];
        b0 = (rol32(b0, 3) - (b3 ^ rk[4])) ^ rk[5];
        rk -= 6;

        b1 = (rot32r9(b1) - (b0 ^ rk[0])) ^ rk[1];
        b2 = (rol32(b2, 5) - (b1 ^ rk[2])) ^ rk[3];
        b3 = (rol32(b3, 3) - (b2 ^ rk[4])) ^ rk[5];
        rk -= 6;
    }

    outblk[0] = b0;
    outblk[1] = b1;
    outblk[2] = b2;
    outblk[3] = b3;
}
