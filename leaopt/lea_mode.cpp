/**
 * MIT License
 * 
 * Copyright (c) 2019 Ilwoong Jeong, https://github.com/ilwoong
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
#include "HardwareSerial.h"

const size_t RKS_SIZE = 24 * 24;

void lea_ecb_encrypt(uint8_t* out, const uint8_t* in, const uint8_t* key, size_t length)
{
    const size_t blocksize = 16;
    if (length % blocksize != 0)
    {
        Serial.println("length is not multiple of 16");
        return; 
    }

    uint8_t rks[RKS_SIZE] = {0,};
    lea128_keygen(rks, key);

    while (length > 0) {
        lea128_encrypt(out, in, rks);

        in += blocksize;
        out += blocksize;
        length -= blocksize;
    }
}

void lea_ecb_decrypt(uint8_t* out, const uint8_t* in, const uint8_t* key, size_t length)
{
    const size_t blocksize = 16;
    if (length % blocksize != 0)
    {
        Serial.println("length is not multiple of 16");
        return; 
    }

    uint8_t rks[RKS_SIZE] = {0,};
    lea128_keygen(rks, key);

    while (length > 0) {
        lea128_decrypt(out, in, rks);

        in += blocksize;
        out += blocksize;
        length -= blocksize;
    }
}

static void xor_bytes(uint8_t* out, const uint8_t* lhs, const uint8_t* rhs, size_t length)
{
    for (int i = 0; i < length; ++i) {
      out[i] = lhs[i] ^ rhs[i];
    }
}

static void increase_counter(uint8_t* ctr_copy, size_t blocksize)
{
    int idx = blocksize - 1;
    while ( (++ctr_copy[idx]) == 0 && idx != 0) {
        --idx;
    }
}

void lea_ctr_encrypt(uint8_t* out, const uint8_t* in, const uint8_t* key, const uint8_t* ctr, size_t length)
{
    const size_t blocksize = 16;

    uint8_t rks[RKS_SIZE] = {0,};
    lea128_keygen(rks, key);

    uint8_t keystream[blocksize] = {0};
    uint8_t ctr_copy[blocksize] = {0};

    memcpy(ctr_copy, ctr, blocksize);

    while (length >= blocksize) {
        lea128_encrypt(keystream, ctr_copy, rks);
        xor_bytes(out, in, keystream, blocksize);
        increase_counter(ctr_copy, blocksize);

        in += blocksize;
        out += blocksize;
        length -= blocksize;
    }

    if (length > 0) {
        lea128_encrypt(keystream, ctr_copy, rks);
        xor_bytes(out, in, keystream, length);
    }
}

void lea_ctr_decrypt(uint8_t* out, const uint8_t* in, const uint8_t* key, const uint8_t* ctr, size_t length)
{
    lea_ctr_encrypt(out, in, key, ctr, length);  
}
