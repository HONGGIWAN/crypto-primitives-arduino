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


#include "aes_test.h"
#include "aes.h"
#include "aes_mode.h"
#include "Arduino.h"

static const size_t RKS_SIZE = (AES128_ROUNDS + 1) * 16;

void print_hex(const char* title, const uint8_t* data, size_t count)
{
    Serial.println(title);
    for (size_t i = 0; i < count; ++i) {
        if (data[i] < 16) {
          Serial.print("0");
        }
        Serial.print(data[i], HEX);

        if (((i+1) & 0xf) == 0) {
            Serial.println();
        } else if ( ((i+1) & 0x3) == 0) {
            Serial.print(" ");
        }
    }

    if ( (count & 0xf) != 0) {
        Serial.println();
    }    
}

static void compare_block(const char* title, const uint8_t* lhs, const uint8_t* rhs)
{
    int out = memcmp(lhs, rhs, 16);

    Serial.println(title);
    print_hex("In ", lhs, 16);
    print_hex("Out", rhs, 16);

    if (out == 0) {
        Serial.println("passed");
    } else {
        Serial.println("failed");
    }

    Serial.println();
}

void aes128_benchmark()
{
    uint8_t mk[16] = {0};
    uint8_t pt[16] = {0};
    uint8_t ct[16] = {0};

    uint8_t enc[16] = {0};
    uint8_t dec[16] = {0};

    uint8_t rks[RKS_SIZE] = {0,};
    aes128_keygen(rks, mk);

    long start = micros();

    aes128_encrypt(enc, pt, rks);

    long elapsed = micros() - start;

    Serial.print("Elapsed time for AES-128 1 block encryption: ");
    Serial.println(elapsed);

    delay(1000);
}

void aes128_encrypt_test()
{
    uint8_t mk[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    uint8_t pt[] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
    uint8_t ct[] = {0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32};
    
    uint8_t enc[16] = {0};

    uint8_t rks[RKS_SIZE] = {0,};
    aes128_keygen(rks, mk);

    aes128_encrypt(enc, pt, rks);
    compare_block("AES-128 Encryption", enc, ct);
}

void aes128_decrypt_test() {
    uint8_t mk[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    uint8_t pt[] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
    uint8_t ct[] = {0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32};
        
    uint8_t dec[16] = {0};

    uint8_t rks[RKS_SIZE] = {0,};
    aes128_keygen(rks, mk);

    aes128_decrypt(dec, ct, rks);
    compare_block("AES-128 Decryption", dec, pt);
}

void aes128_ecb_test() {
    const size_t length = 64;
  
    uint8_t mk[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    uint8_t pt[] = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
    };
    uint8_t enc[length] = { 0 };
    uint8_t dec[length] = { 0 };

    aes_ecb_encrypt(enc, pt, mk, length);
    print_hex("AES ECB ENCRYPTED", enc, length);

    aes_ecb_decrypt(dec, enc, mk, length);
    print_hex("AES ECB DECRYPTED", dec, length);
    Serial.println();
}

void aes128_ctr_test() {
    const size_t length = 64;
  
    uint8_t mk[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    uint8_t ctr[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x00};
    uint8_t pt[] = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
    };
    uint8_t enc[length] = { 0 };
    uint8_t dec[length] = { 0 };

    aes_ctr_encrypt(enc, pt, mk, ctr, length);
    print_hex("AES CTR ENCRYPTED", enc, length);

    aes_ctr_decrypt(dec, enc, mk, ctr, length);
    print_hex("AES CTR DECRYPTED", dec, length);
    Serial.println();
}