/*
* Title       : Implementation of ChaCha20 Stream Cipher
* Author      : Ajaya Kumar Patel
* Roll No.    : CRS2503
* Course      : Cryptographic and Security Implementations
* Date        : 28 July 2026
* Description : C implementation of the ChaCha20 stream cipher using a
*               256-bit key and 96-bit nonce for encryption and decryption. 
*/

#include <stdio.h>
#include <stdint.h>
#include <string.h>

// Rotate left
static uint32_t rotl32(uint32_t x, int n){
    return (x << n) | (x >> (32 - n));
}

// Pack 4 bytes into a 32-bit little-endian integer
static uint32_t pack4(const uint8_t *a){
    uint32_t res = 0;
    res |= (uint32_t)a[0] << 0;
    res |= (uint32_t)a[1] << 8;
    res |= (uint32_t)a[2] << 16;
    res |= (uint32_t)a[3] << 24;
    return res;
}

// Unpack 32-bit integer into 4 bytes
static void unpack4(uint8_t *a, uint32_t x)
{
    a[0] = (uint8_t)x;
    a[1] = (uint8_t)(x >> 8);
    a[2] = (uint8_t)(x >> 16);
    a[3] = (uint8_t)(x >> 24);
}

// Quarter Round
static void quarter_round(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d){
    *a += *b;
    *d ^= *a;
    *d = rotl32(*d, 16);

    *c += *d;
    *b ^= *c;
    *b = rotl32(*b, 12);

    *a += *b;
    *d ^= *a;
    *d = rotl32(*d, 8);

    *c += *d;
    *b ^= *c;
    *b = rotl32(*b, 7);
}



// Generate one block of keystream
void chacha20_block(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12], uint8_t output[64]){
    static const uint32_t constants[4] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};

    uint32_t state[16];
    uint32_t working[16];
    int i;

    // Constants
    state[0] = constants[0];
    state[1] = constants[1];
    state[2] = constants[2];
    state[3] = constants[3];

    // Key
    for(i = 0; i < 8; i++){
        state[4 + i] = pack4(key + i * 4);
    }

    // Counter
    state[12] = counter;

    // Nonce
    state[13] = pack4(nonce + 0);
    state[14] = pack4(nonce + 4);
    state[15] = pack4(nonce + 8);

    memcpy(working, state, sizeof(state));

    // 20 rounds (10 double rounds)
    for(i = 0; i < 10; i++){
        // Column rounds
        quarter_round(&working[0], &working[4], &working[8], &working[12]);
        quarter_round(&working[1], &working[5], &working[9], &working[13]);
        quarter_round(&working[2], &working[6], &working[10], &working[14]);
        quarter_round(&working[3], &working[7], &working[11], &working[15]);

        // Diagonal rounds
        quarter_round(&working[0], &working[5], &working[10], &working[15]);
        quarter_round(&working[1], &working[6], &working[11], &working[12]);
        quarter_round(&working[2], &working[7], &working[8], &working[13]);
        quarter_round(&working[3], &working[4], &working[9], &working[14]);
    }

    // Add original state
    for(i = 0; i < 16; i++){
        working[i] += state[i];
    }

    // Store result back as bytes
    for(i = 0; i < 16; i++){
        unpack4(output + i * 4, working[i]);
    }
}

// Same function works for both encryption and decryption
void chacha20_encrypt(
    const char *operation,
    const uint8_t key[32],
    const uint8_t nonce[12],
    uint32_t counter,
    const uint8_t *input,
    uint8_t *output,
    size_t length)
{
    printf("%s...\n", operation);
    uint8_t keystream[64];

    while(length > 0){
        chacha20_block(key, counter, nonce, keystream);

        size_t block = (length < 64) ? length : 64;

        for(size_t i = 0; i < block; i++){
            output[i] = input[i] ^ keystream[i];
        }

        input += block;
        output += block;
        length -= block;
        counter++;
    }
    printf("%s Completed.\n", operation);
}

int main(void){
    printf("============================================================\n");
    printf("              ChaCha20 Stream Cipher Demo\n");
    printf("============================================================\n\n");

    uint8_t key[32];
    uint8_t nonce[12];

    for(int i = 0; i < 32; i++){
        key[i] = i;
    }

    for(int i = 0; i < 12; i++){
        nonce[i] = i;
    }

    char plaintext[] = "After four failed attempts, the program finally compiled without warnings, and that felt more satisfying than expected.";
    printf("Input Plaintext: %s \n \n", plaintext);

    size_t len = strlen(plaintext);

    uint8_t ciphertext[128];
    uint8_t decrypted[128];

    // Encrypt
    printf("------------------------------------------------------------\n");
    printf("Encryption\n");
    printf("------------------------------------------------------------\n");
    
    chacha20_encrypt("Encryption", key, nonce, 1, (uint8_t *)plaintext, ciphertext, len);

    printf("Ciphertext:\n");

    for(size_t i = 0; i < len; i++){
        printf("%02X", ciphertext[i]);
    }

    printf("\n");

    // Decrypt
    printf("\n------------------------------------------------------------\n");
    printf("Decryption\n");
    printf("------------------------------------------------------------\n");

    chacha20_encrypt("Decryption", key, nonce, 1, ciphertext, decrypted, len);

    decrypted[len] = '\0';

    printf("Recovered Plaintext:\n%s\n\n", decrypted);

    printf("============================================================\n");
    printf("        Encryption and Decryption Successful\n");
    printf("============================================================\n");

    return 0;
}



/*
 * References:
 * 1. OpenAI. ChatGPT (GPT-5.5). Used for understanding the ChaCha20 algorithm,
 *    code review, and implementation guidance.
 *    https://chatgpt.com/
 *
 * 2. Ginurx. "chacha20-c" (C implementation of ChaCha20).
 *    GitHub Repository:
 *    https://github.com/Ginurx/chacha20-c/blob/master/chacha20.c
 */