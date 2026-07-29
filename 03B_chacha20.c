/*
* Title       : Implementation of ChaCha20 Stream Cipher
* Author      : Ajaya Kumar Patel
* Roll No.    : CRS2503
* Course      : Cryptographic and Security Implementations
* Date        : 29 July 2026
* Description : C implementation of the ChaCha20 stream cipher using a
*               256-bit key and 96-bit nonce for encryption and decryption. 
*/

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <x86intrin.h>

#define ITERATIONS 100000

void chacha20_encrypt(const uint8_t key[32], 
                      const uint8_t nonce[12], uint32_t counter,
                      const uint8_t *input, uint8_t *output, size_t length);

static void quarter_round(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d);
static uint32_t rotl32(uint32_t x, int n);
static uint32_t pack4(const uint8_t *a);
static void unpack4(uint8_t *a, uint32_t x);
void chacha20_block(const uint8_t key[32], uint32_t counter, 
                    const uint8_t nonce[12], uint8_t output[64]);

void benchmark_chacha20(const uint8_t key[32],
                        const uint8_t nonce[12],
                        const uint8_t *plaintext,
                        size_t len);

int main(void){
    printf("============================================================\n");
    printf("              ChaCha20 Stream Cipher Demo\n");
    printf("============================================================\n\n");

    uint8_t key[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F
    };

    uint8_t nonce[12] = {
        0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x4A,
        0x00,0x00,0x00,0x00
    };

    char plaintext[] =
    "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    printf("Input Plaintext: %s \n \n", plaintext);

    size_t len = strlen(plaintext);

    uint8_t ciphertext[128];
    uint8_t decrypted[128];

    // Encrypt
    printf("------------------------------------------------------------\n");
    printf("Encryption\n");
    printf("------------------------------------------------------------\n");
    
    printf("Encryption...\n");
    chacha20_encrypt(key, nonce, 1, (uint8_t *)plaintext, ciphertext, len);
    printf("Encryption Completed.\n");

    printf("Ciphertext:\n");

    for(size_t i = 0; i < len; i++){
        printf("%02X", ciphertext[i]);
    }

    printf("\n");

    // Decrypt
    printf("\n------------------------------------------------------------\n");
    printf("Decryption\n");
    printf("------------------------------------------------------------\n");
    
    printf("Decryption...\n");
    chacha20_encrypt(key, nonce, 1, ciphertext, decrypted, len);
    printf("Decryption Completed.\n");

    decrypted[len] = '\0';

    printf("Recovered Plaintext:\n%s\n\n", decrypted);

    printf("============================================================\n");
    printf("        Encryption and Decryption Successful\n");
    printf("============================================================\n");

    benchmark_chacha20(key, nonce, (uint8_t *)plaintext, len);

    return 0;
}

// Same function works for both encryption and decryption
void chacha20_encrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    uint32_t counter,
    const uint8_t *input,
    uint8_t *output,
    size_t length)
{
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

void benchmark_chacha20(const uint8_t key[32],
                        const uint8_t nonce[12],
                        const uint8_t *plaintext,
                        size_t len)
{
    uint8_t ciphertext[128];

    unsigned int aux;

    struct timespec start_time, end_time;

    uint64_t start_cycles, end_cycles;

    clock_gettime(CLOCK_MONOTONIC, &start_time);

    volatile uint8_t checksum = 0;

    start_cycles = __rdtscp(&aux);

    for(int i = 0; i < ITERATIONS; i++) {
        chacha20_encrypt(key, nonce, 1, plaintext, ciphertext, len);
    }

    end_cycles = __rdtscp(&aux);
    clock_gettime(CLOCK_MONOTONIC, &end_time);

    for(size_t i = 0; i < len; i++){
        checksum ^= ciphertext[i];
    }

    printf("Checksum: %u\n", checksum);

    uint64_t total_ns =
        (end_time.tv_sec - start_time.tv_sec) * 1000000000ULL +
        (end_time.tv_nsec - start_time.tv_nsec);

    double avg_ns =
        (double)total_ns / ITERATIONS;

    double avg_cycles =
        (double)(end_cycles - start_cycles) / ITERATIONS;

    printf("\n========== Benchmark ==========\n");
    printf("Iterations          : %d\n", ITERATIONS);
    printf("Total Time          : %lu ns\n", total_ns);
    printf("Average Time        : %.2f ns\n", avg_ns);
    printf("Average CPU Cycles  : %.2f\n", avg_cycles);
}


/*
 * References:
 * 1. Y. Nir and A. Langley, "ChaCha20 and Poly1305 for IETF Protocols,"
 *    RFC 8439, Internet Engineering Task Force (IETF), June 2018.
 *    https://www.rfc-editor.org/rfc/rfc8439
 *
 * 2. OpenAI, ChatGPT (GPT-5.5). Used for understanding the
 *    ChaCha20 algorithm, implementation guidance, and code review.
 *    https://chatgpt.com/
 *
 * 3. Ginurx, "chacha20-c" (C implementation of ChaCha20).
 *    GitHub Repository:
 *    https://github.com/Ginurx/chacha20-c
 */