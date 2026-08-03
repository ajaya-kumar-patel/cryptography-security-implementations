/*
* Title       : Implementation of AES-128 Block Cipher
* Author      : Ajaya Kumar Patel
* Roll No.    : CRS2503
* Course      : Cryptographic and Security Implementations
* Date        : 04 August 2026
* Description : This program implements the AES-128 block cipher according
*               to the NIST FIPS 197 specification. It includes key expansion,
*               encryption, and decryption using the standard AES transformations:
*               SubBytes, ShiftRows, MixColumns, and AddRoundKey.
*               Correctness was verified using official NIST AES-128 test vectors.
*               Performance is evaluated using CPU cycle count and execution time.
*/

#include <stdio.h>
#include <stdint.h>
#include <x86intrin.h>
#include <time.h>

#define Nb 4      // Number of columns in state
#define Nk 4      // Number of 32-bit words in key
#define Nr 10     // Number of rounds

#define TEST_BLOCKS 100000

/* S-box */
const uint8_t sbox[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,

    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,

    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
    0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,

    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
    0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,

    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,

    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
    0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,

    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
    0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,

    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,

    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
    0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,

    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
    0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,

    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,

    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
    0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,

    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
    0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,

    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,

    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
    0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,

    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
    0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

/* Inverse S-box */
const uint8_t rsbox[256] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38,
    0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,

    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87,
    0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,

    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D,
    0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,

    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2,
    0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,

    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,

    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA,
    0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,

    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A,
    0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,

    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02,
    0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,

    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA,
    0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,

    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85,
    0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,

    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89,
    0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,

    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20,
    0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,

    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31,
    0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,

    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D,
    0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,

    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0,
    0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,

    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26,
    0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

/* Rcon */
const uint8_t Rcon[11] = {
    0x00,
    0x01,
    0x02,
    0x04,
    0x08,
    0x10,
    0x20,
    0x40,
    0x80,
    0x1B,
    0x36
};

/* GF multiplication */
uint8_t gmul(uint8_t a, uint8_t b)
{
    uint8_t p = 0;

    for (int i = 0; i < 8; i++)
    {
        // If LSB of b is 1, add current a to product
        if (b & 1)
            p ^= a;

        // Check if MSB of a is set
        uint8_t hi_bit = a & 0x80;

        // Multiply a by x (left shift)
        a <<= 1;

        // Reduce modulo x^8+x^4+x^3+x+1
        if (hi_bit)
            a ^= 0x1B;

        // Next bit of b
        b >>= 1;
    }

    return p;
}

/* Key Expansion */
void KeyExpansion(uint8_t RoundKey[176], const uint8_t Key[16])
{
    uint8_t temp[4];
    int i, j;

    // First round key is the original key
    for (i = 0; i < 16; i++)
        RoundKey[i] = Key[i];

    // Generate remaining round keys
    for (i = Nk; i < Nb * (Nr + 1); i++)
    {
        // Previous word
        for (j = 0; j < 4; j++)
            temp[j] = RoundKey[(i - 1) * 4 + j];

        // Every 4th word
        if (i % Nk == 0)
        {
            // RotWord()
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;

            // SubWord()
            temp[0] = sbox[temp[0]];
            temp[1] = sbox[temp[1]];
            temp[2] = sbox[temp[2]];
            temp[3] = sbox[temp[3]];

            // Rcon
            temp[0] ^= Rcon[i / Nk];
        }

        // W[i] = W[i-4] XOR temp
        for (j = 0; j < 4; j++)
        {
            RoundKey[i * 4 + j] =
                RoundKey[(i - Nk) * 4 + j] ^ temp[j];
        }
    }
}

/* SubBytes */
void SubBytes(uint8_t state[4][4])
{
    int row, col;

    for (row = 0; row < 4; row++)
    {
        for (col = 0; col < 4; col++)
        {
            state[row][col] = sbox[state[row][col]];
        }
    }
}

/* ShiftRows */
void ShiftRows(uint8_t state[4][4])
{
    uint8_t temp;

    // Row 1: Shift left by 1
    temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;

    // Row 2: Shift left by 2
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;

    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    // Row 3: Shift left by 3 (same as right by 1)
    temp = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = state[3][0];
    state[3][0] = temp;
}

/* MixColumns */
void MixColumns(uint8_t state[4][4])
{
    int col;
    uint8_t a0, a1, a2, a3;

    for (col = 0; col < 4; col++)
    {
        // Store current column
        a0 = state[0][col];
        a1 = state[1][col];
        a2 = state[2][col];
        a3 = state[3][col];

        // Perform matrix multiplication in GF(2^8)
        state[0][col] = gmul(0x02, a0) ^ gmul(0x03, a1) ^ a2 ^ a3;

        state[1][col] = a0 ^ gmul(0x02, a1) ^ gmul(0x03, a2) ^ a3;

        state[2][col] = a0 ^ a1 ^ gmul(0x02, a2) ^ gmul(0x03, a3);

        state[3][col] = gmul(0x03, a0) ^ a1 ^ a2 ^ gmul(0x02, a3);
    }
}

/* AddRoundKey */
void AddRoundKey(uint8_t state[4][4], uint8_t RoundKey[])
{
    int row, col;

    for (col = 0; col < 4; col++)
    {
        for (row = 0; row < 4; row++)
        {
            state[row][col] ^= RoundKey[col * 4 + row];
        }
    }
}

/* AES Encrypt */
void Cipher(uint8_t state[4][4], uint8_t RoundKey[176])
{
    int round;

    // Initial Round
    AddRoundKey(state, RoundKey);

    // Rounds 1 to 9
    for (round = 1; round < Nr; round++)
    {
        SubBytes(state);

        ShiftRows(state);

        MixColumns(state);

        AddRoundKey(state, RoundKey + (round * 16));
    }

    // Final Round (No MixColumns)
    SubBytes(state);

    ShiftRows(state);

    AddRoundKey(state, RoundKey + (Nr * 16));
}

/* Inverse SubBytes */
void InvSubBytes(uint8_t state[4][4])
{
    int row, col;

    for (row = 0; row < 4; row++)
    {
        for (col = 0; col < 4; col++)
        {
            state[row][col] = rsbox[state[row][col]];
        }
    }
}

/* Inverse ShiftRows */
void InvShiftRows(uint8_t state[4][4])
{
    uint8_t temp;

    // Row 1: Shift right by 1
    temp = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = temp;

    // Row 2: Shift right by 2
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;

    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    // Row 3: Shift right by 3 (same as left by 1)
    temp = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = temp;
}

/* Inverse MixColumns */
void InvMixColumns(uint8_t state[4][4])
{
    int col;
    uint8_t a0, a1, a2, a3;

    for (col = 0; col < 4; col++)
    {
        // Save current column
        a0 = state[0][col];
        a1 = state[1][col];
        a2 = state[2][col];
        a3 = state[3][col];

        state[0][col] =
            gmul(0x0E, a0) ^
            gmul(0x0B, a1) ^
            gmul(0x0D, a2) ^
            gmul(0x09, a3);

        state[1][col] =
            gmul(0x09, a0) ^
            gmul(0x0E, a1) ^
            gmul(0x0B, a2) ^
            gmul(0x0D, a3);

        state[2][col] =
            gmul(0x0D, a0) ^
            gmul(0x09, a1) ^
            gmul(0x0E, a2) ^
            gmul(0x0B, a3);

        state[3][col] =
            gmul(0x0B, a0) ^
            gmul(0x0D, a1) ^
            gmul(0x09, a2) ^
            gmul(0x0E, a3);
    }
}

/* AES Decrypt */
void InvCipher(uint8_t state[4][4], uint8_t RoundKey[176])
{
    int round;

    // Initial Round (use last round key)
    AddRoundKey(state, RoundKey + (Nr * 16));

    // Rounds 9 to 1
    for (round = Nr - 1; round >= 1; round--)
    {
        InvShiftRows(state);

        InvSubBytes(state);

        AddRoundKey(state, RoundKey + (round * 16));

        InvMixColumns(state);
    }

    // Final Round
    InvShiftRows(state);

    InvSubBytes(state);

    AddRoundKey(state, RoundKey);
}

/* main() */
int main()
{
    uint8_t key[16] = 
    {
        0x00,0x01,0x02,0x03,
        0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,
        0x0C,0x0D,0x0E,0x0F
    };  //128bit

    uint8_t plaintext[16] =
    {
        0x00,0x11,0x22,0x33,
        0x44,0x55,0x66,0x77,
        0x88,0x99,0xAA,0xBB,
        0xCC,0xDD,0xEE,0xFF
    };

    uint8_t RoundKey[176];           //to store all 11 round keys -> 16*11 bytes
    uint8_t state[4][4]; 

    KeyExpansion(RoundKey, key);

    /* Convert plaintext to state matrix */
    for(int i = 0; i < 16; i++)
    {
        state[i % 4][i / 4] = plaintext[i];
    }

    printf("Plaintext:\n");
    for(int i = 0; i < 16; i++)
        printf("%02X ", plaintext[i]);
    printf("\n");

    /* Encrypt */
    Cipher(state, RoundKey);

    printf("\nCiphertext:\n");

    // =========================================================
    // AES-128 Verification Against NIST FIPS 197 Test Vector
    //=========================================================
    uint8_t expected_ciphertext[16] =
    {
        0x69,0xC4,0xE0,0xD8,
        0x6A,0x7B,0x04,0x30,
        0xD8,0xCD,0xB7,0x80,
        0x70,0xB4,0xC5,0x5A
    };

    int test_pass = 1;

    for(int i = 0; i < 16; i++)
    {
        if(state[i % 4][i / 4] != expected_ciphertext[i])
        {
            test_pass = 0;
            break;
        }
    }

    if(test_pass)
        printf("\nNIST AES-128 Test Vector: PASS\n\n");
    else
        printf("\nNIST AES-128 Test Vector: FAIL\n\n");

    // =======================================

    for(int i = 0; i < 16; i++)
    {
        printf("%02X ", state[i % 4][i / 4]);
    }

    printf("\n");

    /* Decrypt */
    InvCipher(state, RoundKey);

    printf("\nRecovered Plaintext:\n");

    for(int i = 0; i < 16; i++)
    {
        printf("%02X ", state[i % 4][i / 4]);
    }

    printf("\n");

    // ================= Cycle and Time Measurement ====================
    unsigned long long start_cycles, end_cycles;
    struct timespec start_time, end_time;
    _mm_lfence();  //CPU memory fence -> Finish all previous load operations before executing any subsequent instructions.
    start_cycles = __rdtsc();
    clock_gettime(CLOCK_MONOTONIC, &start_time);
    for(int i = 0; i < TEST_BLOCKS; i++)
    {
        Cipher(state, RoundKey);
    }

    clock_gettime(CLOCK_MONOTONIC, &end_time);
    _mm_lfence();
    end_cycles = __rdtsc();

    // Calculate cycles
    unsigned long long cycles = end_cycles - start_cycles;

    // Calculate elapsed time in seconds
    double elapsed_time = (end_time.tv_sec - start_time.tv_sec) + (end_time.tv_nsec - start_time.tv_nsec) / 1e9;

    // Data processed
    unsigned long long total_bytes = TEST_BLOCKS * 16;
    unsigned long long total_bits  = TEST_BLOCKS * 128;

    // CPU frequency
    double cpu_frequency = (double)cycles / elapsed_time;

    printf("\n========== AES Performance ==========\n");
    printf("Blocks processed      : %d\n", TEST_BLOCKS);
    printf("Total bytes           : %llu bytes\n", total_bytes);
    printf("Execution time        : %.9f seconds\n", elapsed_time);
    printf("Execution time        : %.6f ms\n", elapsed_time * 1000);
    printf("CPU cycles            : %llu cycles\n", cycles);
    printf("Cycles per byte       : %.4f\n", (double)cycles / total_bytes);
    printf("Cycles per bit        : %.6f\n", (double)cycles / total_bits);
    printf("CPU Frequency         : %.3f GHz\n", cpu_frequency / 1e9);
    printf("====================================\n");
    return 0;
}

/*
 AES-128 implementation based on:
 NIST FIPS 197
 Advanced Encryption Standard (AES)
 https://doi.org/10.6028/NIST.FIPS.197

 AI Assistance:
 OpenAI ChatGPT (GPT-5.5) was used for conceptual clarification,
 debugging assistance, and code review.
 https://chatgpt.com/
*/