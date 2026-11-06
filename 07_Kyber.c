
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <x86intrin.h>

// ================= PARAMETERS =================

#define N 256
#define Q 3329
#define K 2
#define ETA 2

#define TEST_CASES 1000
#define BENCHMARK_RUNS 501
#define MESSAGE_BYTES 32

typedef int poly[N];
typedef poly vec[K];
typedef poly matrix[K][K];

int zetas[128];
int gammas[128];

// Deterministic PRNG for educational testing only
static uint32_t rng_state = 2026;

uint32_t random32(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 17;
    rng_state ^= rng_state << 5;

    return rng_state;
}

// ================= MODULAR ARITHMETIC =================

int modq(long long x)
{
    x %= Q;
    return (x < 0) ? (int)(x + Q) : (int)x;
}

int addq(int a, int b)
{
    int result = a + b;
    return (result >= Q) ? result - Q : result;
}

int subq(int a, int b)
{
    int result = a - b;
    return (result < 0) ? result + Q : result;
}

int power_mod(int base, int exponent)
{
    long long result = 1;
    long long value = base % Q;

    while (exponent > 0)
    {
        if (exponent & 1)
            result = (result * value) % Q;

        value = (value * value) % Q;
        exponent >>= 1;
    }

    return (int)result;
}

// Reverse the lowest seven bits
int reverse_7_bits(int x)
{
    int result = 0;

    for (int i = 0; i < 7; i++)
        result |= ((x >> i) & 1) << (6 - i);

    return result;
}

// ================= NTT SETUP =================

void init_ntt(void)
{
    for (int i = 0; i < 128; i++)
    {
        zetas[i] = power_mod(17, reverse_7_bits(i));
        gammas[i] = power_mod(17, 2 * reverse_7_bits(i) + 1);
    }
}

// ================= FORWARD NTT =================

void ntt(poly f)
{
    int k = 1;

    for (int length = 128; length >= 2; length /= 2)
    {
        for (int start = 0; start < N; start += 2 * length)
        {
            int zeta = zetas[k++];

            for (int j = start; j < start + length; j++)
            {
                int temp = (int)((long long)zeta * f[j + length] % Q);

                f[j + length] = subq(f[j], temp);
                f[j] = addq(f[j], temp);
            }
        }
    }
}

// ================= INVERSE NTT =================

void inverse_ntt(poly f)
{
    int k = 127;

    for (int length = 2; length <= 128; length *= 2)
    {
        for (int start = 0; start < N; start += 2 * length)
        {
            int zeta = zetas[k--];

            for (int j = start; j < start + length; j++)
            {
                int temp = f[j];

                f[j] = addq(temp, f[j + length]);

                f[j + length] =
                    (int)((long long)zeta * subq(f[j + length], temp) % Q);
            }
        }
    }

    // 3303 is the modular inverse of 128 modulo 3329
    for (int i = 0; i < N; i++)
        f[i] = (int)((long long)f[i] * 3303 % Q);
}

// ================= POLYNOMIAL MULTIPLICATION =================

// Schoolbook multiplication in Z_q[X]/(X^256 + 1)

void multiply_schoolbook(const poly a, const poly b, poly result)
{
    long long temp[N] = {0};

    for (int i = 0; i < N; i++)
    {
        for (int j = 0; j < N; j++)
        {
            int degree = i + j;

            if (degree < N)
                temp[degree] += (long long)a[i] * b[j];
            else
                temp[degree - N] -= (long long)a[i] * b[j];
        }
    }

    for (int i = 0; i < N; i++)
        result[i] = modq(temp[i]);
}

// NTT-based polynomial multiplication

void multiply_ntt(const poly a, const poly b, poly result)
{
    poly A, B;

    memcpy(A, a, sizeof(poly));
    memcpy(B, b, sizeof(poly));

    ntt(A);
    ntt(B);

    // Multiply polynomial pairs in the NTT domain

    for (int i = 0; i < 128; i++)
    {
        long long a0 = A[2 * i];
        long long a1 = A[2 * i + 1];

        long long b0 = B[2 * i];
        long long b1 = B[2 * i + 1];

        result[2 * i] =
            (int)((a0 * b0 + (a1 * b1 % Q) * gammas[i]) % Q);

        result[2 * i + 1] =
            (int)((a0 * b1 + a1 * b0) % Q);
    }

    inverse_ntt(result);
}

// ================= POLYNOMIAL OPERATIONS =================

void add_polynomials(const poly a, const poly b, poly result)
{
    for (int i = 0; i < N; i++)
        result[i] = addq(a[i], b[i]);
}

// Dot product of two polynomial vectors

void dot_product(const vec a, const vec b, poly result)
{
    poly product;

    for (int j = 0; j < N; j++)
        result[j] = 0;

    for (int i = 0; i < K; i++)
    {
        multiply_ntt(a[i], b[i], product);

        for (int j = 0; j < N; j++)
            result[j] = addq(result[j], product[j]);
    }
}

// ================= POLYNOMIAL SAMPLING =================

// Centered binomial noise

void sample_noise(poly result)
{
    for (int i = 0; i < N; i++)
    {
        int value = 0;

        for (int j = 0; j < ETA; j++)
            value += (int)(random32() & 1) -
                     (int)(random32() & 1);

        result[i] = modq(value);
    }
}

// Uniform polynomial for educational testing

void sample_uniform(poly result)
{
    for (int i = 0; i < N; i++)
        result[i] = (int)(random32() % Q);
}

// ================= SIMPLIFIED KYBER PKE =================

matrix A;
vec public_key;
vec secret_key;

// KEY GENERATION

void keygen(void)
{
    poly product, error;

    // Generate public matrix A

    for (int i = 0; i < K; i++)
        for (int j = 0; j < K; j++)
            sample_uniform(A[i][j]);

    // Generate secret vector s

    for (int i = 0; i < K; i++)
        sample_noise(secret_key[i]);

    // Calculate t = A*s + e

    for (int i = 0; i < K; i++)
    {
        dot_product(A[i], secret_key, product);

        sample_noise(error);

        add_polynomials(product, error, public_key[i]);
    }
}

// ENCRYPTION

void encrypt(const uint8_t message[32], vec u, poly v)
{
    vec r;
    poly product, error;

    // Generate random vector r

    for (int i = 0; i < K; i++)
        sample_noise(r[i]);

    // Calculate u = A^T*r + e1

    for (int i = 0; i < K; i++)
    {
        vec column;

        for (int j = 0; j < K; j++)
            memcpy(column[j], A[j][i], sizeof(poly));

        dot_product(column, r, product);

        sample_noise(error);

        add_polynomials(product, error, u[i]);
    }

    // Calculate v = t^T*r + e2

    dot_product(public_key, r, product);

    sample_noise(error);

    add_polynomials(product, error, v);

    // Add encoded message to v

    for (int i = 0; i < N; i++)
    {
        int bit = (message[i / 8] >> (i % 8)) & 1;

        if (bit)
            v[i] = modq(v[i] + Q / 2);
    }
}

// DECRYPTION

void decrypt(const vec u, const poly v, uint8_t message[32])
{
    poly product;

    // Calculate s^T*u

    dot_product(secret_key, u, product);

    memset(message, 0, MESSAGE_BYTES);

    for (int i = 0; i < N; i++)
    {
        int value = modq(v[i] - product[i]);

        // Decode message bit

        if (value > Q / 4 && value < 3 * Q / 4)
            message[i / 8] |= (uint8_t)(1U << (i % 8));
    }
}

// ================= CORRECTNESS TESTS =================

int test_ntt_multiplication(void)
{
    poly a, b, result_ntt, result_schoolbook;

    for (int test = 0; test < TEST_CASES; test++)
    {
        sample_uniform(a);
        sample_uniform(b);

        multiply_ntt(a, b, result_ntt);
        multiply_schoolbook(a, b, result_schoolbook);

        if (memcmp(result_ntt, result_schoolbook, sizeof(poly)) != 0)
            return 0;
    }

    return 1;
}

int test_ntt_round_trip(void)
{
    poly original, transformed;

    for (int test = 0; test < TEST_CASES; test++)
    {
        sample_uniform(original);

        memcpy(transformed, original, sizeof(poly));

        ntt(transformed);
        inverse_ntt(transformed);

        if (memcmp(original, transformed, sizeof(poly)) != 0)
            return 0;
    }

    return 1;
}

int test_encryption(void)
{
    uint8_t message[32];
    uint8_t decrypted[32];

    vec u;
    poly v;

    // Test all-zero, all-one and patterned messages

    for (int pattern = 0; pattern < 3; pattern++)
    {
        for (int i = 0; i < MESSAGE_BYTES; i++)
        {
            if (pattern == 0)
                message[i] = 0x00;
            else if (pattern == 1)
                message[i] = 0xFF;
            else
                message[i] = (uint8_t)(i * 7 + 3);
        }

        keygen();
        encrypt(message, u, v);
        decrypt(u, v, decrypted);

        if (memcmp(message, decrypted, MESSAGE_BYTES) != 0)
            return 0;
    }

    return 1;
}

// ================= BENCHMARK =================

int compare_u64(const void *left, const void *right)
{
    uint64_t a = *(const uint64_t *)left;
    uint64_t b = *(const uint64_t *)right;

    return (a > b) - (a < b);
}

// Return median cycle count

uint64_t median_cycles(void (*function)(void))
{
    uint64_t measurements[BENCHMARK_RUNS];

    // Warm-up

    for (int i = 0; i < 5; i++)
        function();

    for (int i = 0; i < BENCHMARK_RUNS; i++)
    {
        uint64_t start = __rdtsc();

        function();

        uint64_t end = __rdtsc();

        measurements[i] = end - start;
    }

    qsort(measurements, BENCHMARK_RUNS,
          sizeof(uint64_t), compare_u64);

    return measurements[BENCHMARK_RUNS / 2];
}

// Benchmark variables

poly benchmark_a, benchmark_b, benchmark_result;

uint8_t benchmark_message[32] = "Crypto Implementation in C";
uint8_t benchmark_output[32];

vec benchmark_u;
poly benchmark_v;

// Benchmark functions

void benchmark_schoolbook(void)
{
    multiply_schoolbook(benchmark_a, benchmark_b, benchmark_result);
}

void benchmark_ntt(void)
{
    multiply_ntt(benchmark_a, benchmark_b, benchmark_result);
}

void benchmark_keygen(void)
{
    keygen();
}

void benchmark_encrypt(void)
{
    encrypt(benchmark_message, benchmark_u, benchmark_v);
}

void benchmark_decrypt(void)
{
    decrypt(benchmark_u, benchmark_v, benchmark_output);
}

// ================= MAIN =================

int main(void)
{
    uint8_t message[32] = "Crypto Implementation in C";
    uint8_t decrypted[32];

    vec u;
    poly v;

    init_ntt();

    printf("Simplified Kyber-style PKE in C\n");

    printf("N = %d, Q = %d, K = %d, ETA = %d\n\n",
           N, Q, K, ETA);

    // Correctness tests

    printf("NTT round-trip test: %s\n",
           test_ntt_round_trip() ? "PASS" : "FAIL");

    printf("NTT vs schoolbook (%d tests): %s\n",
           TEST_CASES,
           test_ntt_multiplication() ? "PASS" : "FAIL");

    if (!test_encryption())
    {
        printf("Encryption/decryption test: FAIL\n");
        return 1;
    }

    printf("Encryption/decryption test: PASS\n\n");

    // Demonstrate encryption and decryption

    keygen();

    encrypt(message, u, v);

    decrypt(u, v, decrypted);

    printf("Original : %s\n", message);
    printf("Decrypted: %s\n", decrypted);

    printf("Result   : %s\n\n",
           memcmp(message, decrypted, MESSAGE_BYTES) == 0
           ? "SUCCESS" : "FAILURE");

    // Prepare multiplication benchmark inputs

    sample_uniform(benchmark_a);
    sample_uniform(benchmark_b);

    uint64_t schoolbook_cycles =
        median_cycles(benchmark_schoolbook);

    uint64_t ntt_cycles =
        median_cycles(benchmark_ntt);

    // Benchmark key generation

    uint64_t keygen_cycles =
        median_cycles(benchmark_keygen);

    // Generate a fresh matching key and ciphertext
    // before encryption and decryption benchmarks

    keygen();

    encrypt(benchmark_message, benchmark_u, benchmark_v);

    uint64_t encrypt_cycles =
        median_cycles(benchmark_encrypt);

    uint64_t decrypt_cycles =
        median_cycles(benchmark_decrypt);

    // Display benchmark results

    printf("Benchmark results (median of %d runs)\n",
           BENCHMARK_RUNS);

    printf("Operation                 Cycles       Cycles/byte\n");

    printf("Schoolbook multiplication %-12llu %.2f\n",
           (unsigned long long)schoolbook_cycles,
           (double)schoolbook_cycles / MESSAGE_BYTES);

    printf("NTT multiplication        %-12llu %.2f\n",
           (unsigned long long)ntt_cycles,
           (double)ntt_cycles / MESSAGE_BYTES);

    printf("Key generation            %-12llu %.2f\n",
           (unsigned long long)keygen_cycles,
           (double)keygen_cycles / MESSAGE_BYTES);

    printf("Encryption                %-12llu %.2f\n",
           (unsigned long long)encrypt_cycles,
           (double)encrypt_cycles / MESSAGE_BYTES);

    printf("Decryption                %-12llu %.2f\n",
           (unsigned long long)decrypt_cycles,
           (double)decrypt_cycles / MESSAGE_BYTES);

    printf("\nNTT multiplication speedup: %.2fx\n",
           (double)schoolbook_cycles / ntt_cycles);

    return 0;
}
