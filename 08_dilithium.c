#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <x86intrin.h>   /* __rdtsc() */

/* Dilithium2 parameters: kept unchanged */
#define N       256
#define Q       8380417
#define K       4
#define L       4
#define ETA     2
#define TAU     39
#define BETA    (TAU * ETA)
#define G1      (1 << 17)
#define G2      ((Q - 1) / 88)
#define RUNS    101

typedef int Poly[N];
typedef Poly VecL[L];
typedef Poly VecK[K];
typedef Poly Matrix[K][L];

/* Global demonstration state */
static Matrix A;
static VecK public_t;
static VecL secret_s1;
static VecK secret_s2;
static int signing_attempts = 0;

/* Simple deterministic PRNG. This is NOT cryptographically secure. */
static uint32_t random_state = 1;

static uint32_t random_u32(void)
{
    uint32_t x = random_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    random_state = x;
    return x;
}

static uint64_t random_u64(uint64_t *state)
{
    uint64_t x = *state;
    x += 0x9E3779B97F4A7C15ULL;
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ULL;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBULL;
    *state = x;
    return x ^ (x >> 31);
}

/* ---------------- Basic modular arithmetic ---------------- */

static int mod_q(long long value)
{
    value %= Q;
    if (value < 0)
        value += Q;
    return (int)value;
}

static int centered_value(int value)
{
    if (value > Q / 2)
        value -= Q;
    return value;
}

static int add_q(int a, int b)
{
    int result = a + b;
    if (result >= Q)
        result -= Q;
    return result;
}

static int sub_q(int a, int b)
{
    int result = a - b;
    if (result < 0)
        result += Q;
    return result;
}

static int mod_power(long long base, int exponent)
{
    long long result = 1;
    base %= Q;

    while (exponent > 0) {
        if (exponent & 1)
            result = result * base % Q;

        base = base * base % Q;
        exponent >>= 1;
    }

    return (int)result;
}

/* ---------------- Polynomial arithmetic ---------------- */

/* Reference multiplication in Zq[X] / (X^256 + 1). */
static void schoolbook_mul(const Poly a, const Poly b, Poly result)
{
    long long temp[N] = {0};

    for (int i = 0; i < N; i++) {
        for (int j = 0; j < N; j++) {
            long long product = (long long)a[i] * b[j];

            if (i + j < N)
                temp[i + j] += product;
            else
                temp[i + j - N] -= product;
        }
    }

    for (int i = 0; i < N; i++)
        result[i] = mod_q(temp[i]);
}

/* ---------------- Number Theoretic Transform ---------------- */

static int zetas[N];
static int inverse_n;

/* Reverse the lowest eight bits of a number. */
static int reverse_bits(int value)
{
    int result = 0;

    for (int i = 0; i < 8; i++) {
        result <<= 1;
        result |= (value >> i) & 1;
    }

    return result;
}

static void initialize_ntt(void)
{
    for (int i = 0; i < N; i++)
        zetas[i] = mod_power(1753, reverse_bits(i));

    inverse_n = mod_power(N, Q - 2);
}

static void forward_ntt(Poly f)
{
    int index = 0;

    for (int length = 128; length >= 1; length /= 2) {
        for (int start = 0; start < N; start += 2 * length) {
            long long zeta = zetas[++index];

            for (int j = start; j < start + length; j++) {
                int temp = (int)(zeta * f[j + length] % Q);

                f[j + length] = sub_q(f[j], temp);
                f[j] = add_q(f[j], temp);
            }
        }
    }
}

static void inverse_ntt(Poly f)
{
    int index = N;

    for (int length = 1; length <= 128; length *= 2) {
        for (int start = 0; start < N; start += 2 * length) {
            long long zeta = Q - zetas[--index];

            for (int j = start; j < start + length; j++) {
                int temp = f[j];

                f[j] = add_q(temp, f[j + length]);
                f[j + length] =
                    (int)(zeta * sub_q(temp, f[j + length]) % Q);
            }
        }
    }

    for (int i = 0; i < N; i++)
        f[i] = (int)((long long)f[i] * inverse_n % Q);
}

/* Polynomial multiplication using NTT. */
static void polynomial_mul(const Poly a, const Poly b, Poly result)
{
    Poly first, second;

    memcpy(first, a, sizeof(Poly));
    memcpy(second, b, sizeof(Poly));

    forward_ntt(first);
    forward_ntt(second);

    for (int i = 0; i < N; i++)
        first[i] = (int)((long long)first[i] * second[i] % Q);

    inverse_ntt(first);
    memcpy(result, first, sizeof(Poly));
}

static void polynomial_add(const Poly a, const Poly b, Poly result)
{
    for (int i = 0; i < N; i++)
        result[i] = mod_q((long long)a[i] + b[i]);
}

static void polynomial_sub(const Poly a, const Poly b, Poly result)
{
    for (int i = 0; i < N; i++)
        result[i] = mod_q((long long)a[i] - b[i]);
}

static int infinity_norm(const Poly p)
{
    int maximum = 0;

    for (int i = 0; i < N; i++) {
        int value = abs(centered_value(p[i]));

        if (value > maximum)
            maximum = value;
    }

    return maximum;
}

/* ---------------- Polynomial sampling ---------------- */

static void sample_uniform(Poly result)
{
    for (int i = 0; i < N; i++)
        result[i] = (int)(random_u32() % Q);
}

/* Coefficients are in [-ETA, ETA]. */
static void sample_small(Poly result)
{
    for (int i = 0; i < N; i++) {
        int value = (int)(random_u32() % (2 * ETA + 1)) - ETA;
        result[i] = mod_q(value);
    }
}

/* Coefficients are in (-G1, G1]. */
static void sample_mask(Poly result)
{
    for (int i = 0; i < N; i++) {
        int value = (int)(random_u32() % (2 * G1)) - (G1 - 1);
        result[i] = mod_q(value);
    }
}

/* ---------------- Rounding operations ---------------- */

static void decompose_value(int value, int *high, int *low)
{
    *low = value % (2 * G2);

    if (*low > G2)
        *low -= 2 * G2;

    if (value - *low == Q - 1) {
        *high = 0;
        *low -= 1;
    } else {
        *high = (value - *low) / (2 * G2);
    }
}

static void get_high_bits(const Poly p, Poly high)
{
    int low;

    for (int i = 0; i < N; i++)
        decompose_value(p[i], &high[i], &low);
}

static int low_bits_norm(const Poly p)
{
    int maximum = 0;

    for (int i = 0; i < N; i++) {
        int high, low;
        decompose_value(p[i], &high, &low);

        if (abs(low) > maximum)
            maximum = abs(low);
    }

    return maximum;
}

/* ---------------- Hash and challenge generation ---------------- */

/* Toy hash for demonstration only; real ML-DSA uses SHAKE256. */
static uint64_t message_hash(const uint8_t *message, int length,
                             const VecK high_parts)
{
    uint64_t hash = 14695981039346656037ULL;

    for (int i = 0; i < length; i++) {
        hash ^= message[i];
        hash *= 1099511628211ULL;
    }

    for (int row = 0; row < K; row++) {
        for (int i = 0; i < N; i++) {
            hash ^= (uint8_t)(high_parts[row][i] & 0xFF);
            hash *= 1099511628211ULL;

            hash ^= (uint8_t)((high_parts[row][i] >> 8) & 0xFF);
            hash *= 1099511628211ULL;
        }
    }

    return hash;
}

/* Creates a polynomial with exactly TAU coefficients equal to +1 or -1. */
static void make_challenge(uint64_t seed, Poly challenge)
{
    uint64_t state = seed;

    memset(challenge, 0, sizeof(Poly));

    for (int i = N - TAU; i < N; i++) {
        int position = (int)(random_u64(&state) % (uint64_t)(i + 1));

        challenge[i] = challenge[position];
        challenge[position] =
            (random_u64(&state) & 1) ? 1 : Q - 1;
    }
}

/* ---------------- Matrix-vector multiplication ---------------- */

/* Calculates result = A * input. */
static void matrix_vector_mul(const VecL input, VecK result)
{
    Poly product;

    for (int row = 0; row < K; row++) {
        memset(result[row], 0, sizeof(Poly));

        for (int col = 0; col < L; col++) {
            polynomial_mul(A[row][col], input[col], product);
            polynomial_add(result[row], product, result[row]);
        }
    }
}

/* ---------------- Key generation ---------------- */

static void generate_keys(void)
{
    VecK matrix_result;

    for (int row = 0; row < K; row++) {
        for (int col = 0; col < L; col++)
            sample_uniform(A[row][col]);
    }

    for (int i = 0; i < L; i++)
        sample_small(secret_s1[i]);

    for (int i = 0; i < K; i++)
        sample_small(secret_s2[i]);

    matrix_vector_mul(secret_s1, matrix_result);

    /* public_t = A * secret_s1 + secret_s2 */
    for (int i = 0; i < K; i++)
        polynomial_add(matrix_result[i], secret_s2[i], public_t[i]);
}

/* ---------------- Signing ---------------- */

/* Signature consists of z and the challenge hash h. */
static void create_signature(const uint8_t *message, int length,
                             VecL z, uint64_t *hash_value)
{
    while (1) {
        VecL y;
        VecK w, high_parts;
        Poly challenge;
        int valid = 1;

        signing_attempts++;

        for (int j = 0; j < L; j++)
            sample_mask(y[j]);

        matrix_vector_mul(y, w);

        for (int i = 0; i < K; i++)
            get_high_bits(w[i], high_parts[i]);

        *hash_value = message_hash(message, length, high_parts);
        make_challenge(*hash_value, challenge);

        /* Calculate z = y + challenge * secret_s1. */
        for (int j = 0; j < L && valid; j++) {
            Poly product;

            polynomial_mul(challenge, secret_s1[j], product);
            polynomial_add(y[j], product, z[j]);

            if (infinity_norm(z[j]) >= G1 - BETA)
                valid = 0;
        }

        /* Check the low bits before accepting the signature. */
        for (int i = 0; i < K && valid; i++) {
            Poly product, difference;

            polynomial_mul(challenge, secret_s2[i], product);
            polynomial_sub(w[i], product, difference);

            if (low_bits_norm(difference) >= G2 - BETA)
                valid = 0;
        }

        if (valid)
            return;
    }
}

/* ---------------- Signature verification ---------------- */

static int check_signature(const uint8_t *message, int length,
                           const VecL z, uint64_t hash_value)
{
    Poly challenge;
    VecK az, high_parts;

    for (int j = 0; j < L; j++) {
        if (infinity_norm(z[j]) >= G1 - BETA)
            return 0;
    }

    make_challenge(hash_value, challenge);
    matrix_vector_mul(z, az);

    /* Calculate high bits of A*z - challenge*public_t. */
    for (int i = 0; i < K; i++) {
        Poly product, difference;

        polynomial_mul(challenge, public_t[i], product);
        polynomial_sub(az[i], product, difference);
        get_high_bits(difference, high_parts[i]);
    }

    return message_hash(message, length, high_parts) == hash_value;
}

/* ---------------- Benchmarking ---------------- */

typedef void (*BenchmarkFunction)(void);

static int compare_u64(const void *a, const void *b)
{
    uint64_t first = *(const uint64_t *)a;
    uint64_t second = *(const uint64_t *)b;

    if (first < second)
        return -1;
    if (first > second)
        return 1;
    return 0;
}

/* Returns the median CPU cycle count over RUNS executions. */
static uint64_t measure_cycles(BenchmarkFunction function)
{
    uint64_t measurements[RUNS];

    for (int i = 0; i < RUNS; i++) {
        uint64_t start = __rdtsc();
        function();
        measurements[i] = __rdtsc() - start;
    }

    qsort(measurements, RUNS, sizeof(uint64_t), compare_u64);
    return measurements[RUNS / 2];
}

/* Benchmark input and output storage. */
static Poly bench_a, bench_b;
static uint8_t message[32] = "Hello Dilithium! 32-byte msg :)";
static VecL signature_z;
static uint64_t signature_hash;



static void benchmark_keygen(void)
{
    generate_keys();
}

static void benchmark_sign(void)
{
    create_signature(message, 32, signature_z, &signature_hash);
}

static void benchmark_verify(void)
{
    (void)check_signature(message, 32, signature_z, signature_hash);
}

/* ---------------- Main function ---------------- */

int main(void)
{
    int multiplication_matches = 1;

    initialize_ntt();

    /* Compare NTT multiplication with schoolbook multiplication. */
    for (int test = 0; test < 100; test++) {
        Poly a, b, result_ntt, result_schoolbook;

        sample_uniform(a);
        sample_uniform(b);

        polynomial_mul(a, b, result_ntt);
        schoolbook_mul(a, b, result_schoolbook);

        if (memcmp(result_ntt, result_schoolbook, sizeof(Poly)) != 0) {
            multiplication_matches = 0;
            break;
        }
    }

    sample_uniform(bench_a);
    sample_uniform(bench_b);

    /* Generate keys and test signing and verification. */
    generate_keys();
    create_signature(message, 32, signature_z, &signature_hash);

    printf("Valid signature   : %s\n",
           check_signature(message, 32, signature_z, signature_hash)
               ? "ACCEPT" : "REJECT");

    message[0] ^= 1;

    printf("Tampered message  : %s\n\n",
           check_signature(message, 32, signature_z, signature_hash)
               ? "ACCEPT" : "REJECT");

    message[0] ^= 1;

    /* Measure key generation, signing, and verification. */
    uint64_t keygen_cycles = measure_cycles(benchmark_keygen);

    signing_attempts = 0;
    uint64_t sign_cycles = measure_cycles(benchmark_sign);
    double average_attempts = (double)signing_attempts / RUNS;

    uint64_t verify_cycles = measure_cycles(benchmark_verify);

    printf("            cycles      cpb (per 32-byte msg)\n");
    printf("keygen : %llu\t%.1f\n",
           (unsigned long long)keygen_cycles,
           (double)keygen_cycles / 32.0);

    printf("sign   : %llu\t%.1f\n",
           (unsigned long long)sign_cycles,
           (double)sign_cycles / 32.0);

    printf("verify : %llu\t%.1f\n",
           (unsigned long long)verify_cycles,
           (double)verify_cycles / 32.0);

    printf("\navg sign attempts (rejection sampling): %.5f\n",
           average_attempts);

    return 0;
}