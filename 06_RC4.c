#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <x86intrin.h>

#define N 256
#define KSA_REPEAT 100000

typedef struct {
    uint8_t S[N];
    uint8_t i;
    uint8_t j;
} RC4;

void rc4_ksa(RC4 *rc4, const uint8_t *key, int keylen);
uint8_t rc4_prga(RC4 *rc4);

int main(){
    RC4 rc4;
    uint64_t start,end;
    double cycles_per_byte, cycles_per_bit;

    uint8_t key[] = "Cryptography";
    int keylen = strlen((char*)key);

    unsigned int aux;
    volatile uint8_t dummy = 0;

    _mm_lfence();
    start = __rdtscp(&aux);
    
    for (int r = 0; r < KSA_REPEAT; r++){
        rc4_ksa(&rc4, key, keylen);
    }

    _mm_lfence();
    end = __rdtscp(&aux);

    double avg_ksa_cycles = (double)(end - start) / KSA_REPEAT;
    printf("KSA cycles = %f\n", avg_ksa_cycles);

    const int OUTPUT_BYTES = 1000000;
    _mm_lfence();
    start = __rdtscp(&aux);
    for(int i=0;i<OUTPUT_BYTES;i++){
        dummy ^= rc4_prga(&rc4);
    }
    _mm_lfence();
    end = __rdtscp(&aux);

    cycles_per_byte = (double)(end - start) / OUTPUT_BYTES;
    cycles_per_bit  = cycles_per_byte / 8.0;

    printf("Dummy = %u\n", dummy);
    printf("Total PRGA cycles = %llu\n", (unsigned long long)(end - start));
    printf("PRGA cycles per byte = %.2f\n", cycles_per_byte);
    printf("PRGA cycles per bit = %.4f\n", cycles_per_bit);
    return 0;
}


void rc4_ksa(RC4 *rc4, const uint8_t *key, int keylen){
    int i;
    uint8_t j = 0;

    for(i=0;i<N;i++)
        rc4->S[i]=i;

    for(i=0;i<N;i++){
        j = j + rc4->S[i] + key[i % keylen];
        uint8_t temp = rc4->S[i];
        rc4->S[i] = rc4->S[j];
        rc4->S[j] = temp;
    }

    rc4->i = 0;
    rc4->j = 0;
}

uint8_t rc4_prga(RC4 *rc4){
    rc4->i = rc4->i + 1;
    rc4->j = rc4->j + rc4->S[rc4->i];

    uint8_t temp = rc4->S[rc4->i];
    rc4->S[rc4->i] = rc4->S[rc4->j];
    rc4->S[rc4->j] = temp;

    return rc4->S[(rc4->S[rc4->i] + rc4->S[rc4->j])];
}

