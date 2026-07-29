/*
* Title       : GCD Computation Using Euclid's Algorithm
* Author      : Ajaya Kumar Patel
* Roll No.    : CRS2503
* Course      : Cryptographic and Security Implementations
* Date        : 22 July 2026
* Description : This program computes the Greatest Common Divisor (GCD)
*               of two positive integers using Euclid's Algorithm and
*               measures the CPU execution time using clock().
*/

#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <x86intrin.h>

#define ITERATIONS 1000000ULL

void benchmark_gcd(unsigned int a, unsigned int b);
unsigned int gcd(unsigned int a, unsigned int b);

int main(){
    unsigned int a, b;

    printf("Enter two positive integers: ");
    scanf("%u %u", &a, &b);

    unsigned int result = gcd(a, b);

    printf("GCD = %u\n", result);

    // Time and cycle analysis
    benchmark_gcd(a, b);

    return 0;
}

unsigned int gcd(unsigned int a, unsigned int b){
    while (b != 0)
    {
        unsigned int r = a % b;
        a = b;
        b = r;
    }
    return a;
}


void benchmark_gcd(unsigned int a, unsigned int b)
{
    clock_t start_time, end_time;

    unsigned int aux;

    uint64_t start_cycles, end_cycles;

    volatile unsigned int result = 0;

    start_time = clock();
    start_cycles = __rdtscp(&aux);

    for(uint64_t i = 0; i < ITERATIONS; i++)
    {
        result = gcd(a, b);
    }

    end_cycles = __rdtscp(&aux);
    end_time = clock();

    double total_time =
        ((double)(end_time - start_time)) / CLOCKS_PER_SEC;

    double average_time =
        total_time / ITERATIONS;

    double average_cycles =
        (double)(end_cycles - start_cycles) / ITERATIONS;


    printf("\n========== Benchmark ==========\n");
    printf("Iterations          : %llu\n", ITERATIONS);
    printf("Total Time          : %.6f seconds\n", total_time);
    printf("Average Time        : %.12f seconds\n", average_time);
    printf("Average CPU Cycles  : %.2f cycles\n", average_cycles);
}

/*
* Acknowledgement:
* OpenAI ChatGPT (GPT-5.5) was used to understand and implement
* the execution time measurement using the C Standard Library
* function clock() from <time.h>. The algorithm implementation
* and final code were reviewed by the author.
*/