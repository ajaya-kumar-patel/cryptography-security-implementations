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
#include <time.h>

unsigned int gcd(unsigned int a, unsigned int b){
    while (b != 0)
    {
        unsigned int r = a % b;
        a = b;
        b = r;
    }
    return a;
}

int main(){
    unsigned int a, b;

    printf("Enter two positive integers: ");
    scanf("%u %u", &a, &b);

    clock_t start_time, end_time;
    start_time = clock();

    unsigned int result = gcd(a, b);
    
    end_time = clock();

    printf("GCD = %u\n", result);

    double cpu_time = ((double)(end_time - start_time))/CLOCKS_PER_SEC;
    printf("Execution Time = %f seconds\n", cpu_time);

    return 0;
}


/*
* Acknowledgement:
* OpenAI ChatGPT (GPT-5.5) was used to understand and implement
* the execution time measurement using the C Standard Library
* function clock() from <time.h>. The algorithm implementation
* and final code were reviewed by the author.
*/