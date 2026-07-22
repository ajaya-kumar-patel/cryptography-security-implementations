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