/*
 * Title       : Performance Comparison of Merge Sort, Quick Sort, and Heap Sort
 * Author      : Ajaya Kumar Patel
 * Roll No.    : CRS2503
 * Course      : Cryptographic and Security Implementations
 * Date        : 30 July 2026
 * Description : C implementation of Merge Sort, Quick Sort, and Heap Sort.
 *               The program benchmarks each algorithm using randomly
 *               generated input data and compares their execution time
 *               and CPU cycles.
 */

#include <stdio.h>
#include <stdlib.h>     // rand(), srand()
#include <string.h>     // memcpy()
#include <stdint.h>     // uint64_t
#include <time.h>       // clock_gettime()
#include <x86intrin.h>  // __rdtscp()

#define SIZE 10000
#define ITERATIONS 100

typedef void (*sort_function)(int arr[], int n);

void merge_sort(int arr[], int left, int right);
void merge(int arr[], int left, int mid, int right);

void quick_sort(int arr[], int low, int high);
int partition(int arr[], int low, int high);
void swap(int *a, int *b);


void heap_sort(int arr[], int n);
void heapify(int arr[], int n, int i);
void swap(int *a, int *b);

void merge_sort_wrapper(int arr[], int n);
void quick_sort_wrapper(int arr[], int n);

void benchmark_sort(const char *name,
                    sort_function sort,
                    const int original[],
                    int n);

int main(void)
{
    int original[SIZE];

    srand(42);

    for(int i = 0; i < SIZE; i++)
        original[i] = rand();

    benchmark_sort("Merge Sort",
                   merge_sort_wrapper,
                   original,
                   SIZE);

    benchmark_sort("Quick Sort",
                   quick_sort_wrapper,
                   original,
                   SIZE);

    benchmark_sort("Heap Sort",
                   heap_sort,
                   original,
                   SIZE);

    return 0;
}

// Merge Sort
void merge_sort(int arr[], int left, int right)
{
    if(left >= right)
        return;

    int mid = left + (right - left) / 2;

    merge_sort(arr, left, mid);
    merge_sort(arr, mid + 1, right);

    merge(arr, left, mid, right);
}

// Merge two sorted subarrays
void merge(int arr[], int left, int mid, int right)
{
    int n1 = mid - left + 1;
    int n2 = right - mid;

    int left_array[n1];
    int right_array[n2];

    // Copy left half
    for(int i = 0; i < n1; i++)
        left_array[i] = arr[left + i];

    // Copy right half
    for(int i = 0; i < n2; i++)
        right_array[i] = arr[mid + 1 + i];

    int i = 0;
    int j = 0;
    int k = left;

    // Merge back into original array
    while(i < n1 && j < n2)
    {
        if(left_array[i] <= right_array[j])
        {
            arr[k] = left_array[i];
            i++;
        }
        else
        {
            arr[k] = right_array[j];
            j++;
        }
        k++;
    }

    // Copy remaining elements of left array
    while(i < n1)
    {
        arr[k] = left_array[i];
        i++;
        k++;
    }

    // Copy remaining elements of right array
    while(j < n2)
    {
        arr[k] = right_array[j];
        j++;
        k++;
    }
}

// ============================
// Quick Sort
// =============================

void quick_sort(int arr[], int low, int high)
{
    if(low < high)
    {
        int pivot = partition(arr, low, high);

        quick_sort(arr, low, pivot - 1);
        quick_sort(arr, pivot + 1, high);
    }
}

// Partition using the last element as pivot
int partition(int arr[], int low, int high)
{
    int pivot = arr[high];
    int i = low - 1;

    for(int j = low; j < high; j++)
    {
        if(arr[j] <= pivot)
        {
            i++;
            swap(&arr[i], &arr[j]);
        }
    }

    swap(&arr[i + 1], &arr[high]);

    return i + 1;
}

// Swap two elements
void swap(int *a, int *b)
{
    int temp = *a;
    *a = *b;
    *b = temp;
}

// ===================================
// Heap Sort
// ===================================
void heap_sort(int arr[], int n)
{
    // Build max heap
    for(int i = n / 2 - 1; i >= 0; i--)
    {
        heapify(arr, n, i);
    }

    // Extract elements one by one
    for(int i = n - 1; i > 0; i--)
    {
        swap(&arr[0], &arr[i]);
        heapify(arr, i, 0);
    }
}

// Heapify a subtree rooted at index i
void heapify(int arr[], int n, int i)
{
    int largest = i;
    int left = 2 * i + 1;
    int right = 2 * i + 2;

    if(left < n && arr[left] > arr[largest])
        largest = left;

    if(right < n && arr[right] > arr[largest])
        largest = right;

    if(largest != i)
    {
        swap(&arr[i], &arr[largest]);
        heapify(arr, n, largest);
    }
}

// ============================
// make all sorting algorithms have the same interface:
// ============================
void merge_sort_wrapper(int arr[], int n)
{
    merge_sort(arr, 0, n - 1);
}

void quick_sort_wrapper(int arr[], int n)
{
    quick_sort(arr, 0, n - 1);
}


// =====================================
// Benchmark Function
// =====================================
void benchmark_sort(const char *name,
                    sort_function sort,
                    const int original[],
                    int n)
{
    int arr[n];

    unsigned int aux;
    struct timespec start_time, end_time;
    uint64_t start_cycles, end_cycles;

    volatile int checksum = 0;

    clock_gettime(CLOCK_MONOTONIC, &start_time);
    start_cycles = __rdtscp(&aux);

    for(int i = 0; i < ITERATIONS; i++)
    {
        memcpy(arr, original, sizeof(arr));

        sort(arr, n);

        checksum ^= arr[n - 1];
    }

    end_cycles = __rdtscp(&aux);
    clock_gettime(CLOCK_MONOTONIC, &end_time);

    uint64_t total_ns =
        (end_time.tv_sec - start_time.tv_sec) * 1000000000ULL +
        (end_time.tv_nsec - start_time.tv_nsec);

    double avg_ns =
        (double)total_ns / ITERATIONS;

    double avg_cycles =
        (double)(end_cycles - start_cycles) / ITERATIONS;

    printf("\n=====================================\n");
    printf("%s\n", name);
    printf("=====================================\n");
    printf("Checksum            : %d\n", checksum);
    printf("Iterations          : %d\n", ITERATIONS);
    printf("Total Time          : %llu ns\n",
        (unsigned long long)total_ns);
    printf("Average Time        : %.2f ns\n", avg_ns);
    printf("Average CPU Cycles  : %.2f\n", avg_cycles);
}

/*
 * References:
 * 1. OpenAI. ChatGPT (GPT-5.5). Used for understanding the sorting
 *    algorithms, benchmarking methodology, implementation guidance,
 *    and code review.
 *    https://chatgpt.com/
 *
 * 2. GeeksforGeeks. "Merge Sort."
 *    https://www.geeksforgeeks.org/merge-sort/
 *
 * 3. GeeksforGeeks. "Quick Sort."
 *    https://www.geeksforgeeks.org/quick-sort/
 *
 * 4. GeeksforGeeks. "Heap Sort."
 *    https://www.geeksforgeeks.org/heap-sort/
 */