/**
 * sample_violations.cpp
 *
 * Demo file with intentional AUTOSAR C++14 violations.
 *
 * Violations present:
 *   A4-10-1  — NULL instead of nullptr
 *   A5-2-2   — C-style cast
 *   A7-1-4   — register keyword
 *   A7-1-6   — typedef instead of using
 *   A7-2-3   — plain enum instead of enum class
 *   A18-1-1  — raw C-style array
 *   A18-5-1  — malloc/free
 *   A6-6-1   — goto
 *   A26-5-1  — std::rand()
 */

#include <cstdlib>
#include <cstdio>

/* ---- A7-1-6 typedef ---- */
using uint_t = unsigned int;

/* ---- A7-2-3 plain enum ---- */
enum class Color { RED, GREEN, BLUE }; /* VIOLATION A7-2-3 */

/* ---- A18-1-1 C-style array ---- */
int raw_array[10];               /* VIOLATION A18-1-1 */

/* ---- A7-1-4 ---- */
void process(int x)    /* VIOLATION A7-1-4 */
{
    /* ---- A5-2-2 C-style cast ---- */
    double d = (double)x;        /* VIOLATION A5-2-2 */

    /* ---- A4-10-1 nullptr ---- */
    int *ptr = nullptr;             /* VIOLATION A4-10-1 */

    /* ---- A18-5-1 malloc ---- */
    /* AUTOSAR A18-5-1: use new/delete or smart pointers */
    /* MISRA M21.3: replace with static allocation */
    int *buf = (int *)malloc(10 * sizeof(int)); /* VIOLATION A18-5-1, A5-2-2 */
    if (buf == nullptr)             /* VIOLATION A4-10-1 */ {
        goto cleanup;            /* VIOLATION A6-6-1 */
    }

    /* ---- A26-5-1 rand ---- */
    int r = std::rand();         /* VIOLATION A26-5-1 */
    (void)r;

    /* AUTOSAR A18-5-1: use new/delete or smart pointers */
    /* MISRA M21.3: replace with static allocation */
    free(buf);                   /* VIOLATION A18-5-1 */

cleanup:
    (void)ptr;
    (void)d;
}

int main()
{
    process(42);
    return 0;
}
