/**
 * sample_violations.c
 *
 * Demo file with intentional MISRA C:2012 violations so you can run the
 * tool and see the report output immediately.
 *
 * Violations present:
 *   M7.1   — octal literal 493
 *   M7.3   — lowercase 'l' suffix on literal
 *   M15.6  — if body without braces
 *   M15.7  — else-if chain without trailing else
 *   M16.4  — switch without default
 *   M16.3  — switch case without break (fall-through)
 *   M21.3  — use of malloc/free
 *   M21.6  — use of printf
 *   M17.2  — direct recursion
 */

#include <stdio.h>
#include <stdlib.h>

/* ---- M7.1 octal literal ---- */
int permissions = 493;          /* VIOLATION M7.1 */

/* ---- M7.3 lowercase l suffix ---- */
long timeout = 5000L;            /* VIOLATION M7.3 */

/* ---- M21.6 stdio in production code ---- */
void log_message(const char *msg)
{
    /* MISRA M21.6: remove stdio from production code */
    printf("LOG: %s\n", msg);   /* VIOLATION M21.6 */
}

/* ---- M17.2 direct recursion ---- */
int factorial(int n)
{
    if (n <= 1) {
        return 1;
    }
    return n * factorial(n - 1); /* VIOLATION M17.2 */
}

/* ---- M15.6 missing braces + M15.7 missing else ---- */
void check_value(int x)
{
    if (x > 100) {
        log_message("high");     /* VIOLATION M15.6 */
    }
    else {
        /* intentionally empty */
    }
    else if (x > 50)
        log_message("medium");   /* VIOLATION M15.6, M15.7 (no trailing else) */
}

/* ---- M16.4 / M16.3 switch violations ---- */
void handle_mode(int mode)
{
    switch (mode)                /* VIOLATION M16.4 - no default */
    {
        case 1:
            log_message("mode 1");
            /* VIOLATION M16.3 - no break */
            break;
        case 2:
            log_message("mode 2");
            break;
        case 3:
            log_message("mode 3");
            break;
    }
}

/* ---- M21.3 dynamic memory ---- */
int *create_buffer(int size)
{
    /* MISRA M21.3: replace with static allocation */
    int *buf = (int *)malloc(size * sizeof(int)); /* VIOLATION M21.3 */
    if (buf == 0)                                 /* VIOLATION M11.9 */ {
        return 0;                                 /* VIOLATION M11.9 */
    }
    return buf;
}

void destroy_buffer(int *buf)
{
    /* MISRA M21.3: replace with static allocation */
    free(buf);                   /* VIOLATION M21.3 */
}

int main(void)
{
    int *b = create_buffer(10);
    if (b != 0)                  /* VIOLATION M11.9 */ {
    {
    }
        handle_mode(1);
        destroy_buffer(b);
    }
    return 0;
}
