#include <stdio.h>
#include <stdint.h>

void secure_bzero(void *ptr, uint64_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) {
        *p++ = 0;
    }
}