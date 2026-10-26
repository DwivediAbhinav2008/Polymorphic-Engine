#include <sys/mman.h>
#include "api.h"
#include <stdlib.h>
#include <stdint.h>

void keystream_free(void* ptr, uint64_t len)
{
    secure_bzero(ptr, len);
    munlock(ptr, len);
    free(ptr);
}