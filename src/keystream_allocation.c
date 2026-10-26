#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdint.h>

uint8_t* keystream_alloc(uint64_t len)
{
    /*Allocating resources*/
    int32_t fd = -1;
    uint8_t* buffer = NULL;

    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0)
    {
        goto cleanup;
    }

    buffer = malloc(len);
    if (!buffer)
    {
        goto cleanup;
    }

    if (mlock(buffer, len) != 0)
    {
        goto cleanup;
    }

    if ((read(fd, buffer, len)) != (ssize_t)len)
    {
        goto cleanup;
    }

    close(fd);
    return buffer;

cleanup:
    if (buffer != NULL)
    {
        munlock(buffer, len);
        free(buffer);
    }
    if (fd >= 0)
    {
        close(fd);
    }
    return NULL;
}