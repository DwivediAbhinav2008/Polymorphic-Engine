#include "api.h"

int32_t single_byte_emitter(stub* stub_routine, uint8_t byte)
{
    if (stub_routine->current_size + 1 > stub_routine->capacity)
    {
        stub_routine->capacity += CAPACITY;
        uint8_t* temp_ptr = realloc(stub_routine->buffer, stub_routine->capacity);
        if (!temp_ptr)
        {
            return 1;
        }
        stub_routine->buffer = temp_ptr;
    }
    stub_routine->buffer[stub_routine->current_size++] = byte;
    return 0;
}

int32_t multi_byte_emitter(stub* stub_routine, uintptr_t chunk)
{
    uint64_t num_bytes = sizeof(uintptr_t);
    if (stub_routine->current_size + num_bytes > stub_routine->capacity)
    {
        stub_routine->capacity += CAPACITY;
        uint8_t* temp_ptr = realloc(stub_routine->buffer, stub_routine->capacity);
        if (!temp_ptr)
        {
            return 1;
        }
        stub_routine->buffer = temp_ptr;
    }
    for (uint64_t byte = 0; byte < num_bytes; byte++)
    {
        stub_routine->buffer[stub_routine->current_size++] = (uint8_t)(chunk & 0xFF); // get the lowest byte
        chunk >>= 8; // right shift by a byte
    }
    return 0;
}
