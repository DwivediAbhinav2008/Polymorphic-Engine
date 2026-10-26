#ifndef API_H
#define API_H
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
extern void regeneration_engine(uint8_t* payload, uint64_t size_of_payload);
extern uint8_t* keystream_alloc(uint64_t len);
extern void keystream_free(void* ptr, uint64_t len);
extern void secure_bzero(void *ptr, uint64_t len);

#define CAPACITY 4096

typedef struct StubContext
{
    uint8_t *buffer;
    uint64_t current_size;
    uint64_t capacity;
} stub;

typedef enum x86_64_registers
{
    RAX = 0,
    RCX = 1,
    RDX = 2,
    RBX = 3,
    RSI = 6,
    RDI = 7,
    R8 = 8,
    R9 = 9,
    R10 = 10,
    R11 = 11,
    R12 = 12,
    R13 = 13,
    R14 = 14,
    R15 = 15
} Reg;

/*Helpers*/
int32_t single_byte_emitter(stub* stub_routine, uint8_t byte);
int32_t multi_byte_emitter(stub* stub_routine, uintptr_t chunk);

#endif
