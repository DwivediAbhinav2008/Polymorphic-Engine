/* elf_wrap.c — wraps output.bin into a static ELF64 executable.
 * Build: gcc -O2 -o elf_warp.out elf_wrap.c
 * Run:   ./elf_warp.out output.bin output.elf */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <elf.h>
#include <sys/stat.h>

#define MAGIC 0xDEADBEEFCAFEBABEULL
#define BASE  0x400000ULL
#define PG    0x1000ULL

static uint64_t rd64(const uint8_t *p) { uint64_t v; memcpy(&v, p, 8); return v; }
static void     wr64(uint8_t *p, uint64_t v) { memcpy(p, &v, 8); }

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: %s output.bin output.elf\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("input"); return 1; }
    fseek(f, 0, SEEK_END); long fsz = ftell(f); rewind(f);
    uint8_t *buf = malloc(fsz);
    if (!buf) { fclose(f); return 1; }
    if (fread(buf, 1, fsz, f) != (size_t)fsz) { fclose(f); free(buf); return 1; }
    fclose(f);

    /* Locate trailer. */
    long magic_off = -1;
    for (long i = 0; i + 8 + 32 <= fsz; i++) {
        if (rd64(buf + i) == MAGIC) { magic_off = i; break; }
    }
    if (magic_off < 0) {
        fprintf(stderr, "trailer magic not found in %s\n", argv[1]);
        free(buf);
        return 1;
    }

    uint64_t mprotect_addr_off = rd64(buf + magic_off +  8);
    uint64_t mprotect_len_off  = rd64(buf + magic_off + 16);
    uint64_t jmp_addr_off      = rd64(buf + magic_off + 24);
    uint64_t ct_len            = rd64(buf + magic_off + 32);

    uint64_t stub_len   = (uint64_t)magic_off;
    uint64_t stub_va    = BASE;
    uint64_t stub_p_off = PG;
    uint64_t ct_p_off   = stub_p_off + stub_len + 40;
    uint64_t ct_va      = stub_va + stub_len + 40;
    uint64_t ct_file_off = (uint64_t)magic_off + 40;

    uint64_t page_va  = ct_va & ~(PG - 1);
    uint64_t page_len = ((ct_va + ct_len + PG - 1) & ~(PG - 1)) - page_va;

    fprintf(stderr,
        "[elf_wrap] stub_len=%lu ct_len=%lu\n"
        "[elf_wrap] stub_va=0x%lx ct_va=0x%lx ct_p_offset=0x%lx\n"
        "[elf_wrap] mprotect placeholder target: page=0x%lx len=0x%lx prot=R|X\n"
        "[elf_wrap] jmp target=0x%lx\n",
        (unsigned long)stub_len, (unsigned long)ct_len,
        (unsigned long)stub_va, (unsigned long)ct_va,
        (unsigned long)ct_p_off,
        (unsigned long)page_va, (unsigned long)page_len,
        (unsigned long)ct_va);

    /* Patch placeholders. */
    wr64(buf + mprotect_addr_off, page_va);
    wr64(buf + mprotect_len_off,  page_len);
    wr64(buf + jmp_addr_off,      ct_va);

    uint64_t file_sz = ct_p_off + ct_len;
    if (file_sz < PG + stub_len + 40 + ct_len) file_sz = PG + stub_len + 40 + ct_len;

    uint8_t *elf = calloc(1, file_sz);
    if (!elf) { free(buf); return 1; }

    Elf64_Ehdr *eh = (Elf64_Ehdr *)elf;
    Elf64_Phdr *ph = (Elf64_Phdr *)(elf + sizeof(*eh));

    memcpy(eh->e_ident, ELFMAG, 4);
    eh->e_ident[EI_CLASS]   = ELFCLASS64;
    eh->e_ident[EI_DATA]    = ELFDATA2LSB;
    eh->e_ident[EI_VERSION] = EV_CURRENT;
    eh->e_ident[EI_OSABI]   = ELFOSABI_SYSV;
    eh->e_type              = ET_EXEC;
    eh->e_machine           = EM_X86_64;
    eh->e_version           = EV_CURRENT;
    eh->e_entry             = stub_va;
    eh->e_phoff             = sizeof(*eh);
    eh->e_shoff             = 0;
    eh->e_flags             = 0;
    eh->e_ehsize            = sizeof(*eh);
    eh->e_phentsize         = sizeof(Elf64_Phdr);
    eh->e_phnum             = 2;
    eh->e_shentsize         = 0;
    eh->e_shnum             = 0;
    eh->e_shstrndx          = SHN_UNDEF;

    /* Segment 1: stub code, R+X. */
    ph[0].p_type   = PT_LOAD;
    ph[0].p_flags  = PF_R | PF_X;
    ph[0].p_offset = stub_p_off;
    ph[0].p_vaddr  = stub_va;
    ph[0].p_paddr  = stub_va;
    ph[0].p_filesz = stub_len;
    ph[0].p_memsz  = stub_len;
    ph[0].p_align  = PG;

    /* Segment 2: ciphertext, R+W+X from load.
     * The stub's mprotect narrows W away at runtime; if the kernel
     * denies the narrowing, page stays RWX and the jmp still works. */
    ph[1].p_type   = PT_LOAD;
    ph[1].p_flags  = PF_R | PF_W | PF_X;
    ph[1].p_offset = ct_p_off;
    ph[1].p_vaddr  = ct_va;
    ph[1].p_paddr  = ct_va;
    ph[1].p_filesz = ct_len;
    ph[1].p_memsz  = ct_len;
    ph[1].p_align  = PG;

    memcpy(elf + stub_p_off, buf, stub_len);
    memcpy(elf + ct_p_off,   buf + ct_file_off, ct_len);

    FILE *o = fopen(argv[2], "wb");
    if (!o) { perror("output"); free(elf); free(buf); return 1; }
    if (fwrite(elf, 1, file_sz, o) != file_sz) {
        perror("write"); fclose(o); free(elf); free(buf); return 1;
    }
    fclose(o);
    free(elf);
    free(buf);

    chmod(argv[2], 0755);
    printf("wrote %s (%lu bytes, stub=%lu @0x%lx, ct=%lu @0x%lx)\n",
           argv[2], (unsigned long)file_sz,
           (unsigned long)stub_len, (unsigned long)stub_va,
           (unsigned long)ct_len, (unsigned long)ct_va);
    return 0;
}