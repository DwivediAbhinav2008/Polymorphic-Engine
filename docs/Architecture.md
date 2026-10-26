# Architecture

How the polymorphic engine and the ELF wrapper work, end to end.

---

## The shape of the problem

We have a plaintext payload -- say, 35 bytes of shellcode. We want to
produce a file that:

1. Contains no plaintext version of those 35 bytes
2. When executed, results in those 35 bytes running
3. Looks different every time it's generated, so a signature database
   can't match a stable byte pattern

The approach: generate a stub. The stub is machine code that decrypts
the payload in place and jumps to it. The payload is stored encrypted
next to the stub. Different builds use different registers, different
encoding modes, different byte layouts -- so no two builds of the same
input payload share enough bytes to be signature-matched.

There are two programs:

- `Polymorphic_engine` -- the generator. Emits the stub as bytes.
- `elf_wrap` -- the packer. Wraps the stub output into a Linux ELF64
  executable.

The engine is a pure function: `(payload bytes, length) -> stub bytes`.
Everything else is packaging.

---

## Part 1: The generator

### 1.1 Allocation

The engine allocates a growable buffer (`stub` struct from `api.h`) at
4 KB initial capacity. Every emitter call appends to this buffer, growing
it by another 4 KB when full. The buffer holds raw x86-64 machine code
being synthesized -- not text, not assembly, just bytes.

It also allocates a keystream buffer from `/dev/urandom` (size =
payload length) via `keystream_alloc()`, which `mlock`s it so the OS
can't swap the key to disk.

### 1.2 Register role assignment

Three registers hold the stub's working state:

    cursor    - address of the next ciphertext byte to decrypt
    iterator  - how many bytes remain to decrypt
    keystream - the key byte

The registers themselves are chosen at random per build. The pool of
candidates excludes `RSP` and `RBP` (stack and frame pointers -- never
safe to clobber in the middle of a function). The engine shuffles the
14 remaining caller-saved registers (RAX, RCX, RDX, RBX, RSI, RDI,
R8-R15) using a Fisher-Yates shuffle, then assigns the first three
shuffled registers to `cursor`, `iterator`, and `keystream`.

This is why each build uses different registers. Same logical operation,
different physical register, different encoded bytes.

### 1.3 Mode selection

`rand() % 2` picks the encoding mode:

- **XOR**: builder encrypts with `ciphertext[i] = plaintext[i] ^ key`;
  stub decrypts with `XOR byte [cursor], key_low`
- **ADD/SUB**: builder encrypts with `ciphertext[i] = plaintext[i] + key`;
  stub decrypts with `SUB byte [cursor], key_low`

The two modes use different opcodes (0x30 for XOR, 0x28 for SUB), so
neither a signature for the XOR loop nor a signature for the SUB loop
matches the other. This is mode polymorphism at the byte level.

### 1.4 Instruction emission

Every x86-64 instruction the stub needs is emitted byte by byte. The
encoding for each instruction is built by hand:

- **REX prefixes** -- `0x40` plus bit flags: W (64-bit operand), R
  (extended reg field), X (extended index), B (extended base/r/m field).
  For example, `0x48` = REX.W, `0x4D` = REX.W + REX.R + REX.B.
- **ModR/M bytes** -- `(mod << 6) | (reg << 3) | r/m`. Mod `11` for
  register-to-register, `00` with r/m `101` for RIP-relative addressing
  with a 32-bit displacement.
- **RIP-relative displacement** -- a signed 32-bit offset from the byte
  after the current instruction to the target address. For a `LEA` at
  address A with a 4-byte displacement field at A+3, the displacement is
  `target - (A + 7)`.

Two emitter primitives write these bytes:

- `single_byte_emitter(buf, byte)` -- one byte
- `multi_byte_emitter(buf, word)` -- `sizeof(uintptr_t)` bytes,
  little-endian

Every other emission is a sequence of `single_byte_emitter` calls.

### 1.5 The stub in instruction order

Both modes emit the same skeleton, with two differences (the clear idiom
and the decode primitive):
LEA cursor, [RIP + disp32] ; cursor = address of ciphertext
MOV keystream, imm64 = key ; low 8 bits of key
XOR/SUB iterator, iterator ; zero the counter
MOV iterator, imm64 = len ; counter = payload length

loop:
XOR/SUB byte [cursor], key_low ; decrypt one byte in place
INC cursor ; advance to next ciphertext byte
DEC iterator ; decrement counter
JNZ loop ; loop while counter != 0

; epilogue
MOV rax, 10 ; SYS_mprotect
MOV rdi, page_address ; (placeholder)
MOV rsi, page_length ; (placeholder)
MOV rdx, 5 ; PROT_READ | PROT_EXEC
SYSCALL
MOV rax, ciphertext_address ; (placeholder)
JMP rax


The decode loop body is small (10-12 bytes). The prologue is ~30 bytes.
The epilogue is ~40 bytes. Everything past the epilogue is padding and
trailer (see 1.6).

### 1.6 Padding and trailer

Two problems the epilogue creates:

1. `elf_wrap` will place the stub and the ciphertext in two separate
   `PT_LOAD` segments. If both segments share a page, the loader's two
   `mmap` calls fight -- the second replaces the first, and either the
   stub becomes non-executable or the ciphertext becomes non-writable.
2. `elf_wrap` needs to know where in the stub the three epilogue
   placeholders (mprotect address, mprotect length, jmp target) live,
   and how many ciphertext bytes to copy.

The engine solves both:

- **Page-alignment padding** -- emit NOPs (`0x90`) until
  `(current_size + 40) % 0x1000 == 0`. Since `elf_wrap` computes
  `ct_va = BASE + stub_len + 40`, this forces `ct_va` onto a fresh page.
  The padding is unreachable at runtime (the epilogue's `JMP rax` skips
  over it).

- **Trailer** -- 40 bytes appended after the padding, holding five
  64-bit values:

magic 0xDEADBEEFCAFEBABE (identifies the trailer)
addr_off offset of mprotect address placeholder in stub
len_off offset of mprotect length placeholder in stub
jmp_off offset of jmp target placeholder in stub
ct_len number of ciphertext bytes


`elf_wrap` scans for the magic, reads the four fields, computes the
final virtual addresses, and writes them back into the placeholders.

### 1.7 Appending ciphertext

The ciphertext is appended after the trailer via
`multi_byte_emitter` in 8-byte chunks, with a remainder of
`size_of_payload % 8` bytes via `single_byte_emitter`. This is purely a
byte-copy loop -- the payload is already encrypted.

The temp buffer that held the encrypted copy is wiped via `secure_bzero`
(volatile writes that the compiler can't optimize away) and then freed.
The keystream buffer is wiped via `keystream_free`, which bzero's,
munlocks, and frees it.

---

## Part 2: The ELF wrapper

### 2.1 Input parsing

`elf_wrap` reads `output.bin`, scans for the magic (byte-by-byte
`uint64_t` reads), and pulls out the four trailer fields.

### 2.2 Address computation

Two virtual addresses are computed:

stub_va = 0x400000
ct_va   = BASE + stub_len + 40

`BASE = 0x400000` is the conventional static executable base. `stub_len`
is the offset of the magic (which equals the size of the stub code +
epilogue + padding). `+ 40` skips the trailer itself.

The mprotect targets are derived from `ct_va`:

page_va  = ct_va & ~0xFFF
page_len = page_align_up(ct_va + ct_len) - page_va

### 2.3 Placeholder patching

The three placeholders in the stub buffer are overwritten in place
*before* the ELF is written:

stub[mprotect_addr_off .. +8]  <- page_va
stub[mprotect_len_off  .. +8]  <- page_len
stub[jmp_addr_off      .. +8]  <- ct_va

After patching, the stub, when executed, will:

1. Compute `page_va` and `page_len` from its own RIP-relative
displacements (already baked in by the engine's LEA).
2. Call `mprotect(page_va, page_len, PROT_READ | PROT_EXEC)`.
3. `JMP ct_va` -- into the ciphertext segment.

### 2.4 ELF layout

Two `PT_LOAD` segments are written:

| Segment | Virtual address | File offset | Flags | Contents |
|---|---|---|---|---|
| 1 | `0x400000` | `0x1000` | R+X | stub code + padding |
| 2 | `ct_va` | `ct_va - BASE` | R+W+X | ciphertext |

The `R+W+X` flag on segment 2 is deliberate. If the segment were only
`R+W`, the stub's `mprotect` would be *widening* the permissions (adding
X to a writable page), which is denied by W^X policies on hardened
kernels. Instead the segment loads with all three permissions already
set, and the stub's `mprotect` *narrows* to `R+X` -- removing W. On
kernels that permit RWX segments, the mprotect succeeds and shrinks the
permission set. On kernels that deny `mprotect(PROT_EXEC)` regardless,
the segment stays RWX and the JMP still works (the page was already
executable).

Both file offsets are chosen so that `p_offset % 0x1000 == p_vaddr %
0x1000`. With `BASE = 0x400000` (page-aligned) and `stub_p_off = 0x1000`
(page-aligned), the invariant holds automatically for the ciphertext
segment at `ct_p_off = 0x1000 + stub_len + 40`.

### 2.5 Entry point

`e_entry = stub_va = 0x400000`. The kernel jumps directly to the first
byte of the stub, which is the `LEA cursor, [RIP + disp32]` instruction.

---

## Part 3: Runtime flow

kernel loads ELF
  |
  v
PC = 0x400000 (stub start)
  |
  +-- LEA cursor, [RIP+disp32]      ; cursor points to ciphertext
  +-- MOV keystream, imm64          ; load key byte
  +-- XOR iterator, iterator        ; clear counter
  +-- MOV iterator, imm64 = len     ; set counter
  |
  v
loop:
  +-- XOR/SUB byte [cursor], key    ; decrypt 1 byte
  +-- INC cursor                    ; advance
  +-- DEC iterator                  ; count down
  +-- JNZ loop                      ; repeat until zero
  |
  v
epilogue:
  +-- MOV rax, 10  (SYS_mprotect)
  +-- MOV rdi, page_va              ; patched by elf_wrap
  +-- MOV rsi, page_len             ; patched by elf_wrap
  +-- MOV rdx, 5   (R|X)
  +-- SYSCALL                       ; flip page to R|X
  +-- MOV rax, ct_va                ; patched by elf_wrap
  +-- JMP rax                       ; -> decrypted payload
  |
  v
payload runs (plaintext, executable page)

At the moment the JMP executes, the ciphertext segment contains the
decrypted payload. The stub code itself is never modified; only the
ciphertext segment is written during the loop.

---

## Part 4: What varies per build

Each run of the engine produces different bytes for the same input
payload, from four independent sources:

1. **Register assignment** -- Fisher-Yates shuffle of the 14-register
pool. 14 * 13 * 12 = 2184 distinct (cursor, iterator, keystream)
triples.
2. **Encoding mode** -- `rand() % 2`. Two modes.
3. **Key byte** -- `encryption_key[0]` from `/dev/urandom`. 256 values.
4. **Padding length** -- derived from `stub_len` modulo 4096; varies
slightly because register encoding lengths vary (e.g., register 0
uses 3-byte LEA, register 8 uses 4-byte LEA).

Combined variation space is on the order of 2184 * 2 * 256 = 1.1
million distinct stub layouts for any given payload. The ciphertext
bytes vary independently with the key.

This is enough to defeat a *static* signature: no two builds share
enough bytes for a substring match. It is not enough to defeat a
*semantic* signature -- the instruction sequence is fixed, and a
matcher that looks for "LEA followed by MOV followed by a decode loop
followed by mprotect + jmp" recognizes the stub regardless of register
choice.

---

## Part 5: What this architecture does not address

Out of scope for this project, listed here so the boundary is explicit:

- **Memory scanning.** The payload is plaintext in the ciphertext
segment during its entire execution. `/proc/<pid>/mem` reads it
trivially.
- **Behavioral analysis.** The `mprotect(page, PROT_EXEC)` followed
immediately by `jmp page` pattern is a well-known shellcode-execution
signal that EDR products flag.
- **Debugger detection.** No `ptrace(PTRACE_TRACEME)`, no
`TracerPid` check. `gdb ./output.elf` single-steps straight through
the decode loop and dumps the key register before the first byte is
decoded.
- **Anti-strace.** No `rdtsc` timing. `strace` reveals every syscall
and every address.
- **Cryptographic strength.** Single-byte XOR. 256 brute-force
attempts recover the payload if the ciphertext is ever obtained.
- **Trailer fingerprint.** The `0xDEADBEEFCAFEBABE` magic is a static
byte pattern in every build. A hex search for it locates the trailer
instantly.
- **Instruction-sequence variation.** The shape is fixed. Only the
bytes and register choices vary.

Each of these is a layer that a production packer would add on top of
this architecture. None are present here.

---

## Summary

The engine is a template expander: fixed instruction skeleton, random
register choices, two encoding modes, byte-level variation. The ELF
wrapper is a two-segment packer with placeholder patching. Together they
produce a self-decrypting ELF64 executable whose bytes change every
build, but whose behavior and structure do not.

Static byte-signature evasion: yes. Everything else: no.
