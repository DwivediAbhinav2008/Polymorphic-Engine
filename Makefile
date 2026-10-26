all:
	gcc -O2 -o Polymorphic_engine.out main.c engine.c helper.c keystream_allocation.c securebzero.c keystream_free.c
	gcc elf_warp.c -o elf_warp.out

clean:
	rm -f Polymorphic_engine.out elf_warp.out output.bin shellcode.out output.out

.PHONY: all clean