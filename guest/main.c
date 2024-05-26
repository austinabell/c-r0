#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define WORD_SIZE 4
#define BLOCK_WORDS 16
#define FILENO_JOURNAL 3

__asm__(".global _start\n\t"
		".type _start, @function\n\t"
		"_start:\n\t"
		"la sp,      _stack_top\n\t"

		// Load the globals pointer. The program will load pointers relative to this
		// register, so it must be set to the right value on startup.
		// See: https://gnu-mcu-eclipse.github.io/arch/riscv/programmer/#the-gp-global-pointer-register
		// Linker relaxations must be disabled to avoid the initialization beign
		// relaxed with an uninitialized global pointer: mv gp, gp
		".option push;\n\t"
		".option norelax\n\t"
		"la gp,      __global_pointer$\n\t"
		".option pop\n\t"

		// Jump to main function
		"call main\n\t");

extern void sys_halt(uint8_t exit_code, uint32_t *initial_sha_state);
extern void sys_write(uint32_t fd, uint8_t *byte_ptr, int len);
extern void sys_sha_buffer(uint32_t *out_state, uint32_t *in_state, uint8_t *buf, uint32_t count);
extern void *sys_alloc_aligned(uint32_t bytes, uint32_t align);

extern void *init_sha256();
extern void sha256_update(void *hasher, const uint8_t *bytes_ptr, uint32_t len);
extern uint32_t *sha256_finalize(void *hasher);

void zkvm_exit(void *hasher, uint8_t exit_code);

int main()
{
	// TODO introduce entropy into memory image (for zk)
	void *hasher = init_sha256();
	uint8_t output_bytes[4] = {0, 1, 2, 3};

	sha256_update(hasher, output_bytes, sizeof(output_bytes));

	sys_write(FILENO_JOURNAL, output_bytes, sizeof(output_bytes));

	zkvm_exit(hasher, 0);

	return 0;
}
