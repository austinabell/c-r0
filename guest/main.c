#include <stdint.h>

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

// Note: this syscall isn't used, but just to indicate the platform syscalls can be called directly.
extern void *sys_alloc_aligned(uint32_t bytes, uint32_t align);

typedef void *HASHER;
extern HASHER init_sha256();
extern void sha256_update(HASHER hasher, const uint8_t *bytes_ptr, uint32_t len);
extern uint32_t *sha256_finalize(HASHER hasher);

void commit(void *hasher, const uint8_t *bytes_ptr, uint32_t len);
void zkvm_exit(void *hasher, uint8_t exit_code);

int main()
{
	// TODO introduce entropy into memory image (for zk)
	void *hasher = init_sha256();
	uint8_t output_bytes[4] = {0, 1, 2, 3};

	commit(hasher, output_bytes, sizeof(output_bytes));

	zkvm_exit(hasher, 0);

	return 0;
}
