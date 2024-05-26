#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define WORD_SIZE 4
#define BLOCK_WORDS 16

#define min(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a < _b ? _a : _b; })

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
extern void *memcpy(void *dest, const void *src, size_t n);

// Function to align up an address to the nearest multiple of alignment
int align_up(int addr, int al)
{
	return (addr + al - 1) & ~(al - 1);
}

// Function to compute the number of 32-bit words needed
int compute_u32s_needed(int len_bytes)
{
	// Add one byte for end marker
	int n_words = align_up(len_bytes + 1, WORD_SIZE) / WORD_SIZE;
	// Add two words for length at end (even though we only use one of them, being a 32-bit architecture)
	n_words += 2;

	return align_up(n_words, BLOCK_WORDS);
}

void sha_buffer(uint32_t *initial_state, uint8_t *bytes, int len_bytes, uint32_t *out_state)
{
	int pad_len = compute_u32s_needed(len_bytes);
	// TODO unchecked mul
	uint32_t *pad_buf = (uint32_t *)sys_alloc_aligned(pad_len * sizeof(uint32_t), 4);

	uint8_t *pad_buf_u8 = (uint8_t *)pad_buf;
	int length = min(len_bytes, pad_len * 4);
	memcpy(pad_buf_u8, bytes, length);
	pad_buf_u8[length] = 0x80;

	uint32_t bits_trailer = 8 * len_bytes;
	bits_trailer = ((bits_trailer & 0x000000FF) << 24) | ((bits_trailer & 0x0000FF00) << 8) |
				   ((bits_trailer & 0x00FF0000) >> 8) | ((bits_trailer & 0xFF000000) >> 24);
	pad_buf[pad_len - 1] = bits_trailer;

	uint32_t num_blocks = pad_len / 16;
	sys_sha_buffer(out_state, initial_state, pad_buf_u8, num_blocks);

	// Note: using bump alloc so no need to free pad_buf
}

void sha256_init_state(uint32_t *state)
{
	state[0] = 0x6a09e667;
	state[1] = 0xbb67ae85;
	state[2] = 0x3c6ef372;
	state[3] = 0xa54ff53a;
	state[4] = 0x510e527f;
	state[5] = 0x9b05688c;
	state[6] = 0x1f83d9ab;
	state[7] = 0x5be0cd19;
}

void tagged_struct(const char *tag, uint32_t digests[][8], int num_digests, uint32_t *out_state)
{
	uint32_t tag_digest[8];
	uint32_t sha_state[8];
	sha256_init_state(sha_state);
	sha_buffer(sha_state, (uint8_t *)tag, strlen(tag), tag_digest);

	int total_len = 8 * 4 + num_digests * 32 + 2;
	uint8_t *all_bytes = (uint8_t *)sys_alloc_aligned(total_len, 4);
	uint8_t *ptr = all_bytes;

	// Append LE bytes of tag digest
	for (int i = 0; i < 8; i++)
	{
		ptr[0] = (tag_digest[i] >> 0) & 0xFF;
		ptr[1] = (tag_digest[i] >> 8) & 0xFF;
		ptr[2] = (tag_digest[i] >> 16) & 0xFF;
		ptr[3] = (tag_digest[i] >> 24) & 0xFF;
		ptr += 4;
	}

	// Append LE bytes of each digest word
	for (int i = 0; i < num_digests; i++)
	{
		for (int j = 0; j < 8; j++)
		{
			ptr[0] = (digests[i][j] >> 0) & 0xFF;
			ptr[1] = (digests[i][j] >> 8) & 0xFF;
			ptr[2] = (digests[i][j] >> 16) & 0xFF;
			ptr[3] = (digests[i][j] >> 24) & 0xFF;
			ptr += 4;
		}
	}

	// Append length of digests as u16 LE
	ptr[0] = (uint8_t)(num_digests & 0xFF);
	ptr[1] = (uint8_t)((num_digests >> 8) & 0xFF);

	uint32_t final_sha_state[8];
	sha256_init_state(final_sha_state);
	sha_buffer(final_sha_state, all_bytes, total_len, out_state);

	// Note: do not need to free all_bytes since bump allocator
}

int main()
{
	uint32_t assumptions_digest_state[8] = {0, 0, 0, 0, 0, 0, 0, 0};
	uint8_t output_bytes[4] = {0, 1, 2, 3};

	uint32_t journal_digest[8];
	uint32_t sha_state[8];
	sha256_init_state(sha_state);
	sha_buffer(sha_state, output_bytes, sizeof(output_bytes), journal_digest);

	sys_write(3, output_bytes, sizeof(output_bytes));

	uint32_t output[8];
	uint32_t digests[2][8] = {{0}, {0}};
	memcpy(digests[0], journal_digest, 8 * sizeof(uint32_t));
	memcpy(digests[1], assumptions_digest_state, 8 * sizeof(uint32_t));

	tagged_struct("risc0.Output", digests, 2, output);

	sys_halt(0, output);

	return 0;
}
