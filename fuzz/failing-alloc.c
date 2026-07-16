/* Originally from HarfBuzz: https://github.com/harfbuzz/harfbuzz/blob/main/src/failing-alloc.c
 * SPDX-License-Identifier: MIT-Modern-Variant
 */

#include <stdlib.h>

/* The library's allocator calls are redirected here via -Wl,--wrap, so __real_*
 * reaches the real (sanitizer-instrumented) allocator.
 */
extern void *__real_malloc(size_t size);
extern void *__real_calloc(size_t count, size_t size);
extern void *__real_realloc(void *ptr, size_t size);

int alloc_state = 0;

__attribute__((no_sanitize("integer")))
static int
fastrand(void)
{
	if (!alloc_state)
		return 1;
	alloc_state = (214013 * alloc_state + 2531011);
	return (alloc_state >> 16) & 0x7FFF;
}

__attribute__((malloc, alloc_size(1)))
void *
__wrap_malloc(size_t size)
{
	return (fastrand() % 16) ? __real_malloc(size) : NULL;
}

__attribute__((malloc, alloc_size(1, 2)))
void *
__wrap_calloc(size_t count, size_t size)
{
	return (fastrand() % 16) ? __real_calloc(count, size) : NULL;
}

__attribute__((alloc_size(2)))
void *
__wrap_realloc(void *ptr, size_t size)
{
	return (fastrand() % 16) ? __real_realloc(ptr, size) : NULL;
}
