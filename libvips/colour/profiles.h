/* The fallback profiles, coded as a set of uchar arrays, see wrap-profiles.sh
 */

#include <stddef.h>

typedef struct _VipsProfileFallback {
	const char *name;
	size_t length;
	const unsigned char data[];
} VipsProfileFallback;

extern VipsProfileFallback *vips__profile_fallback_table[];

