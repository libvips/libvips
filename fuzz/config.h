#pragma once

#include <unistd.h>

/* Only supported since clang >= 14.0.
 */
#if __has_attribute(disable_sanitizer_instrumentation)
#define DISABLE_SANITIZER_INSTRUMENTATION \
	__attribute__((disable_sanitizer_instrumentation))
#else
#define DISABLE_SANITIZER_INSTRUMENTATION
#endif

#define DEFINE_SANITIZER_OPTS(FN, SUPP_FILE, ...) \
	extern "C" const char * \
	FN() DISABLE_SANITIZER_INSTRUMENTATION \
	{ \
		return access(SUPP_FILE, R_OK) == 0 \
			? "suppressions=" SUPP_FILE __VA_ARGS__ \
			: "" __VA_ARGS__; \
	}

#ifndef SUPPRESSIONS_DIR
#define SUPPRESSIONS_DIR "./suppressions"
#endif

DEFINE_SANITIZER_OPTS(__asan_default_options, SUPPRESSIONS_DIR "/asan.supp")
DEFINE_SANITIZER_OPTS(__lsan_default_options, SUPPRESSIONS_DIR "/lsan.supp")
DEFINE_SANITIZER_OPTS(__tsan_default_options, SUPPRESSIONS_DIR "/tsan.supp")
DEFINE_SANITIZER_OPTS(__ubsan_default_options, SUPPRESSIONS_DIR "/ubsan.supp")
