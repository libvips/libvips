#pragma once

// `#embed` requires C23 support. However, this file is only included when
// building with `-Dfuzz=true`, so it ought to be safe.
#ifdef __clang__
#pragma clang diagnostic ignored "-Wc23-extensions"
#endif

extern "C" const char *
__asan_default_suppressions()
{
	static const char asan_suppressions[] = {
#embed "../suppressions/asan.supp"
		, 0 // ensure null-terminated string
	};

	return asan_suppressions;
}

extern "C" const char *
__lsan_default_suppressions()
{
	static const char lsan_suppressions[] = {
#embed "../suppressions/lsan.supp"
		, 0
	};

	return lsan_suppressions;
}

extern "C" const char *
__tsan_default_suppressions()
{
	static const char tsan_suppressions[] = {
#embed "../suppressions/tsan.supp"
		, 0
	};

	return tsan_suppressions;
}

// Requires https://github.com/llvm/llvm-project/pull/194862
extern "C" const char *
__ubsan_default_suppressions()
{
	static const char ubsan_suppressions[] = {
#embed "../suppressions/ubsan.supp"
		, 0
	};

	return ubsan_suppressions;
}
