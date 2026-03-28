extern "C" const char *
__tsan_default_options()
{
	return "halt_on_error=1:ignore_noninstrumented_modules=1";
}

extern "C" const char *
__tsan_default_suppressions()
{
	// `#embed` requires C23 support. However, this file is only included when
	// compiling with `-fsanitize=thread`, so it ought to be safe.
	static const char vips_suppressions[] = {
#embed "../suppressions/tsan.supp"
		, 0 // ensure null-terminated string
	};

	return vips_suppressions;
}
