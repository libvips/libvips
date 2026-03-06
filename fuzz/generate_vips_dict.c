/* Generate a libFuzzer dictionary for vips_fuzzer.
 * This ensures the dictionary matches the exact set of operations,
 * arguments, flags and enum values available in the build.
 *
 * Usage: ./build/fuzz/generate_vips_dict > vips_fuzzer.dict
 */

#include <vips/vips.h>

static int
operation_compare(VipsObjectClass *a, VipsObjectClass *b, void *user_data)
{
	return g_strcmp0(a->nickname, b->nickname);
}

static void *
add_operation(VipsObjectClass *class, GSList **operations)
{
	if (VIPS_OPERATION_CLASS(class)->flags & VIPS_OPERATION_DEPRECATED)
		return NULL;

	if (!g_slist_find_custom(*operations, class,
			(GCompareFunc) operation_compare))
		*operations = g_slist_append(*operations, class);

	return NULL;
}

static void *
add_optional_arg(VipsObjectClass *object_class,
	GParamSpec *pspec, VipsArgumentClass *argument_class,
	GSList **arguments, void *b)
{
	if ((argument_class->flags & VIPS_ARGUMENT_REQUIRED) ||
		!(argument_class->flags & VIPS_ARGUMENT_CONSTRUCT) ||
		!(argument_class->flags & VIPS_ARGUMENT_INPUT) ||
		(argument_class->flags & VIPS_ARGUMENT_DEPRECATED))
		return NULL;

	const char *name = g_param_spec_get_name(pspec);

	if (!g_slist_find_custom(*arguments, name,
			(GCompareFunc) g_strcmp0))
		*arguments = g_slist_append(*arguments, (void *) name);

	return NULL;
}

static void *
add_optional_arguments(VipsObjectClass *class, GSList **arguments)
{
	printf("\"%s\"\n", class->nickname);

	vips_argument_class_map(class,
		(VipsArgumentClassMapFn) add_optional_arg, arguments, NULL);

	return NULL;
}

static void
emit_optional_argument(const char *name, void *user_data)
{
	printf("\"--%s\"\n", name);
}

static void *
add_enums(GType type, GSList **values)
{
	/* GParamSpecEnum holds a ref on the class so we just peek.
	 */
	GEnumClass *genum = g_type_class_peek(type);

	for (int i = 0; i < genum->n_values; i++) {
		if (!g_slist_find_custom(*values, genum->values[i].value_nick,
				(GCompareFunc) g_strcmp0))
			*values = g_slist_append(*values,
				(void *) genum->values[i].value_nick);
	}

	return NULL;
}

static void *
add_flags(GType type, GSList **values)
{
	/* GParamSpecFlags holds a ref on the class so we just peek.
	 */
	GFlagsClass *gflags = g_type_class_peek(type);

	for (unsigned int i = 0; i < gflags->n_values; i++) {
		if (!g_slist_find_custom(*values, gflags->values[i].value_nick,
				(GCompareFunc) g_strcmp0))
			*values = g_slist_append(*values,
				(void *) gflags->values[i].value_nick);
	}

	return NULL;
}

static void
emit_value(const char *name, void *user_data)
{
	printf("\"%s\"\n", name);
}

static void
emit_array_syntax(void)
{
	const char *values[] = {
		" ",
		"0",
		"1",
		"128",
		"255",
		"0.0",
		"0.5",
		"1.0",
		"0 0 0",
		"1 2 3",
		"128 128 128",
		"255 255 255",
		"0.0 0.0 0.0",
		"1.0 1.0 1.0",
		"1.0 2.0 3.0",
		"1 0 0 0 1 0 0 0 1",
	};

	for (int i = 0; i < VIPS_NUMBER(values); i++)
		printf("\"%s\"\n", values[i]);
}

int
main(int argc, char **argv)
{
	GSList *operations = NULL;
	GSList *arguments = NULL;
	GSList *values = NULL;

	if (VIPS_INIT(argv[0]))
		vips_error_exit(NULL);

	printf("# Auto-generated libFuzzer dictionary for vips_fuzzer\n\n");

	printf("# operation nicknames\n");
	(void) vips_class_map_all(g_type_from_name("VipsOperation"),
		(VipsClassMapFn) add_operation, &operations);
	operations = g_slist_sort(operations, (GCompareFunc) operation_compare);
	g_slist_foreach(operations, (GFunc) add_optional_arguments, &arguments);

	printf("\n# optional argument names\n");
	arguments = g_slist_sort(arguments, (GCompareFunc) g_strcmp0);
	g_slist_foreach(arguments, (GFunc) emit_optional_argument, NULL);

	g_slist_free(operations);
	g_slist_free(arguments);

	printf("\n# optional argument syntax\n");
	printf("\"%s\"\n", "--");
	printf("\"%s\"\n", "=");

	printf("\n# bool values\n");
	printf("\"%s\"\n", "true");
	printf("\"%s\"\n", "false");

	printf("\n# enum and flag values\n");
	vips_type_map_all(g_type_from_name("GEnum"),
		(VipsTypeMapFn) add_enums, &values);
	vips_type_map_all(g_type_from_name("GFlags"),
		(VipsTypeMapFn) add_flags, &values);
	values = g_slist_sort(values, (GCompareFunc) g_strcmp0);
	g_slist_foreach(values, (GFunc) emit_value, NULL);

	g_slist_free(values);

	printf("\n# interpolator names (not in enum introspection)\n");
	printf("\"%s\"\n", "bicubic");
	printf("\"%s\"\n", "bilinear");
	printf("\"%s\"\n", "lbb");
	printf("\"%s\"\n", "nohalo");
	printf("\"%s\"\n", "vsqbs");

	printf("\n# array syntax\n");
	emit_array_syntax();

	return 0;
}
