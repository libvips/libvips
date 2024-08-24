#include <vips/vips.h>

/*
#define DEBUG
 */

#ifndef SAVE_SUFFIX
#define SAVE_SUFFIX ".jpg"
#endif

extern "C" int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	if (VIPS_INIT(*argv[0]))
		return -1;

	vips_concurrency_set(1);

#ifdef DEBUG
	printf("available suffixes:\n");
	GSList *suffixes = nullptr;
	char **array = vips_foreign_get_suffixes();
	for (int i = 0; array[i] != nullptr; i++) {
		if (!g_slist_find_custom(suffixes, array[i],
			(GCompareFunc) g_strcmp0)) {
			printf("%s\n", array[i]);
			suffixes = g_slist_append(suffixes, g_strdup(array[i]));
		}

		g_free(array[i]);
	}
	g_free(array);
	g_slist_free_full(suffixes, g_free);
#endif

	return 0;
}

extern "C" int
LLVMFuzzerTestOneInput(const guint8 *data, size_t size)
{
	VipsImage *image;
	void *buf;
	size_t len;

	if (!(image = vips_image_new_from_buffer(data, size, "", nullptr)))
		return 0;

	if (image->Xsize > 100 ||
		image->Ysize > 100 ||
		image->Bands > 4) {
		g_object_unref(image);
		return 0;
	}

	if (vips_image_write_to_buffer(image, SAVE_SUFFIX, &buf, &len, nullptr)) {
		g_object_unref(image);
		return 0;
	}

	g_free(buf);
	g_object_unref(image);

	return 0;
}
