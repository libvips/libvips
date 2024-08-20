#include <vips/vips.h>

extern "C" int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	vips_concurrency_set(1);
	return 0;
}

static
const char* extractNextLine(const guint8 **data, size_t *size) {
	char* extracted_string = nullptr;
	for(size_t i = 0; i < (*size); i++) {
		if((*data)[i] == '\n') {
			extracted_string = (char *)g_malloc(i + 1);
			memcpy(extracted_string, *data, i);
			extracted_string[i] = '\0';
			*data = (*data) + i + 1;
			*size = (*size) - i - 1;
			break;
		}
	}
	return (const char*)extracted_string;
}

extern "C" int
LLVMFuzzerTestOneInput(const guint8 *data, size_t size)
{
	VipsImage *image;
	void *buf;
	const char *option_string, *suffix;
	size_t len;

	option_string = extractNextLine(&data, &size);
	if (!option_string) {
		return 0;
	}
	suffix = extractNextLine(&data, &size);
	if (!suffix) {
		g_free((void*)option_string);
		return 0;
	}

	if (!(image = vips_image_new_from_buffer(data, size, option_string, nullptr))) {
		g_free((void*)option_string);
		g_free((void*)suffix);
		return 0;
	}

	if (image->Xsize > 100 ||
		image->Ysize > 100 ||
		image->Bands > 4) {
		g_object_unref(image);
		g_free((void*)option_string);
		g_free((void*)suffix);
		return 0;
	}

	if (vips_image_write_to_buffer(image, suffix, &buf, &len, nullptr)) {
		g_object_unref(image);
		g_free((void*)option_string);
		g_free((void*)suffix);
		return 0;
	}

	g_free(buf);
	g_free((void*)option_string);
	g_free((void*)suffix);
	g_object_unref(image);

	return 0;
}
