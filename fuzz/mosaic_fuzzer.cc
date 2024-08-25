#include <cstring>
#include <vips/vips.h>

#ifdef __GNUC__
#define PACK(...) __VA_ARGS__ __attribute__((__packed__))
#elif defined(_MSC_VER)
#define PACK(...) __pragma(pack(push, 1)) __VA_ARGS__ __pragma(pack(pop))
#else
#define PACK(...) __VA_ARGS__
#endif

PACK(struct mosaic_opt {
	guint8 dir : 1;
	guint16 xref;
	guint16 yref;
	guint16 xsec;
	guint16 ysec;
});

extern "C" int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	if (VIPS_INIT(*argv[0]))
		return -1;

	vips_concurrency_set(1);
	return 0;
}

extern "C" int
LLVMFuzzerTestOneInput(const guint8 *data, size_t size)
{
	VipsImage *ref, *sec, *out;
	mosaic_opt opt = {};
	double d;

	if (size < sizeof(mosaic_opt))
		return 0;

	/* The tail of `data` is treated as mosaic configuration
	 */
	size -= sizeof(mosaic_opt);
	memcpy(&opt, data + size, sizeof(mosaic_opt));

	/* Remainder of input is the image
	 */
	if (!(ref = vips_image_new_from_buffer(data, size, "", nullptr)))
		return 0;

	if (ref->Xsize > 100 ||
		ref->Ysize > 100 ||
		ref->Bands > 4) {
		g_object_unref(ref);
		return 0;
	}

	if (vips_rot180(ref, &sec, nullptr)) {
		g_object_unref(ref);
		return 0;
	}

	if (vips_mosaic(ref, sec, &out, (VipsDirection) opt.dir,
			opt.xref, opt.yref, opt.xsec, opt.ysec, nullptr)) {
		g_object_unref(sec);
		g_object_unref(ref);
		return 0;
	}

	vips_max(out, &d, nullptr);

	g_object_unref(out);
	g_object_unref(sec);
	g_object_unref(ref);

	return 0;
}
