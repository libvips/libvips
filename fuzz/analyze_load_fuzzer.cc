/* Fuzz the Analyze 7.5 loader (analyzeload).
 *
 * The Analyze loader needs a header/data file pair: generate_filenames()
 * (analyze2vips.c) derives "<base>.hdr" and "<base>.img" from the load
 * filename, so buffer-loading fuzzers can never provide the data sibling
 * and the parser sat at 30/221 lines covered (2026-11-12 report). The
 * header is a fixed 348-byte big-endian struct whose fields drive the
 * image geometry (dim[0] selects 2..7 dimensions, height is the product
 * of dim[2..dim[0]]), pixel format (datatype 2/4/8/16/32/64/128) and
 * per-field metadata attachment.
 *
 * This harness splits the fuzz input into a 348-byte header and an image
 * payload, materialises them as the <base>.hdr / <base>.img pair, and
 * loads with vips_analyzeload(). A path-style byte picks whether the load
 * filename carries the .hdr suffix, no suffix, or the .img suffix.
 * Evaluation is size-bounded so huge declared dims cannot OOM the
 * harness: the header parse and metadata attachment always run, pixel
 * generation only for sane geometry.
 *
 * Input format:
 *   byte 0      path style (0: "<base>.hdr", 1: "<base>", 2: "<base>.img")
 *   byte 1      flags (bit 0: also load via vips_image_new_from_file())
 *   bytes 2..   input; first 348 bytes become the header, remainder the
 *               image data file
 */

#include "config.h"

#include <glib/gstdio.h>

#include <vips/vips.h>

#define HDR_SIZE 348
#define MAX_DIM 1024
#define MAX_BANDS 8

extern "C" int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	if (VIPS_INIT(*argv[0]))
		return -1;

	vips_concurrency_set(1);
	vips_cache_set_max(0);

	return 0;
}

static void
eval_bounded(VipsImage *image)
{
	double d;

	if (image->Xsize > MAX_DIM ||
		image->Ysize > MAX_DIM ||
		image->Bands > MAX_BANDS)
		return;

	vips_min(image, &d, nullptr);
}

extern "C" int
LLVMFuzzerTestOneInput(const guint8 *data, size_t size)
{
	gchar *dir = NULL;
	gchar *base = NULL;
	gchar *hdr_path = NULL;
	gchar *img_path = NULL;
	gchar *load_path = NULL;
	VipsImage *image = NULL;
	guint8 path_style;
	guint8 flags;

	if (size < 2 + HDR_SIZE)
		return 0;

	path_style = data[0] % 3;
	flags = data[1];
	data += 2;
	size -= 2;

	if (!(dir = g_dir_make_tmp("vips-fuzz-az-XXXXXX", NULL)))
		return 0;

	base = g_build_filename(dir, "f", NULL);
	hdr_path = g_strconcat(base, ".hdr", NULL);
	img_path = g_strconcat(base, ".img", NULL);

	if (!g_file_set_contents(hdr_path,
			(const char *) data, HDR_SIZE, NULL) ||
		!g_file_set_contents(img_path,
			(const char *) (data + HDR_SIZE), size - HDR_SIZE,
			NULL))
		goto done;

	load_path = path_style == 0
		? g_strdup(hdr_path)
		: path_style == 1
			? g_strdup(base)
			: g_strdup(img_path);

	if (!vips_analyzeload(load_path, &image, nullptr))
		eval_bounded(image);

	if ((flags & 1) && !image) {
		/* Also exercise the content-sniffing dispatch path. */
		if ((image = vips_image_new_from_file(load_path,
				  "access", VIPS_ACCESS_RANDOM, nullptr)))
			eval_bounded(image);
	}

done:
	if (image)
		g_object_unref(image);

	g_free(load_path);
	g_unlink(hdr_path);
	g_unlink(img_path);
	g_free(hdr_path);
	g_free(img_path);
	g_free(base);
	g_rmdir(dir);
	g_free(dir);

	vips_error_clear();

	return 0;
}
