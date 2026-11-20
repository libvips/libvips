/* Generate seeds for save_options_fuzzer.
 *
 * Each seed is a save_options_fuzzer input: one byte selecting the saver,
 * zero or more "--name=value" option lines, then an embedded image (PPM).
 * Options use nicknames verified against the saver classes
 * (tiffsave.c/vipspng.c/jpegsave.c/webpsave.c/cgifsave.c/jxlsave.c).
 *
 * Usage: ./generate_save_options_seeds <output-dir>
 */

#include <glib/gstdio.h>

#include <string.h>

#include <vips/vips.h>

static void
emit_seed(const char *dir, const char *name,
	guint8 saver, const char *options,
	const void *image_bytes, size_t image_len)
{
	GByteArray *seed = g_byte_array_new();
	char *path;

	g_byte_array_append(seed, &saver, 1);
	g_byte_array_append(seed, (const guint8 *) options, strlen(options));
	g_byte_array_append(seed, (const guint8 *) image_bytes, image_len);

	path = g_build_filename(dir, name, NULL);
	g_file_set_contents(path,
		(const char *) seed->data, seed->len, NULL);

	g_free(path);
	g_byte_array_free(seed, TRUE);
}

static void
emit_all(const char *dir, const void *image_bytes, size_t image_len)
{
	/* 0 tiffsave_buffer */
	emit_seed(dir, "tiff-default", 0, "", image_bytes, image_len);
	emit_seed(dir, "tiff-tile-pyramid", 0,
		"--tile\n--tile-width=64\n--tile-height=64\n--pyramid\n",
		image_bytes, image_len);
	emit_seed(dir, "tiff-jpeg", 0, "--compression=jpeg\n--Q=50\n",
		image_bytes, image_len);
	emit_seed(dir, "tiff-deflate-pred", 0,
		"--compression=deflate\n--predictor=horizontal\n",
		image_bytes, image_len);
	emit_seed(dir, "tiff-lzw-bigtiff", 0,
		"--compression=lzw\n--bigtiff\n",
		image_bytes, image_len);
	emit_seed(dir, "tiff-rgbjpeg-subifd", 0,
		"--compression=jpeg\n--rgbjpeg\n--subifd\n",
		image_bytes, image_len);

	/* 1 pngsave_buffer */
	emit_seed(dir, "png-default", 1, "", image_bytes, image_len);
	emit_seed(dir, "png-interlace", 1, "--interlace\n",
		image_bytes, image_len);
	emit_seed(dir, "png-exact-progressive", 1,
		"--exact\n--progressive\n", image_bytes, image_len);
	emit_seed(dir, "png-squash-bitdepth", 1,
		"--squash\n--bitdepth=4\n", image_bytes, image_len);

	/* 2 webpsave_buffer */
	emit_seed(dir, "webp-default", 2, "", image_bytes, image_len);
	emit_seed(dir, "webp-lossless", 2, "--lossless\n",
		image_bytes, image_len);
	emit_seed(dir, "webp-near-lossless", 2,
		"--near-lossless\n--Q=60\n", image_bytes, image_len);

	/* 3 gifsave_buffer */
	emit_seed(dir, "gif-default", 3, "", image_bytes, image_len);
	emit_seed(dir, "gif-dither-effort", 3,
		"--dither=0.5\n--effort=7\n", image_bytes, image_len);
	emit_seed(dir, "gif-interlace-bitdepth", 3,
		"--interlace\n--bitdepth=4\n", image_bytes, image_len);

	/* 4 jpegsave_buffer */
	emit_seed(dir, "jpeg-default", 4, "", image_bytes, image_len);
	emit_seed(dir, "jpeg-subsample", 4,
		"--Q=20\n--subsample_mode=on\n", image_bytes, image_len);
	emit_seed(dir, "jpeg-trellis", 4,
		"--optimize_coding\n--trellis_quant\n", image_bytes, image_len);
	emit_seed(dir, "jpeg-scans-deringing", 4,
		"--optimize_scans\n--overshoot_deringing\n",
		image_bytes, image_len);

	/* 5 jxlsave_buffer */
	emit_seed(dir, "jxl-default", 5, "", image_bytes, image_len);
	emit_seed(dir, "jxl-lossless", 5, "--lossless\n",
		image_bytes, image_len);
	emit_seed(dir, "jxl-effort-distance", 5,
		"--effort=3\n--distance=2.0\n", image_bytes, image_len);

	/* 6 heifsave_buffer */
	emit_seed(dir, "heif-default", 6, "", image_bytes, image_len);
	emit_seed(dir, "heif-Q", 6, "--Q=60\n", image_bytes, image_len);

	/* 7 radsave_buffer */
	emit_seed(dir, "rad-default", 7, "", image_bytes, image_len);
}

int
main(int argc, char **argv)
{
	VipsImage *xy = NULL;
	VipsImage *x = NULL;
	VipsImage *rgb = NULL;
	void *buf;
	size_t len;
	const char *dir;

	if (VIPS_INIT(argv[0]))
		vips_error_exit(NULL);

	if (argc != 2) {
		fprintf(stderr, "usage: %s <output-dir>\n", argv[0]);
		return 1;
	}
	dir = argv[1];

	/* Deterministic 32x32 three-band gradient, serialised as PPM. */
	if (vips_xyz(&xy, 32, 32, NULL) ||
		vips_extract_band(xy, &x, 0, NULL) ||
		vips_bandjoin_const(x, &rgb, (double[]) { 40, 80 }, 2, NULL) ||
		vips_image_write_to_buffer(rgb, "x.ppm", &buf, &len, NULL))
		vips_error_exit(NULL);

	emit_all(dir, buf, len);

	g_free(buf);
	g_object_unref(rgb);
	g_object_unref(x);
	g_object_unref(xy);

	return 0;
}
