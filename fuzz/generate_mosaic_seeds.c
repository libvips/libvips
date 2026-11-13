/* Generate seeds for mosaic_balance_fuzzer.
 *
 * Each seed is a mosaic_balance_fuzzer input: a 20-byte header selecting the
 * join operation and balancer arguments, followed by an embeddable image
 * (PPM). The harness writes the image to temp files at run time, so seeds
 * only need a valid image plus header values that produce plausible joins.
 *
 * Usage: ./generate_mosaic_seeds <output-dir>
 * Writes one file per seed into <output-dir>.
 */

#include <glib/gstdio.h>

#include <vips/vips.h>

/* Little-endian field writers matching the harness header layout. */
static void
put8(GByteArray *b, guint8 v)
{
	g_byte_array_append(b, &v, 1);
}

static void
put16(GByteArray *b, guint16 v)
{
	guint8 le[2] = { (guint8) (v & 0xff), (guint8) ((v >> 8) & 0xff) };

	g_byte_array_append(b, le, 2);
}

/* op, flags, mblend, gamma_raw, 8 coords, then the embedded image bytes. */
static void
emit_seed(const char *dir, const char *name,
	guint8 op, guint8 flags, guint8 mblend, guint8 gamma_raw,
	const int coords[8],
	const void *image_bytes, size_t image_len)
{
	GByteArray *seed = g_byte_array_new();
	char *path;

	put8(seed, op);
	put8(seed, flags);
	put8(seed, mblend);
	put8(seed, gamma_raw);
	for (int i = 0; i < 8; i++)
		put16(seed, (guint16) coords[i]);

	g_byte_array_append(seed, (guint8 *) image_bytes, image_len);

	path = g_build_filename(dir, name, NULL);
	g_file_set_contents(path,
		(const char *) seed->data, seed->len, NULL);

	g_free(path);
	g_byte_array_free(seed, TRUE);
}

static void
emit_all(const char *dir, const void *image_bytes, size_t image_len)
{
	int c0[8] = { 8, 0, 0, 0, 0, 0, 0, 0 };
	int c1[8] = { 0, 8, 0, 0, 0, 0, 0, 0 };
	int c2[8] = { 0, 0, 31, 0, 0, 0, 0, 0 };
	int c3[8] = { 0, 0, 0, 31, 0, 0, 0, 0 };
	int c4[8] = { 0, 0, 31, 0, 31, 10, 0, 10 };
	int c5[8] = { 0, 0, 0, 31, 10, 31, 10, 0 };
	int c6[8] = { 0, 0, 31, 0, 16, 31, 15, 0 };
	int c7[8] = { 0, 0, 31, 0, 31, 0, 0, 0 };

	/* merge H/V, with and without mblend */
	emit_seed(dir, "merge-h-blend",
		0, 2, 8, 255, c0, image_bytes, image_len);
	emit_seed(dir, "merge-v-blend",
		1, 2, 8, 255, c1, image_bytes, image_len);
	emit_seed(dir, "merge-h-noblend",
		0, 0, 0, 255, c0, image_bytes, image_len);
	emit_seed(dir, "merge-h-maxblend",
		0, 2, 64, 255, c0, image_bytes, image_len);
	/* mosaic H/V */
	emit_seed(dir, "mosaic-h",
		2, 0, 0, 255, c2, image_bytes, image_len);
	emit_seed(dir, "mosaic-v",
		3, 0, 0, 255, c3, image_bytes, image_len);
	/* mosaic1 H/V, two point pairs */
	emit_seed(dir, "mosaic1-h",
		4, 0, 0, 255, c4, image_bytes, image_len);
	emit_seed(dir, "mosaic1-v",
		5, 0, 0, 255, c5, image_bytes, image_len);
	/* match */
	emit_seed(dir, "match",
		6, 0, 0, 255, c6, image_bytes, image_len);
	/* balancer argument matrix: gamma extremes, int_output */
	emit_seed(dir, "merge-h-gamma-min",
		0, 0, 0, 0, c0, image_bytes, image_len);
	emit_seed(dir, "merge-h-gamma-mid",
		0, 0, 0, 51, c0, image_bytes, image_len);
	emit_seed(dir, "merge-h-int-output",
		0, 1, 0, 255, c0, image_bytes, image_len);
	emit_seed(dir, "mosaic-h-int-output",
		2, 1, 0, 255, c2, image_bytes, image_len);
	emit_seed(dir, "mosaic1-v-int-output",
		5, 1, 0, 255, c5, image_bytes, image_len);
	/* degenerate join at origin */
	emit_seed(dir, "merge-h-origin",
		0, 2, 16, 255, c7, image_bytes, image_len);
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

	/* Deterministic 32x32 three-band image: x gradient plus two
	 * constant bands, serialised as PPM (decodes to 3-band uchar).
	 */
	{
		double consts[2] = { 40, 80 };

		if (vips_xyz(&xy, 32, 32, NULL) ||
			vips_extract_band(xy, &x, 0, NULL) ||
			vips_bandjoin_const(x, &rgb, consts, 2, NULL) ||
			vips_image_write_to_buffer(rgb, "x.ppm", &buf, &len, NULL))
			vips_error_exit(NULL);
	}

	emit_all(dir, buf, len);

	g_free(buf);
	g_object_unref(rgb);
	g_object_unref(x);
	g_object_unref(xy);

	return 0;
}
