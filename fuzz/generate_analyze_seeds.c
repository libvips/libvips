/* Generate seeds for analyze_load_fuzzer.
 *
 * Each seed is an analyze_load_fuzzer input: two bytes (path style, flags),
 * a 348-byte Analyze 7.5 header (big-endian, as the format requires), and
 * an image data blob. Seeds cover the supported datatypes, dimensionality
 * variants, and a couple of header-parse-only error paths.
 *
 * Usage: ./generate_analyze_seeds <output-dir>
 */

#include <glib/gstdio.h>

#include <string.h>

#include <vips/vips.h>

#define HDR_SIZE 348

/* Field offsets within struct dsr. */
#define OFF_SIZEOF_HDR 0
#define OFF_DIM 40		/* dim[0..7], int16 each */
#define OFF_DATATYPE 70		/* int16 */
#define OFF_BITPIX 72		/* int16 */

static void
put_be16(guint8 *b, int off, int v)
{
	b[off] = (guint8) ((v >> 8) & 0xff);
	b[off + 1] = (guint8) (v & 0xff);
}

static void
put_be32(guint8 *b, int off, int v)
{
	b[off] = (guint8) ((v >> 24) & 0xff);
	b[off + 1] = (guint8) ((v >> 16) & 0xff);
	b[off + 2] = (guint8) ((v >> 8) & 0xff);
	b[off + 3] = (guint8) (v & 0xff);
}

/* header params: dims0 (dimensionality), width, height, datatype, bitpix */
static void
emit_seed(const char *dir, const char *name,
	guint8 path_style, guint8 flags,
	int dims0, int width, int height, int datatype, int bitpix,
	size_t data_len)
{
	guint8 hdr[HDR_SIZE];
	guint8 data[1 << 16];
	GByteArray *seed = g_byte_array_new();
	char *path;

	memset(hdr, 0, HDR_SIZE);
	put_be32(hdr, OFF_SIZEOF_HDR, HDR_SIZE);
	put_be16(hdr, OFF_DIM + 0, dims0);
	put_be16(hdr, OFF_DIM + 2, width);
	put_be16(hdr, OFF_DIM + 4, height);
	put_be16(hdr, OFF_DATATYPE, datatype);
	put_be16(hdr, OFF_BITPIX, bitpix);

	for (size_t i = 0; i < data_len; i++)
		data[i] = (guint8) ((i * 7 + 3) & 0xff);

	g_byte_array_append(seed, &path_style, 1);
	g_byte_array_append(seed, &flags, 1);
	g_byte_array_append(seed, hdr, HDR_SIZE);
	g_byte_array_append(seed, data, data_len);

	path = g_build_filename(dir, name, NULL);
	g_file_set_contents(path,
		(const char *) seed->data, seed->len, NULL);

	g_free(path);
	g_byte_array_free(seed, TRUE);
}

static void
emit_all(const char *dir)
{
	/* path_style 0 = "<base>.hdr" */

	emit_seed(dir, "uchar-32x32", 0, 0, 2, 32, 32, 2, 8, 32 * 32);
	emit_seed(dir, "short-16x16", 0, 0, 2, 16, 16, 4, 16, 16 * 16 * 2);
	emit_seed(dir, "int-8x8", 0, 0, 2, 8, 8, 8, 32, 8 * 8 * 4);
	emit_seed(dir, "float-16x16", 0, 0, 2, 16, 16, 16, 32, 16 * 16 * 4);
	emit_seed(dir, "complex-4x4", 0, 0, 2, 4, 4, 32, 64, 4 * 4 * 8);
	emit_seed(dir, "double-8x8", 0, 0, 2, 8, 8, 64, 64, 8 * 8 * 8);
	emit_seed(dir, "rgb-16x16", 0, 0, 2, 16, 16, 128, 24, 16 * 16 * 3);
	/* 7-dimensional: height = 2*2*2*2*2*2 = 64 */
	emit_seed(dir, "7dim-4x64", 0, 0, 7, 4, 64, 2, 8, 4 * 64);
	/* 4-dimensional: height = 8*2*2 = 32 */
	emit_seed(dir, "4dim-8x32", 0, 0, 4, 8, 32, 2, 8, 8 * 32);
	/* unsupported datatype: header parse + metadata only */
	emit_seed(dir, "bad-datatype", 0, 1, 2, 8, 8, 5, 8, 8 * 8);
	/* unsupported dimensionality */
	emit_seed(dir, "bad-dim0", 0, 0, 1, 8, 8, 2, 8, 8 * 8);
	/* load via "<base>" (no suffix) */
	emit_seed(dir, "no-suffix", 1, 0, 2, 8, 8, 2, 8, 8 * 8);
	/* load via "<base>.img" */
	emit_seed(dir, "img-suffix", 2, 0, 2, 8, 8, 2, 8, 8 * 8);
}

int
main(int argc, char **argv)
{
	const char *dir;

	if (VIPS_INIT(argv[0]))
		vips_error_exit(NULL);

	if (argc != 2) {
		fprintf(stderr, "usage: %s <output-dir>\n", argv[0]);
		return 1;
	}
	dir = argv[1];

	emit_all(dir);

	return 0;
}
