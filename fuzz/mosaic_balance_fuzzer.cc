/* Fuzz the mosaicing chain: join -> global balance.
 *
 * vips_globalbalance() rebuilds a mosaic from the History metadata attached
 * to its input: it re-opens each leaf image under the filename recorded in
 * the history, parses the join tree, finds per-image correction factors by
 * least-mean-square over the overlap areas, and re-assembles with the shared
 * merge/mosaic machinery (see global_balance.c analyse_mosaic /
 * vips__build_mosaic). No existing fuzz target reaches it: mosaic_fuzzer
 * calls vips_mosaic on in-memory images only, so no input ever carries the
 * file-backed join history the balancer needs (global_balance.c covered
 * 98/903 lines, 2026-11-12 report).
 *
 * This harness materialises the fuzz image to a real temp file so the join
 * records genuine filenames, drives a fuzz-selected join
 * (merge/mosaic/mosaic1/match with fuzz join geometry), then runs
 * vips_globalbalance() with fuzz gamma / int_output and forces evaluation.
 *
 * Input format (little-endian):
 *   byte 0      op selector (0 merge-H, 1 merge-V, 2 mosaic-H, 3 mosaic-V,
 *               4 mosaic1-H, 5 mosaic1-V, 6 match)
 *   byte 1      flags (bit 0: int_output, bit 1: pass mblend)
 *   byte 2      mblend raw (mod 65 -> 0..64)
 *   byte 3      gamma raw (mod 1001 -> 0.0..10.0, clamped to op range)
 *   bytes 4..19 eight u16 join coordinates
 *   remainder   ref image, decoded via vips_image_new_from_buffer()
 */

#include "config.h"

#include <glib/gstdio.h>

#include <vips/vips.h>

#define MAX_DIM 100
#define MAX_BLEND 64

typedef struct {
	guint8 op;
	guint8 flags;
	guint8 mblend;
	guint8 gamma_raw;
	guint16 coords[8];
} mosaic_hdr;

extern "C" int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	if (VIPS_INIT(*argv[0]))
		return -1;

	vips_concurrency_set(1);
	vips_cache_set_max(0);

	return 0;
}

/* Open a file-backed copy of `in` under dir/name, so joins record a
 * filename the balancer can re-open later. Returns a new reference.
 */
static VipsImage *
file_copy(VipsImage *in, const char *dir, const char *name)
{
	char *path = g_build_filename(dir, name, NULL);
	VipsImage *loaded = NULL;

	if (vips_image_write_to_file(in, path, nullptr))
		goto done;

	loaded = vips_image_new_from_file(path,
		"access", VIPS_ACCESS_RANDOM, nullptr);

done:
	g_free(path);
	return loaded;
}

extern "C" int
LLVMFuzzerTestOneInput(const guint8 *data, size_t size)
{
	mosaic_hdr hdr;
	VipsImage *bufimg = NULL;
	VipsImage *ref = NULL;
	VipsImage *sec = NULL;
	VipsImage *joined = NULL;
	VipsImage *balanced = NULL;
	gchar *dir = NULL;
	double gamma;
	int op, dx, dy;
	int xref, yref, xsec, ysec;
	int xr1, yr1, xs1, ys1, xr2, yr2, xs2, ys2;
	int mblend = 10;
	gboolean int_output;

	if (size < sizeof(mosaic_hdr) + 1)
		return 0;

	memcpy(&hdr, data, sizeof(mosaic_hdr));
	data += sizeof(mosaic_hdr);
	size -= sizeof(mosaic_hdr);

	if (!(bufimg = vips_image_new_from_buffer(data, size, "", nullptr)))
		return 0;

	if (bufimg->Xsize > MAX_DIM ||
		bufimg->Ysize > MAX_DIM ||
		bufimg->Bands > 4) {
		g_object_unref(bufimg);
		return 0;
	}

	if (!(dir = g_dir_make_tmp("vips-fuzz-mb-XXXXXX", NULL))) {
		g_object_unref(bufimg);
		return 0;
	}

	/* File-backed copies with genuine filenames. The secondary is
	 * rotated 180 so the two leaves differ in content — degenerate
	 * identical leaves would drive the balancer's least-mean-square
	 * factor search to trivial values.
	 */
	if (!(ref = file_copy(bufimg, dir, "a.v")))
		goto done;
	{
		VipsImage *rotated;

		if (!vips_rot180(bufimg, &rotated, nullptr))
			sec = file_copy(rotated, dir, "b.v");
		g_object_unref(rotated);
		if (!sec)
			goto done;
	}

	op = hdr.op % 7;
	int_output = (hdr.flags & 1) ? TRUE : FALSE;
	if (hdr.flags & 2)
		mblend = hdr.mblend % (MAX_BLEND + 1);

	gamma = 0.00001 + (hdr.gamma_raw / 255.0) * (10.0 - 0.00001);

	/* Keep join geometry within the image so joins usually succeed and
	 * the balancer gets a real tree to chew on.
	 */
	xref = hdr.coords[0] % (ref->Xsize + 1);
	yref = hdr.coords[1] % (ref->Ysize + 1);
	xsec = hdr.coords[2] % (sec->Xsize + 1);
	ysec = hdr.coords[3] % (sec->Ysize + 1);
	xr1 = xref; yr1 = yref; xs1 = xsec; ys1 = ysec;
	xr2 = hdr.coords[4] % (ref->Xsize + 1);
	yr2 = hdr.coords[5] % (ref->Ysize + 1);
	xs2 = hdr.coords[6] % (sec->Xsize + 1);
	ys2 = hdr.coords[7] % (sec->Ysize + 1);
	dx = xref; dy = yref;

	switch (op) {
	case 0:
		if (hdr.flags & 2)
			vips_merge(ref, sec, &joined,
				VIPS_DIRECTION_HORIZONTAL, dx, dy,
				"mblend", mblend, nullptr);
		else
			vips_merge(ref, sec, &joined,
				VIPS_DIRECTION_HORIZONTAL, dx, dy, nullptr);
		break;

	case 1:
		if (hdr.flags & 2)
			vips_merge(ref, sec, &joined,
				VIPS_DIRECTION_VERTICAL, dx, dy,
				"mblend", mblend, nullptr);
		else
			vips_merge(ref, sec, &joined,
				VIPS_DIRECTION_VERTICAL, dx, dy, nullptr);
		break;

	case 2:
		vips_mosaic(ref, sec, &joined,
			VIPS_DIRECTION_HORIZONTAL,
			xref, yref, xsec, ysec, nullptr);
		break;

	case 3:
		vips_mosaic(ref, sec, &joined,
			VIPS_DIRECTION_VERTICAL,
			xref, yref, xsec, ysec, nullptr);
		break;

	case 4:
	case 5:
		vips_mosaic1(ref, sec, &joined,
			op == 4
				? VIPS_DIRECTION_HORIZONTAL
				: VIPS_DIRECTION_VERTICAL,
			xr1, yr1, xs1, ys1,
			xr2, yr2, xs2, ys2, nullptr);
		break;

	case 6:
		vips_match(ref, sec, &joined,
			xr1, yr1, xs1, ys1,
			xr2, yr2, xs2, ys2, nullptr);
		break;

	default:
		g_assert_not_reached();
	}

	if (joined) {
		/* The balancer re-opens the leaves recorded in the join
		 * history, so the temp files must still exist here.
		 */
		if (!vips_globalbalance(joined, &balanced,
				"gamma", gamma,
				"int_output", int_output,
				nullptr)) {
			double d;

			vips_min(balanced, &d, nullptr);
			g_object_unref(balanced);
		}
	}

done:
	g_object_unref(joined);
	g_object_unref(sec);
	g_object_unref(ref);
	g_object_unref(bufimg);

	{
		char *path_a = g_build_filename(dir, "a.v", NULL);
		char *path_b = g_build_filename(dir, "b.v", NULL);

		g_unlink(path_a);
		g_unlink(path_b);
		g_free(path_a);
		g_free(path_b);
	}
	g_rmdir(dir);
	g_free(dir);

	vips_error_clear();

	return 0;
}
