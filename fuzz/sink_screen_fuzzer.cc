/* Fuzz vips_sink_screen(), the interactive-display sink.
 *
 * vips_sink_screen() is a plain function, not a VipsOperation, so the
 * operation-dispatching vips_fuzzer can never reach it: sinkscreen.c sat at
 * 9/540 lines covered (2026-11-12 report). It renders `in` through a tile
 * cache driven by a background thread, fills an optional one-band uchar
 * mask, and fires a notify callback per painted tile, with priority-sign
 * dependent scheduling (foreground vs single-tile thumbnail renders).
 *
 * This harness drives the render state machine with fuzz-controlled tile
 * geometry, cache size and priority, an optional mask, an optional notify
 * callback, and both evaluation orders (force full eval, then re-read to
 * exercise the cache-hit path, then optionally force mask evaluation).
 *
 * Input format:
 *   byte 0      tile_width - 1   (1..256)
 *   byte 1      tile_height - 1  (1..256)
 *   byte 2..3   u16 max_tiles raw (0: unlimited (-1), else value 1..4096)
 *   byte 4      priority (s8, sign selects the scheduling class)
 *   byte 5      flags (bit 0: notify callback, bit 1: attach mask,
 *               bit 2: second eval pass, bit 3: force mask eval)
 *   remainder   image, decoded via vips_image_new_from_buffer()
 */

#include "config.h"

#include <vips/vips.h>

#define MAX_DIM 100
#define MAX_TILES 4096

/* vips_image_new_from_buffer() does not copy the caller's bytes: an image
 * keeps referencing them for as long as it (and anything built on it) is
 * alive. A sink_screen render keeps working in background threads even
 * after LLVMFuzzerTestOneInput returns, so the input must outlive the
 * callback — keep a process-lifetime stable copy of the most recent input
 * and load every image from that. The buffer only ever grows; prior renders
 * may see the overwritten contents of a later iteration, which is benign
 * (valid memory, garbage pixels).
 */
static GMutex stable_lock;
static guint8 *stable_buf = NULL;
static size_t stable_len = 0;

static const guint8 *
stable_copy(const guint8 *data, size_t size)
{
	g_mutex_lock(&stable_lock);
	if (size > stable_len) {
		g_free(stable_buf);
		stable_buf = static_cast<guint8 *>(g_malloc(size));
		stable_len = size;
	}
	memcpy(stable_buf, data, size);
	g_mutex_unlock(&stable_lock);

	return stable_buf;
}

static void
notify_count(VipsImage *image, VipsRect *rect, void *a)
{
	int *count = (int *) a;

	(void) image;
	(void) rect;

	g_atomic_int_add(count, 1);
}

extern "C" int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	if (VIPS_INIT(*argv[0]))
		return -1;

	vips_concurrency_set(1);
	vips_cache_set_max(0);

	return 0;
}

extern "C" int
LLVMFuzzerTestOneInput(const guint8 *data, size_t size)
{
	VipsImage *image = NULL;
	VipsImage *out = NULL;
	VipsImage *mask = NULL;
	int tile_width;
	int tile_height;
	int max_tiles;
	int priority;
	int flags;
	int notify_count_val = 0;
	double d;

	if (size < 6)
		return 0;

	if (!(image = vips_image_new_from_buffer(
			  stable_copy(data, size) + 6, size - 6,
			  "", nullptr)))
		return 0;

	if (image->Xsize > MAX_DIM ||
		image->Ysize > MAX_DIM ||
		image->Bands > 4) {
		g_object_unref(image);
		return 0;
	}

	tile_width = (data[0] % 256) + 1;
	tile_height = (data[1] % 256) + 1;
	max_tiles = data[2] | (data[3] << 8);
	max_tiles = max_tiles ? VIPS_MIN(max_tiles, MAX_TILES) : -1;
	priority = (int) (gint8) data[4];
	flags = data[5];

	out = vips_image_new();
	if (flags & 2)
		mask = vips_image_new();

	if (!vips_sink_screen(image, out, mask,
			tile_width, tile_height, max_tiles, priority,
			(flags & 1) ? notify_count : NULL,
			&notify_count_val)) {
		/* Force a full synchronous eval. */
		vips_min(out, &d, nullptr);

		if (flags & 4) {
			/* Second pass: should hit the tile cache. */
			vips_min(out, &d, nullptr);
		}

		if (mask && (flags & 8)) {
			size_t len;

			/* Force mask evaluation. */
			void *buf = vips_image_write_to_memory(mask, &len);
			g_free(buf);
		}
	}

	if (mask)
		g_object_unref(mask);
	g_object_unref(out);
	g_object_unref(image);

	vips_error_clear();

	return 0;
}
