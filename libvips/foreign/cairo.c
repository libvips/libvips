/* Shared code for cairo based loaders like svgload and pdfload.
 */

/*

	This file is part of VIPS.

	VIPS is free software; you can redistribute it and/or modify
	it under the terms of the GNU Lesser General Public License as published by
	the Free Software Foundation; either version 2 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU Lesser General Public License for more details.

	You should have received a copy of the GNU Lesser General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
	02110-1301  USA

 */

/*

	These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/

#include <vips/vips.h>
#include <vips/internal.h>

/* Convert from Cairo-style premultiplied BGRA to RGBA.
 *
 * See also openslide's argb2rgba().
 */
void
vips__premultiplied_bgra2rgba(guint32 *restrict p, int n)
{
	int x;

	for (x = 0; x < n; x++) {
		guint32 bgra = GUINT32_FROM_BE(p[x]);
		guint8 a = bgra & 0xff;

		guint32 rgba;

		if (a == 0 ||
			a == 255)
			rgba =
				(bgra & 0x00ff00ff) |
				(bgra & 0x0000ff00) << 16 |
				(bgra & 0xff000000) >> 16;
		else
			/* Undo premultiplication.
			 */
			rgba =
				((255 * ((bgra >> 8) & 0xff) / a) << 24) |
				((255 * ((bgra >> 16) & 0xff) / a) << 16) |
				((255 * ((bgra >> 24) & 0xff) / a) << 8) |
				a;

		p[x] = GUINT32_TO_BE(rgba);
	}
}

/* Unpremultiplied RGBA (vips convention) to cairo-style premul BGRA.
 */
void
vips__rgba2bgra_premultiplied(guint32 *restrict p, int n)
{
	int x;

	for (x = 0; x < n; x++) {
		guint32 rgba = GUINT32_FROM_BE(p[x]);
		guint8 a = rgba & 0xff;

		guint32 bgra;

		if (a == 0)
			bgra = 0;
		else if (a == 255)
			bgra = (rgba & 0x00ff00ff) |
				(rgba & 0x0000ff00) << 16 |
				(rgba & 0xff000000) >> 16;
		else {
			int r = (rgba >> 24) & 0xff;
			int g = (rgba >> 16) & 0xff;
			int b = (rgba >> 8) & 0xff;

			r = ((r * a) + 128) >> 8;
			g = ((g * a) + 128) >> 8;
			b = ((b * a) + 128) >> 8;

			bgra = (b << 24) | (g << 16) | (r << 8) | a;
		}

		p[x] = GUINT32_TO_BE(bgra);
	}
}

/* Convert from PDFium-style BGRA to RGBA.
 */
void
vips__bgra2rgba(guint32 *restrict p, int n)
{
	int x;

	for (x = 0; x < n; x++) {
		guint32 bgra = GUINT32_FROM_BE(p[x]);

		guint rgba;

		/* Leave G and A, swap R and B.
		 */
		rgba =
			(bgra & 0x00ff00ff) |
			(bgra & 0x0000ff00) << 16 |
			(bgra & 0xff000000) >> 16;

		p[x] = GUINT32_TO_BE(rgba);
	}
}

/*
 * Convert from Cairo-style premultiplied RGBA128F to straight RGBA, for one row.
 * It also linearizes the pixel values.

 * Processes 'n' pixels in the 'p' buffer.
 * The data is assumed to be RGBA (R, G, B, A) 32-bit floats per pixel.
 */
void
vips__premultiplied_rgb1282scrgba(float *restrict p, int n)
{
	vips_col_make_tables_RGB_16();
	for (int x = 0; x < n; x++) {
		// CLIP is much faster than FCLIP, and we want an int result
		int ri = VIPS_CLIP(0, (int) (p[0] * 65535), 65535);
		int gi = VIPS_CLIP(0, (int) (p[1] * 65535), 65535);
		int bi = VIPS_CLIP(0, (int) (p[2] * 65535), 65535);

		// linearize the values with LUT
		float r = vips_v2Y_16[ri];
		float g = vips_v2Y_16[gi];
		float b = vips_v2Y_16[bi];
		float a = p[3];

		p[0] = a > 0.00001 ? r / a : 0.0F;
		p[1] = a > 0.00001 ? g / a : 0.0F;
		p[2] = a > 0.00001 ? b / a : 0.0F;

		p += 4;
	}
}
