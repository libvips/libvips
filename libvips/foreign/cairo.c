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

/**
 * @brief Converts a normal sRGB color value to a linear sRGB color value.
 *
 * This function removes the gamma correction from a non-linear sRGB component,
 * transforming it into a linear light intensity value. It implements the
 * inverse sRGB Electro-Optical Transfer Function (EOTF).
 *
 * @param c A single non-linear sRGB color component, expected in the [0, 1] range.
 * @return The corresponding linear sRGB color component, also in the [0, 1] range.
 *
 * @note This function is the C port of the `linearize` function found in librsvg.
 * For reference, the Rust source code for this function is available at:
 * https://github.com/GNOME/librsvg/blob/2.60.0/rsvg/build.rs#L28
 */
static inline float
linearize(float c)
{
	// The threshold (0.04045f) is the point where the linear segment of the
	// sRGB transfer function (used for encoding) meets the power-law segment.
	// This value is derived directly from the sRGB specification: 12.92 * 0.0031308.
	if (c <= 0.04045f) {
		return c / 12.92f;
	}
	else {
		// Apply the inverse power-law function for sRGB linearization.
		// All numerical literals use the 'f' suffix to explicitly ensure
		// single-precision float-point arithmetic throughout the calculation.
		return powf(((c + 0.055f) / 1.055f), 2.4f);
	}
}

/**
 * @brief Converts a row of Cairo-style premultiplied RGBA128F pixels to linear RGBA.
 *
 * This function processes 'n' pixels in the 'p' buffer. For each pixel, it performs
 * two main operations:
 * 1. Un-premultiplies the R, G, and B color components by their respective
 * alpha channel value. This converts colors from a premultiplied format
 * (common in graphics APIs like Cairo) to a straight alpha format.
 * 2. Applies the inverse sRGB gamma correction (linearization) to the
 * un-premultiplied R, G, and B components. This transforms the colors
 * from a perceptually uniform (non-linear sRGB) space to a linear light
 * intensity space, which is often required for further image processing,
 * blending, or accurate color calculations.
 *
 * The input and output data are assumed to be RGBA (Red, Green, Blue, Alpha)
 * with 32-bit floats per channel. The alpha channel (A) remains unchanged
 * (linear) throughout this process.
 *
 * @param p A pointer to the start of the pixel data (premultiplied RGBA floats).
 * @param n The number of pixels to process in the row.
 *
 * @note This function expects the *output* from librsvg (which typically provides
 * premultiplied sRGB data) and converts it to linear space.
 * Therefore, `linearize_float` is called *after* the un-premultiplication step.
 */
void
vips__premultiplied_rgb1282scrgba(float *restrict p, int n)
{
	// A small epsilon value used to safely check if alpha is close to zero.
	// This prevents division by zero or numerical instability for nearly transparent pixels.
	const float ALPHA_EPSILON = 0.00001f;

	for (int x = 0; x < n; x++) {
		float r = p[x * 4 + 0];
		float g = p[x * 4 + 1];
		float b = p[x * 4 + 2];
		float a = p[x * 4 + 3]; // Alpha component remains linear

		// Step 1: Un-premultiply R, G, B components.
		// If alpha is extremely small, the color components are effectively zero,
		// and setting them to 0.0f avoids NaN/Inf results from division.
		float unmultiplied_r = (a > ALPHA_EPSILON) ? r / a : 0.0f;
		float unmultiplied_g = (a > ALPHA_EPSILON) ? g / a : 0.0f;
		float unmultiplied_b = (a > ALPHA_EPSILON) ? b / a : 0.0f;

		// Step 2: Apply sRGB linearization (inverse gamma correction).
		// This converts the color components from non-linear sRGB space
		// to a linear light intensity space.
		p[x * 4 + 0] = linearize(unmultiplied_r);
		p[x * 4 + 1] = linearize(unmultiplied_g);
		p[x * 4 + 2] = linearize(unmultiplied_b);
		p[x * 4 + 3] = a; // Alpha channel is kept as is (linear)
	}
}
