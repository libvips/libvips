/* dECMC.c
 *
 * Modified:
 * 31/10/12
 * 	- from dE76.c
 * 5/3/26
 *	- find difference in LCh
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
#include <glib/gi18n-lib.h>

#include <vips/vips.h>
#include <vips/debug.h>

#include "pcolour.h"

typedef struct _VipsdECMC {
	VipsColourDifference parent_instance;

} VipsdECMC;

typedef VipsColourDifferenceClass VipsdECMCClass;

G_DEFINE_TYPE(VipsdECMC, vips_dECMC, VIPS_TYPE_COLOUR_DIFFERENCE);

/* Find the difference between two buffers of LCh data (CMC is LCh).
 */
static void
vips_dECMC_lch_difference(VipsColour *colour,
	VipsPel *out, VipsPel **in, int width)
{
	float *restrict p1 = (float *) in[0];
	float *restrict p2 = (float *) in[1];
	float *restrict q = (float *) out;

	int x;

	for (x = 0; x < width; x++) {
		float C1 = p1[1];
		float h1 = p1[2];
		float C2 = p2[1];
		float h2 = p2[2];

		float a1;
		float b1;
		vips_col_Ch2ab(C1, h1, &a1, &b1);

		float a2;
		float b2;
		vips_col_Ch2ab(C2, h2, &a2, &b2);

		float dL = p1[0] - p2[0];
		float da = a1 - a2;
		float db = b1 - b2;

		q[x] = sqrtf(dL * dL + da * da + db * db);

		p1 += 3;
		p2 += 3;
	}
}

static void
vips_dECMC_class_init(VipsdECMCClass *class)
{
	VipsObjectClass *object_class = (VipsObjectClass *) class;
	VipsColourClass *colour_class = VIPS_COLOUR_CLASS(class);

	object_class->nickname = "dECMC";
	object_class->description = _("calculate dECMC");

	colour_class->process_line = vips_dECMC_lch_difference;
}

static void
vips_dECMC_init(VipsdECMC *dECMC)
{
	VipsColourDifference *difference = VIPS_COLOUR_DIFFERENCE(dECMC);

	difference->interpretation = VIPS_INTERPRETATION_CMC;
}

/**
 * vips_dECMC: (method)
 * @left: first input image
 * @right: second input image
 * @out: (out): output image
 * @...: `NULL`-terminated list of optional named arguments
 *
 * Calculate dE CMC. The input images are transformed to CMC colour space and
 * the euclidean distance between corresponding pixels calculated.
 *
 * To calculate a colour difference with values for (l:c) other than (1:1),
 * transform the two source images to CMC yourself, scale the channels
 * appropriately, and call this function.
 *
 * ::: seealso
 *     [method@Image.colourspace]
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_dECMC(VipsImage *left, VipsImage *right, VipsImage **out, ...)
{
	va_list ap;
	int result;

	va_start(ap, out);
	result = vips_call_split("dECMC", ap, left, right, out);
	va_end(ap);

	return result;
}
