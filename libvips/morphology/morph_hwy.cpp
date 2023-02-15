/* 24/08/22 kleisauke
 * 	- initial implementation
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

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include <vips/vips.h>
#include <vips/vector.h>
#include <vips/debug.h>
#include <vips/internal.h>

#include "pmorphology.h"

#ifdef HAVE_HWY

#undef HWY_TARGET_INCLUDE
#define HWY_TARGET_INCLUDE "libvips/morphology/morph_hwy.cpp"
#include <hwy/foreach_target.h>
#include <hwy/highway.h>

namespace HWY_NAMESPACE {

using namespace hwy::HWY_NAMESPACE;

using DI16 = ScalableTag<int16_t>;
constexpr Rebind<uint8_t, DI16> du8;
constexpr DI16 di16;

HWY_ATTR void
vips_dilate_uchar_hwy(VipsRegion *out_region, VipsRegion *ir, VipsRect *r,
	size_t sz, size_t nn128, const int32_t *HWY_RESTRICT offsets,
	const int32_t *HWY_RESTRICT coeff)
{
	int32_t bo = VIPS_RECT_BOTTOM(r);

	const auto zero = Zero(di16);
	const auto one = Set(di16, 255);

	for (int32_t y = r->top; y < bo; ++y) {
		VipsPel *HWY_RESTRICT p = VIPS_REGION_ADDR(ir, r->left, y);
		VipsPel *HWY_RESTRICT q = VIPS_REGION_ADDR(out_region, r->left, y);

		for (size_t x = 0; x < sz; ++x) {
			auto sum = zero;

			for (size_t i = 0; i < nn128; ++i) {
				/* Load with an offset.
				 */
				auto pix = PromoteTo(di16, LoadU(du8, p + offsets[i]));

				if (!coeff[i])
					pix = Xor(pix, one);
				sum = Or(sum, pix);
			}

			auto demoted = DemoteTo(du8, sum);
			q[x] = GetLane(demoted);
			p += 1;
		}
	}
}

HWY_ATTR void
vips_erode_uchar_hwy(VipsRegion *out_region, VipsRegion *ir, VipsRect *r,
	size_t sz, size_t nn128, const int32_t *HWY_RESTRICT offsets,
	const int32_t *HWY_RESTRICT coeff)
{
	int32_t bo = VIPS_RECT_BOTTOM(r);

	const auto one = Set(di16, 255);

	for (int32_t y = r->top; y < bo; ++y) {
		VipsPel *HWY_RESTRICT p = VIPS_REGION_ADDR(ir, r->left, y);
		VipsPel *HWY_RESTRICT q = VIPS_REGION_ADDR(out_region, r->left, y);

		for (size_t x = 0; x < sz; ++x) {
			auto sum = one;

			for (size_t i = 0; i < nn128; ++i) {
				/* Load with an offset.
				 */
				auto pix = PromoteTo(di16, LoadU(du8, p + offsets[i]));

				sum = !coeff[i] ? AndNot(pix, one) : And(sum, pix);
			}

			auto demoted = DemoteTo(du8, sum);
			q[x] = GetLane(demoted);
			p += 1;
		}
	}
}

} /*namespace HWY_NAMESPACE*/

#if HWY_ONCE
HWY_EXPORT(vips_dilate_uchar_hwy);
HWY_EXPORT(vips_erode_uchar_hwy);

void
vips_dilate_uchar_hwy(VipsRegion *out_region, VipsRegion *ir, VipsRect *r,
	size_t sz, size_t nn128, int *restrict offsets, int *restrict coeff)
{
	/* clang-format off */
	HWY_DYNAMIC_DISPATCH(vips_dilate_uchar_hwy)(out_region, ir, r, sz,
		nn128, offsets, coeff);
	/* clang-format on */
}

void
vips_erode_uchar_hwy(VipsRegion *out_region, VipsRegion *ir, VipsRect *r,
	size_t sz, size_t nn128, int *restrict offsets, int *restrict coeff)
{
	/* clang-format off */
	HWY_DYNAMIC_DISPATCH(vips_erode_uchar_hwy)(out_region, ir, r, sz,
		nn128, offsets, coeff);
	/* clang-format on */
}
#endif /*HWY_ONCE*/

#endif /*HAVE_HWY*/
