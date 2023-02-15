/* 20/08/22 kleisauke
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

#include "pconvolution.h"

#ifdef HAVE_HWY

#undef HWY_TARGET_INCLUDE
#define HWY_TARGET_INCLUDE "libvips/convolution/convi_hwy.cpp"
#include <hwy/foreach_target.h>
#include <hwy/highway.h>

namespace HWY_NAMESPACE {

using namespace hwy::HWY_NAMESPACE;

using DI32 = ScalableTag<int32_t>;
using DI16 = ScalableTag<int16_t>;
using DU8 = ScalableTag<uint8_t>;
constexpr DU8 du8;
constexpr Rebind<uint8_t, DI32> du8x32;
constexpr DI16 di16;
constexpr DI32 di32;

HWY_ATTR void
vips_convi_uchar_hwy(VipsRegion *out_region, VipsRegion *ir, VipsRect *r,
	int32_t ne, int32_t nnz, int32_t offset, const int32_t *HWY_RESTRICT offsets,
	const int16_t *HWY_RESTRICT mant, int32_t exp)
{
	int32_t bo = VIPS_RECT_BOTTOM(r);

	const int32_t N = Lanes(di32);

	const auto v_exp = Set(di32, 1 << (exp - 1));
	const auto v_offset = Set(di32, offset);

	for (int32_t y = r->top; y < bo; ++y) {
		VipsPel *HWY_RESTRICT p = VIPS_REGION_ADDR(ir, r->left, y);
		VipsPel *HWY_RESTRICT q = VIPS_REGION_ADDR(out_region, r->left, y);

		/* Main loop: unrolled.
		 */
		int32_t x = 0;
		for (; x + N <= ne; x += N) {
			auto sum = v_exp;

			for (int32_t i = 0; i < nnz; ++i) {
				auto mmk = Set(di16, mant[i]);

				/* Load with an offset.
				 */
				auto top = LoadU(du8, p + offsets[i]); /* top line */

				auto source = InterleaveLower(du8, top, Zero(du8));
				auto pix = BitCast(di16, source);

				/* We accumulate the signed 32-bit result in sum.
				 */
				sum = Add(sum, MulAddAdjacent(pix, mmk));
			}

			/* The final 32->8 conversion.
			 */
			sum = ShiftRightSame(sum, exp);
			sum = Add(sum, v_offset);

			auto demoted = DemoteTo(du8x32, sum);
			StoreU(demoted, du8x32, q + x);
			p += N;
		}

		/* `ne` was not a multiple of the vector length `N`;
		 * proceed one by one.
		 */
		for (; x < ne; ++x) {
			auto sum = v_exp;

			for (int32_t i = 0; i < nnz; ++i) {
				auto mmk = Set(di16, mant[i]);

				/* Load with an offset.
				 */
				auto top = LoadU(du8x32, p + offsets[i]); /* top line */

				auto source = PromoteTo(di32, top);
				auto pix = BitCast(di16, source);

				/* We accumulate the signed 32-bit result in sum.
				 */
				sum = Add(sum, MulAddAdjacent(pix, mmk));
			}

			/* The final 32->8 conversion.
			 */
			sum = ShiftRightSame(sum, exp);
			sum = Add(sum, v_offset);

			auto demoted = DemoteTo(du8x32, sum);
			q[x] = GetLane(demoted);
			p += 1;
		}
	}
}

} /*namespace HWY_NAMESPACE*/

#if HWY_ONCE
HWY_EXPORT(vips_convi_uchar_hwy);

void
vips_convi_uchar_hwy(VipsRegion *out_region, VipsRegion *ir, VipsRect *r,
	int ne, int nnz, int offset, const int *restrict offsets,
	const short *restrict mant, int exp)
{
	/* clang-format off */
	HWY_DYNAMIC_DISPATCH(vips_convi_uchar_hwy)(out_region, ir, r, ne, nnz,
		offset, offsets, mant, exp);
	/* clang-format on */
}
#endif /*HWY_ONCE*/

#endif /*HAVE_HWY*/
