/* 19/08/22 kleisauke
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

#include "presample.h"

#ifdef HAVE_HWY

#undef HWY_TARGET_INCLUDE
#define HWY_TARGET_INCLUDE "libvips/resample/reduce_hwy.cpp"
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
vips_reduce_uchar_hwy(VipsPel *pout, VipsPel *pin,
	int32_t n, int32_t ne, int32_t lskip, const int16_t *HWY_RESTRICT k)
{
	const auto l1 = lskip / sizeof(uint8_t);

	const int32_t N = Lanes(di32);
	const auto initial = Set(di32, VIPS_INTERPOLATE_SCALE >> 1);

	/* Main loop: unrolled.
	 */
	int32_t x = 0;
	for (; x + N <= ne; x += N) {
		auto *HWY_RESTRICT p = (uint8_t *) pin + x;
		auto *HWY_RESTRICT q = (uint8_t *) pout + x;

		auto sum = initial;

		int32_t i = 0;
		/* TODO(kleisauke): Unroll?
		 */
		/*for (; i < n - 1; i += 2) {
			// Load two coefficients at once
			auto mmk = Set(di16, *(int32_t *) &k[i]);

			auto top = LoadU(du8, p); // top line
			p += l1;
			auto bottom = LoadU(du8, p); // bottom line
			p += l1;

			auto source = InterleaveLower(du8, top, bottom);
			auto pix = BitCast(di16, source);

			sum = Add(sum, MulAddAdjacent(pix, mmk));
		}*/
		for (; i < n; ++i) {
			auto mmk = Set(di16, k[i]);

			auto top = LoadU(du8, p); /* top line */
			p += l1;

			auto source = InterleaveLower(du8, top, Zero(du8));
			auto pix = BitCast(di16, source);

			sum = Add(sum, MulAddAdjacent(pix, mmk));
		}

		sum = ShiftRight<VIPS_INTERPOLATE_SHIFT>(sum);

		auto demoted = DemoteTo(du8x32, sum);
		StoreU(demoted, du8x32, q);
	}

	/* `ne` was not a multiple of the vector length `N`;
	 * proceed one by one.
	 */
	for (; x < ne; ++x) {
		auto *HWY_RESTRICT p = (uint8_t *) pin + x;
		auto *HWY_RESTRICT q = (uint8_t *) pout + x;

		auto sum = initial;

		for (int32_t i = 0; i < n; ++i) {
			auto mmk = Set(di16, k[i]);

			auto top = LoadU(du8x32, p); /* top line */
			p += l1;

			auto source = PromoteTo(di32, top);
			auto pix = BitCast(di16, source);

			sum = Add(sum, MulAddAdjacent(pix, mmk));
		}

		sum = ShiftRight<VIPS_INTERPOLATE_SHIFT>(sum);

		auto demoted = DemoteTo(du8x32, sum);
		*q = GetLane(demoted);
	}
}

} /*namespace HWY_NAMESPACE*/

#if HWY_ONCE
HWY_EXPORT(vips_reduce_uchar_hwy);

void
vips_reduce_uchar_hwy(VipsPel *pout, VipsPel *pin,
	int n, int ne, int lskip, const short *restrict k)
{
	/* clang-format off */
	HWY_DYNAMIC_DISPATCH(vips_reduce_uchar_hwy)(pout, pin, n, ne, lskip, k);
	/* clang-format on */
}
#endif /*HWY_ONCE*/

#endif /*HAVE_HWY*/
