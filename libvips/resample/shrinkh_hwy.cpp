/* 15/11/24 kleisauke
 * 	- from shrinkv_hwy.cpp
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
#define HWY_TARGET_INCLUDE "libvips/resample/shrinkh_hwy.cpp"
#include <hwy/foreach_target.h>
#include <hwy/highway.h>

namespace HWY_NAMESPACE {

using namespace hwy::HWY_NAMESPACE;

using DU32 = ScalableTag<uint32_t>;
constexpr Rebind<uint8_t, DU32> du8x32;
constexpr DU32 du32;

constexpr int64_t max_uint32 = 1LL << 32;
constexpr int32_t max_bits = 1 << 8;

HWY_ATTR void
vips_shrinkh_uchar_hwy(VipsPel *pout, VipsPel *pin,
	int32_t width, int32_t hshrink, int32_t bands)
{
#if HWY_TARGET != HWY_SCALAR
	const auto multiplier = Set(du32, max_uint32 / (max_bits * hshrink));
	const auto amend = Set(du32, hshrink / 2);

	int32_t ix = 0;

	for (int32_t x = 0; x < width; ++x) {
		auto *HWY_RESTRICT p = (uint8_t *) pin + ix * bands;
		auto *HWY_RESTRICT q = (uint8_t *) pout + x * bands;

		auto sum0 = amend;

		int32_t xx = 0;
		for (; xx + 2 <= hshrink; xx += 2) {
			auto pix0 = PromoteTo(du32, LoadU(du8x32, p));
			p += bands;
			auto pix1 = PromoteTo(du32, LoadU(du8x32, p));
			p += bands;

			pix0 = Add(pix0, pix1);
			sum0 = Add(sum0, pix0);
		}
		for (; xx < hshrink; ++xx) {
			auto pix0 = PromoteTo(du32, LoadU(du8x32, p));
			p += bands;

			sum0 = Add(sum0, pix0);
		}

		sum0 = Mul(sum0, multiplier);

		/* The final 32->8 conversion.
		 */
		sum0 = ShiftRight<24>(sum0);

		auto demoted = DemoteTo(du8x32, sum0);
		StoreU(demoted, du8x32, q);

		ix += hshrink;
	}
#endif
}

} /*namespace HWY_NAMESPACE*/

#if HWY_ONCE
HWY_EXPORT(vips_shrinkh_uchar_hwy);

void
vips_shrinkh_uchar_hwy(VipsPel *pout, VipsPel *pin,
	int width, int hshrink, int bands)
{
	/* clang-format off */
	HWY_DYNAMIC_DISPATCH(vips_shrinkh_uchar_hwy)(pout, pin,
		width, hshrink, bands);
	/* clang-format on */
}
#endif /*HWY_ONCE*/

#endif /*HAVE_HWY*/
