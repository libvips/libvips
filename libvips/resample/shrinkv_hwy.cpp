/* 14/11/24 kleisauke
 * 	- from reducev_hwy.cpp
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
#define HWY_TARGET_INCLUDE "libvips/resample/shrinkv_hwy.cpp"
#include <hwy/foreach_target.h>
#include <hwy/highway.h>

namespace HWY_NAMESPACE {

using namespace hwy::HWY_NAMESPACE;

using DU32 = ScalableTag<uint32_t>;
using DU16 = ScalableTag<uint16_t>;
constexpr Rebind<uint8_t, DU16> du8x16;
#if HWY_ARCH_RVV || (HWY_ARCH_ARM_A64 && HWY_TARGET <= HWY_SVE)
constexpr Rebind<uint8_t, DU32> du8x32;
#endif
constexpr DU16 du16;
constexpr DU32 du32;

constexpr int64_t max_uint32 = 1LL << 32;
constexpr int32_t max_bits = 1 << 8;

#if defined(HAVE_HWY_1_1_0) && \
	(HWY_ARCH_RVV || (HWY_ARCH_ARM_A64 && HWY_TARGET <= HWY_SVE))
#define InterleaveLower InterleaveWholeLower
#define InterleaveUpper InterleaveWholeUpper
#endif

HWY_ATTR void
vips_shrinkv_uchar_hwy(VipsPel *pout, VipsPel *pin,
	int32_t ne, int32_t vshrink, int32_t lskip)
{
#if HWY_TARGET != HWY_SCALAR
	const auto l1 = lskip / sizeof(uint8_t);

#if !defined(HAVE_HWY_1_1_0) && \
	(HWY_ARCH_RVV || (HWY_ARCH_ARM_A64 && HWY_TARGET <= HWY_SVE))
	/* Ensure we do not cross 128-bit block boundaries on RVV/SVE.
	 */
	const int32_t N = 8;
#else
	const int32_t N = Lanes(du16);
#endif

	const uint32_t multiplier = max_uint32 / (max_bits * vshrink);
	const uint32_t amend = vshrink / 2;

	const auto zero = Zero(du16);
	const auto multiplier_v = Set(du32, multiplier);
	const auto amend_v = Set(du32, amend);

	/* Main loop: unrolled.
	 */
	int32_t x = 0;
	for (; x + N <= ne; x += N) {
		auto *HWY_RESTRICT p = (uint8_t *) pin + x;
		auto *HWY_RESTRICT q = (uint8_t *) pout + x;

		auto sum0 = amend_v;
		auto sum1 = amend_v;

		int32_t yy = 0;
		for (; yy + 2 <= vshrink; yy += 2) {
			auto pix0 = PromoteTo(du16, LoadU(du8x16, p));
			p += l1;
			auto pix1 = PromoteTo(du16, LoadU(du8x16, p));
			p += l1;

			pix0 = Add(pix0, pix1);

			sum0 = Add(sum0, BitCast(du32, InterleaveLower(du16, pix0, zero)));
			sum1 = Add(sum1, BitCast(du32, InterleaveUpper(du16, pix0, zero)));
		}
		for (; yy < vshrink; ++yy) {
			auto pix0 = PromoteTo(du16, LoadU(du8x16, p));
			p += l1;

			sum0 = Add(sum0, BitCast(du32, InterleaveLower(du16, pix0, zero)));
			sum1 = Add(sum1, BitCast(du32, InterleaveUpper(du16, pix0, zero)));
		}

		sum0 = Mul(sum0, multiplier_v);
		sum1 = Mul(sum1, multiplier_v);

		/* The final 32->8 conversion.
		 */
		sum0 = ShiftRight<24>(sum0);
		sum1 = ShiftRight<24>(sum1);

#if HWY_ARCH_RVV || (HWY_ARCH_ARM_A64 && HWY_TARGET <= HWY_SVE)
		/* RVV/SVE defines demotion as writing to the upper or lower half
		 * of each lane, rather than compacting them within a vector.
		 */
		auto demoted0 = DemoteTo(du8x32, sum0);
		auto demoted1 = DemoteTo(du8x32, sum1);

		StoreU(demoted0, du8x32, q + 0 * N / 2);
		StoreU(demoted1, du8x32, q + 1 * N / 2);
#else
		auto demoted0 = ReorderDemote2To(du16, sum0, sum1);
		auto demoted = DemoteTo(du8x16, demoted0);

		StoreU(demoted, du8x16, q);
#endif
	}

	/* `ne` was not a multiple of the vector length `N`;
	 * proceed one by one.
	 */
	for (; x < ne; ++x) {
		auto *HWY_RESTRICT p = (uint8_t *) pin + x;
		auto *HWY_RESTRICT q = (uint8_t *) pout + x;

		uint32_t sum = amend;

		int32_t yy = 0;
		for (; yy + 2 <= vshrink; yy += 2) {
			auto pix0 = *p;
			p += l1;
			auto pix1 = *p;
			p += l1;

			sum += pix0 + pix1;
		}
		for (; yy < vshrink; ++yy) {
			auto pix0 = *p;
			p += l1;

			sum += pix0;
		}

		*q = (sum * multiplier) >> 24;
	}
#endif
}

#undef InterleaveLower
#undef InterleaveUpper

} /*namespace HWY_NAMESPACE*/

#if HWY_ONCE
HWY_EXPORT(vips_shrinkv_uchar_hwy);

void
vips_shrinkv_uchar_hwy(VipsPel *pout, VipsPel *pin,
	int ne, int vshrink, int lskip)
{
	/* clang-format off */
	HWY_DYNAMIC_DISPATCH(vips_shrinkv_uchar_hwy)(pout, pin,
		ne, vshrink, lskip);
	/* clang-format on */
}
#endif /*HWY_ONCE*/

#endif /*HAVE_HWY*/
