/* 19/08/22 kleisauke
 * 	- initial implementation
 * 07/09/22 kleisauke
 * 	- implement using ReorderWidenMulAccumulate
 * 29/11/22 kleisauke
 * 	- prefer use of RearrangeToOddPlusEven
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

using DI32 = CappedTag<int32_t, 8>;
using DI16 = CappedTag<int16_t, 16>;
using DU8 = CappedTag<uint8_t, 32>;
constexpr DU8 du8;
constexpr Rebind<uint8_t, DI16> du8x16;
constexpr Rebind<uint8_t, DI32> du8x32;
constexpr DI16 di16;
constexpr DI32 di32;

HWY_ATTR void
vips_reduce_uchar_hwy(VipsPel *pout, VipsPel *pin,
	int32_t n, int32_t ne, int32_t lskip, const int16_t *HWY_RESTRICT k)
{
#if HWY_TARGET != HWY_SCALAR
	const auto l1 = lskip / sizeof(uint8_t);

	const int32_t N = Lanes(di32);
	const auto zero = Zero(du8);
	const auto initial = Set(di32, VIPS_INTERPOLATE_SCALE >> 1);

	/* Main loop: unrolled.
	 */
	int32_t x = 0;
	for (; x + N <= ne; x += N) {
		auto *HWY_RESTRICT p = (uint8_t *) pin + x;
		auto *HWY_RESTRICT q = (uint8_t *) pout + x;

#if HWY_ARCH_X86 || HWY_ARCH_WASM || HWY_TARGET == HWY_EMU128
		/* Initialize the sum with the addition on x86 and Wasm,
		 * avoids an extra add instruction. Should be safe given
		 * that only one accumulator is used.
		 */
		auto sum0 = initial; /* left row */
		auto sum2 = initial; /* right row */
#else
		auto sum0 = Zero(di32);
		auto sum2 = Zero(di32);
#endif
		auto sum1 = Zero(di32); /* unused on x86 and Wasm */
		auto sum3 = Zero(di32); /* unused on x86 and Wasm */

		int32_t i = 0;
		for (; i + 2 <= n; i += 2) {
			/* Load two coefficients at once.
			 */
			auto mmk = BitCast(di16, Set(di32, *(int32_t *) &k[i]));

			auto top = LoadU(du8, p); /* top line */
			p += l1;
			auto bottom = LoadU(du8, p); /* bottom line */
			p += l1;

			auto source = InterleaveLower(top, bottom);
			auto pix = BitCast(di16, InterleaveLower(source, zero));

			sum0 = ReorderWidenMulAccumulate(di32, pix, mmk, sum0,
				/* byref */ sum1);

			pix = BitCast(di16, InterleaveUpper(du8, source, zero));

			sum2 = ReorderWidenMulAccumulate(di32, pix, mmk, sum2,
				/* byref */ sum3);
		}
		for (; i < n; ++i) {
			auto mmk = Set(di16, k[i]);

			auto top = LoadU(du8, p);
			p += l1;

			auto source = InterleaveLower(top, zero);
			auto pix = BitCast(di16, InterleaveLower(source, zero));

			sum0 = ReorderWidenMulAccumulate(di32, pix, mmk, sum0,
				/* byref */ sum1);

			pix = BitCast(di16, InterleaveUpper(du8, source, zero));

			sum2 = ReorderWidenMulAccumulate(di32, pix, mmk, sum2,
				/* byref */ sum3);
		}

		sum0 = RearrangeToOddPlusEven(sum0, sum1);
		sum2 = RearrangeToOddPlusEven(sum2, sum3);

#if !(HWY_ARCH_X86 || HWY_ARCH_WASM || HWY_TARGET == HWY_EMU128)
		sum0 = Add(sum0, initial);
		sum2 = Add(sum2, initial);
#endif

		/* The final 32->8 conversion.
		 */
		sum0 = ShiftRight<VIPS_INTERPOLATE_SHIFT>(sum0);
		sum2 = ShiftRight<VIPS_INTERPOLATE_SHIFT>(sum2);

#if HWY_ARCH_RVV || (HWY_ARCH_ARM_A64 && HWY_TARGET <= HWY_SVE)
		/* RVV/SVE defines demotion as writing to the upper or lower half
		 * of each lane, rather than compacting them within a vector.
		 */
		auto demoted0 = DemoteTo(du8x32, sum0);
		auto demoted1 = DemoteTo(du8x32, sum2);
		StoreU(demoted0, du8x32, q);
		StoreU(demoted1, du8x32, q + 4);
#else
		auto demoted = DemoteTo(du8x16,
			ReorderDemote2To(di16, sum0, sum2));
		StoreU(demoted, du8x16, q);
#endif
	}

	/* `ne` was not a multiple of the vector length `N`;
	 * proceed one by one.
	 */
	for (; x < ne; ++x) {
		auto *HWY_RESTRICT p = (uint8_t *) pin + x;
		auto *HWY_RESTRICT q = (uint8_t *) pout + x;

#if HWY_ARCH_X86 || HWY_ARCH_WASM || HWY_TARGET == HWY_EMU128
		/* Initialize the sum with the addition on x86 and Wasm,
		 * avoids an extra add instruction. Should be safe given
		 * that only one accumulator is used.
		 */
		auto sum0 = initial;
#else
		auto sum0 = Zero(di32);
#endif
		auto sum1 = Zero(di32); /* unused on x86 and Wasm */

		int32_t i = 0;
		for (; i + 2 <= n; i += 2) {
			/* Load two coefficients at once.
			 */
			auto mmk = BitCast(di16, Set(di32, *(int32_t *) &k[i]));

			auto top = LoadU(du8x16, p); /* top line */
			p += l1;
			auto bottom = LoadU(du8x16, p); /* bottom line */
			p += l1;

			auto source = InterleaveLower(top, bottom);
			auto pix = PromoteTo(di16, source);

			sum0 = ReorderWidenMulAccumulate(di32, pix, mmk, sum0,
				/* byref */ sum1);
		}
		for (; i < n; ++i) {
			auto mmk = Set(di16, k[i]);

			auto top = LoadU(du8x32, p);
			p += l1;

			auto source = PromoteTo(di32, top);
			auto pix = BitCast(di16, source);

			sum0 = ReorderWidenMulAccumulate(di32, pix, mmk, sum0,
				/* byref */ sum1);
		}

		sum0 = RearrangeToOddPlusEven(sum0, sum1);

#if !(HWY_ARCH_X86 || HWY_ARCH_WASM || HWY_TARGET == HWY_EMU128)
		sum0 = Add(sum0, initial);
#endif

		/* The final 32->8 conversion.
		 */
		sum0 = ShiftRight<VIPS_INTERPOLATE_SHIFT>(sum0);

		auto demoted = DemoteTo(du8x32, sum0);
		*q = GetLane(demoted);
	}
#endif
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
