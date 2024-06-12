/* 20/08/22 kleisauke
 * 	- initial implementation
 * 07/09/22 kleisauke
 * 	- implement using ReorderWidenMulAccumulate
 * 29/11/22 kleisauke
 * 	- prefer use of RearrangeToOddPlusEven
 * 02/10/23 kleisauke
 * 	- prefer use of InterleaveWhole{Lower,Upper} on RVV/SVE
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
constexpr Rebind<uint8_t, DI16> du8x16;
constexpr Rebind<uint8_t, DI32> du8x32;
constexpr DI16 di16;
constexpr DI32 di32;

#if defined(HAVE_HWY_1_1_0) && \
	(HWY_ARCH_RVV || (HWY_ARCH_ARM_A64 && HWY_TARGET <= HWY_SVE))
#define InterleaveLower InterleaveWholeLower
#define InterleaveUpper InterleaveWholeUpper
#endif

HWY_ATTR void
vips_convi_uchar_hwy(VipsRegion *out_region, VipsRegion *ir, VipsRect *r,
	int32_t ne, int32_t nnz, int32_t offset, const int32_t *HWY_RESTRICT offsets,
	const int16_t *HWY_RESTRICT mant, int32_t exp)
{
#if HWY_TARGET != HWY_SCALAR
	int32_t bo = VIPS_RECT_BOTTOM(r);

#if !defined(HAVE_HWY_1_1_0) && \
	(HWY_ARCH_RVV || (HWY_ARCH_ARM_A64 && HWY_TARGET <= HWY_SVE))
	/* Ensure we do not cross 128-bit block boundaries on RVV/SVE.
	 */
	const int32_t N = 16;
#else
	const int32_t N = Lanes(du8);
#endif

	const auto zero = Zero(du8);
	const auto v_exp = Set(di32, 1 << (exp - 1));
	const auto v_offset = Set(di32, offset);

	for (int32_t y = r->top; y < bo; ++y) {
		VipsPel *HWY_RESTRICT p = VIPS_REGION_ADDR(ir, r->left, y);
		VipsPel *HWY_RESTRICT q = VIPS_REGION_ADDR(out_region, r->left, y);

		/* Main loop: unrolled.
		 */
		int32_t x = 0;
		for (; x + N <= ne; x += N) {
#if HWY_ARCH_X86 || HWY_ARCH_WASM || HWY_TARGET == HWY_EMU128
			/* Initialize the sum with the addition on x86 and Wasm,
			 * avoids an extra add instruction. Should be safe given
			 * that only one accumulator is used.
			 */
			auto sum0 = v_exp;
			auto sum2 = v_exp;
			auto sum4 = v_exp;
			auto sum6 = v_exp;
#else
			auto sum0 = Zero(di32);
			auto sum2 = Zero(di32);
			auto sum4 = Zero(di32);
			auto sum6 = Zero(di32);
#endif
			auto sum1 = Zero(di32); /* unused on x86 and Wasm */
			auto sum3 = Zero(di32); /* unused on x86 and Wasm */
			auto sum5 = Zero(di32); /* unused on x86 and Wasm */
			auto sum7 = Zero(di32); /* unused on x86 and Wasm */

			int32_t i = 0;
			for (; i + 2 <= nnz; i += 2) {
				/* Load two coefficients at once.
				 */
				auto mmk = BitCast(di16,
					Set(di32, *(int32_t *) &mant[i]));

				/* Load with an offset.
				 */
				auto top = LoadU(du8, /* top line */
					p + offsets[i]);
				auto bottom = LoadU(du8, /* bottom line */
					p + offsets[i + 1]);

				auto source = InterleaveLower(top, bottom);
				auto pix = BitCast(di16, InterleaveLower(source, zero));

				sum0 = ReorderWidenMulAccumulate(di32, pix, mmk, sum0,
					/* byref */ sum1);

				pix = BitCast(di16, InterleaveUpper(du8, source, zero));

				sum2 = ReorderWidenMulAccumulate(di32, pix, mmk, sum2,
					/* byref */ sum3);

				source = InterleaveUpper(du8, top, bottom);
				pix = BitCast(di16, InterleaveLower(source, zero));

				sum4 = ReorderWidenMulAccumulate(di32, pix, mmk, sum4,
					/* byref */ sum5);

				pix = BitCast(di16, InterleaveUpper(du8, source, zero));

				sum6 = ReorderWidenMulAccumulate(di32, pix, mmk, sum6,
					/* byref */ sum7);
			}
			for (; i < nnz; ++i) {
				auto mmk = Set(di16, mant[i]);

				/* Load with an offset.
				 */
				auto top = LoadU(du8, p + offsets[i]);

				auto source = InterleaveLower(top, zero);
				auto pix = BitCast(di16, InterleaveLower(source, zero));

				sum0 = ReorderWidenMulAccumulate(di32, pix, mmk, sum0,
					/* byref */ sum1);

				pix = BitCast(di16, InterleaveUpper(du8, source, zero));

				sum2 = ReorderWidenMulAccumulate(di32, pix, mmk, sum2,
					/* byref */ sum3);

				source = InterleaveUpper(du8, top, zero);
				pix = BitCast(di16, InterleaveLower(source, zero));

				sum4 = ReorderWidenMulAccumulate(di32, pix, mmk, sum4,
					/* byref */ sum5);

				pix = BitCast(di16, InterleaveUpper(du8, source, zero));

				sum6 = ReorderWidenMulAccumulate(di32, pix, mmk, sum6,
					/* byref */ sum7);
			}

			sum0 = RearrangeToOddPlusEven(sum0, sum1);
			sum2 = RearrangeToOddPlusEven(sum2, sum3);
			sum4 = RearrangeToOddPlusEven(sum4, sum5);
			sum6 = RearrangeToOddPlusEven(sum6, sum7);

#if !(HWY_ARCH_X86 || HWY_ARCH_WASM || HWY_TARGET == HWY_EMU128)
			sum0 = Add(sum0, v_exp);
			sum2 = Add(sum2, v_exp);
			sum4 = Add(sum4, v_exp);
			sum6 = Add(sum6, v_exp);
#endif

			/* The final 32->8 conversion.
			 */
			sum0 = ShiftRightSame(sum0, exp);
			sum2 = ShiftRightSame(sum2, exp);
			sum4 = ShiftRightSame(sum4, exp);
			sum6 = ShiftRightSame(sum6, exp);
			sum0 = Add(sum0, v_offset);
			sum2 = Add(sum2, v_offset);
			sum4 = Add(sum4, v_offset);
			sum6 = Add(sum6, v_offset);

#if HWY_ARCH_RVV || (HWY_ARCH_ARM_A64 && HWY_TARGET <= HWY_SVE)
			/* RVV/SVE defines demotion as writing to the upper or lower half
			 * of each lane, rather than compacting them within a vector.
			 */
			auto demoted0 = DemoteTo(du8x32, sum0);
			auto demoted1 = DemoteTo(du8x32, sum2);
			auto demoted2 = DemoteTo(du8x32, sum4);
			auto demoted3 = DemoteTo(du8x32, sum6);

			StoreU(demoted0, du8x32, q + x + 0 * N / 4);
			StoreU(demoted1, du8x32, q + x + 1 * N / 4);
			StoreU(demoted2, du8x32, q + x + 2 * N / 4);
			StoreU(demoted3, du8x32, q + x + 3 * N / 4);
#else
			auto demoted0 = ReorderDemote2To(di16, sum0, sum2);
			auto demoted2 = ReorderDemote2To(di16, sum4, sum6);
			auto demoted = ReorderDemote2To(du8, demoted0, demoted2);

			StoreU(demoted, du8, q + x);
#endif
			p += N;
		}

		/* `ne` was not a multiple of the vector length `N`;
		 * proceed one by one.
		 */
		for (; x < ne; ++x) {
#if HWY_ARCH_X86 || HWY_ARCH_WASM || HWY_TARGET == HWY_EMU128
			/* Initialize the sum with the addition on x86 and Wasm,
			 * avoids an extra add instruction. Should be safe given
			 * that only one accumulator is used.
			 */
			auto sum0 = v_exp;
#else
			auto sum0 = Zero(di32);
#endif
			auto sum1 = Zero(di32); /* unused on x86 and Wasm */

			int32_t i = 0;
			for (; i + 2 <= nnz; i += 2) {
				/* Load two coefficients at once.
				 */
				auto mmk = BitCast(di16,
					Set(di32, *(int32_t *) &mant[i]));

				/* Load with an offset.
				 */
				auto top = LoadU(du8x16, /* top line */
					p + offsets[i]);
				auto bottom = LoadU(du8x16, /* bottom line */
					p + offsets[i + 1]);

				auto source = InterleaveLower(top, bottom);
				auto pix = PromoteTo(di16, source);

				sum0 = ReorderWidenMulAccumulate(di32, pix, mmk, sum0,
					/* byref */ sum1);
			}
			for (; i < nnz; ++i) {
				auto mmk = Set(di16, mant[i]);

				/* Load with an offset.
				 */
				auto top = LoadU(du8x32, p + offsets[i]);

				auto source = PromoteTo(di32, top);
				auto pix = BitCast(di16, source);

				sum0 = ReorderWidenMulAccumulate(di32, pix, mmk, sum0,
					/* byref */ sum1);
			}

			sum0 = RearrangeToOddPlusEven(sum0, sum1);

#if !(HWY_ARCH_X86 || HWY_ARCH_WASM || HWY_TARGET == HWY_EMU128)
			sum0 = Add(sum0, v_exp);
#endif

			/* The final 32->8 conversion.
			 */
			sum0 = ShiftRightSame(sum0, exp);
			sum0 = Add(sum0, v_offset);

			auto demoted = DemoteTo(du8x32, sum0);
			q[x] = GetLane(demoted);
			p += 1;
		}
	}
#endif
}

#undef InterleaveLower
#undef InterleaveUpper

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
