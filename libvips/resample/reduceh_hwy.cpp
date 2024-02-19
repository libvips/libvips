/* 22/07/23 kleisauke
 * 	- from reducev_hwy.cpp
 * 02/12/23 kleisauke
 * 	- prefer use of Dup128VecFromValues
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
	021100301  USA

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
#define HWY_TARGET_INCLUDE "libvips/resample/reduceh_hwy.cpp"
#include <hwy/foreach_target.h>
#include <hwy/highway.h>

namespace HWY_NAMESPACE {

using namespace hwy::HWY_NAMESPACE;

using DI32 = ScalableTag<int32_t>;
using DI16 = ScalableTag<int16_t>;
using DI8 = ScalableTag<int8_t>;
using DU8 = ScalableTag<uint8_t>;
constexpr DU8 du8;
constexpr Rebind<uint8_t, DI32> du8x32;
constexpr DI8 di8;
constexpr DI16 di16;
constexpr DI32 di32;

HWY_ATTR void
vips_reduceh_uchar_hwy(VipsPel *pout, VipsPel *pin,
	int32_t n, int32_t width, int32_t bands,
	int16_t *HWY_RESTRICT cs[VIPS_TRANSFORM_SCALE + 1],
	double X, double hshrink)
{
#if HWY_TARGET != HWY_SCALAR
	const auto initial = Set(di32, VIPS_INTERPOLATE_SCALE >> 1);

#ifdef HAVE_HWY_1_1_0
	/*  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
	 * r0 g0 b0 r1 g1 b1 r2 g2 b2 r3 g3 b3
	 */
	const auto shuf3_lo = Dup128VecFromValues(di8,
		0, -1, 3, -1, 1, -1, 4, -1,
		2, -1, 5, -1, -1, -1, -1, -1);
	const auto shuf3_hi = Dup128VecFromValues(di8,
		6, -1, 9, -1, 7, -1, 10, -1,
		8, -1, 11, -1, -1, -1, -1, -1);

	/*  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
	 * r0 g0 b0 a0 r1 g1 b1 a1 r2 g2 b2 a2 r3 g3 b3 a3
	 */
	const auto shuf4_lo = Dup128VecFromValues(di8,
		0, -1, 4, -1, 1, -1, 5, -1,
		2, -1, 6, -1, 3, -1, 7, -1);
	const auto shuf4_hi = Dup128VecFromValues(di8,
		8, -1, 12, -1, 9, -1, 13, -1,
		10, -1, 14, -1, 11, -1, 15, -1);

	const auto shuf_lo = BitCast(di16, bands == 3 ? shuf3_lo : shuf4_lo);
	const auto shuf_hi = BitCast(di16, bands == 3 ? shuf3_hi : shuf4_hi);
#else
	/*  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
	 * r0 g0 b0 r1 g1 b1 r2 g2 b2 r3 g3 b3
	 */
	alignas(16) static constexpr int8_t tbl3_lo[16] = {
		0, -1, 3, -1, 1, -1, 4, -1,
		2, -1, 5, -1, -1, -1, -1, -1
	};
	alignas(16) static constexpr int8_t tbl3_hi[16] = {
		6, -1, 9, -1, 7, -1, 10, -1,
		8, -1, 11, -1, -1, -1, -1, -1
	};

	/*  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
	 * r0 g0 b0 a0 r1 g1 b1 a1 r2 g2 b2 a2 r3 g3 b3 a3
	 */
	alignas(16) static constexpr int8_t tbl4_lo[16] = {
		0, -1, 4, -1, 1, -1, 5, -1,
		2, -1, 6, -1, 3, -1, 7, -1
	};
	alignas(16) static constexpr int8_t tbl4_hi[16] = {
		8, -1, 12, -1, 9, -1, 13, -1,
		10, -1, 14, -1, 11, -1, 15, -1
	};

	const auto shuf_lo = BitCast(di16,
		LoadDup128(di8, bands == 3 ? tbl3_lo : tbl4_lo));
	const auto shuf_hi = BitCast(di16,
		LoadDup128(di8, bands == 3 ? tbl3_hi : tbl4_hi));
#endif

	for (int32_t x = 0; x < width; ++x) {
		const int ix = (int) X;
		const int sx = X * VIPS_TRANSFORM_SCALE * 2;
		const int six = sx & (VIPS_TRANSFORM_SCALE * 2 - 1);
		const int tx = (six + 1) >> 1;
		const int16_t *k = cs[tx];

		auto *HWY_RESTRICT p = (uint8_t *) pin + ix * bands;
		auto *HWY_RESTRICT q = (uint8_t *) pout + x * bands;

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
		for (; i + 4 <= n; i += 4) {
			/* Load four coefficients.
			 */
			auto mmk_lo = BitCast(di16, Set(di32, *(int32_t *) &k[i]));
			auto mmk_hi = BitCast(di16, Set(di32, *(int32_t *) &k[i + 2]));

			auto source = LoadU(du8, p);
			p += bands * 4;

			auto pix = TableLookupBytesOr0(source, shuf_lo);

			sum0 = ReorderWidenMulAccumulate(di32, pix, mmk_lo, sum0,
				/* byref */ sum1);

			pix = TableLookupBytesOr0(source, shuf_hi);

			sum0 = ReorderWidenMulAccumulate(di32, pix, mmk_hi, sum0,
				/* byref */ sum1);
		}
		for (; i + 2 <= n; i += 2) {
			/* Load two coefficients at once.
			 */
			auto mmk_lo = BitCast(di16, Set(di32, *(int32_t *) &k[i]));

			auto source = LoadU(du8, p);
			p += bands * 2;

			auto pix = TableLookupBytesOr0(source, shuf_lo);

			sum0 = ReorderWidenMulAccumulate(di32, pix, mmk_lo, sum0,
				/* byref */ sum1);
		}
		for (; i < n; ++i) {
			auto mmk = Set(di16, k[i]);

			auto source = LoadU(du8x32, p);
			p += bands;

			auto pix = BitCast(di16, PromoteTo(di32, source));

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
		StoreU(demoted, du8x32, q);

		X += hshrink;
	}
#endif
}

} /*namespace HWY_NAMESPACE*/

#if HWY_ONCE
HWY_EXPORT(vips_reduceh_uchar_hwy);

void
vips_reduceh_uchar_hwy(VipsPel *pout, VipsPel *pin,
	int n, int width, int bands,
	short *restrict cs[VIPS_TRANSFORM_SCALE + 1],
	double X, double hshrink)
{
	/* clang-format off */
	HWY_DYNAMIC_DISPATCH(vips_reduceh_uchar_hwy)(pout, pin,
		n, width, bands, cs, X, hshrink);
	/* clang-format on */
}
#endif /*HWY_ONCE*/

#endif /*HAVE_HWY*/
