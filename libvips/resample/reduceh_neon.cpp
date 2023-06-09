#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/

#include <stdlib.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include "presample.h"

#if HAVE_NEON

#include <arm_neon.h>

void
reduceh_uchar_simd_4bands(VipsPel *pout, VipsPel *pin,
	int32_t n, int32_t width,
	int16_t *restrict cs[VIPS_TRANSFORM_SCALE + 1],
	double Xstart, double Xstep)
{
	int32_t x, i;
	double X = Xstart;

	uint8x16_t line8;
	int32x4_t line32;
	int32x4_t sum;
	int16x4_t sum_16;
	uint8x8_t sum_8;

	const int32x4_t initial = vdupq_n_s32(VIPS_INTERPOLATE_SCALE >> 1);

	//  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
	// r0 g0 b0 a0 r1 g1 b1 a1 r2 g2 b2 a2 r3 g3 b3 a3
	const uint8x16_t tbl0 = {
		0, 16, 16, 16, 1, 16, 16, 16,
		2, 16, 16, 16, 3, 16, 16, 16
	};
	const uint8x16_t tbl1 = {
		4, 16, 16, 16, 5, 16, 16, 16,
		6, 16, 16, 16, 7, 16, 16, 16
	};
	const uint8x16_t tbl2 = {
		8, 16, 16, 16, 9, 16, 16, 16,
		10, 16, 16, 16, 11, 16, 16, 16
	};
	const uint8x16_t tbl3 = {
		12, 16, 16, 16, 13, 16, 16, 16,
		14, 16, 16, 16, 15, 16, 16, 16
	};

	for (x = 0; x < width; x++) {
		const int ix = (int) X;
		const int sx = X * VIPS_TRANSFORM_SCALE * 2;
		const int six = sx & (VIPS_TRANSFORM_SCALE * 2 - 1);
		const int tx = (six + 1) >> 1;
		const int16_t *c = cs[tx];

		uint8_t *restrict p = pin + ix * 4;
		uint8_t *restrict q = pout + x * 4;

		sum = initial;

		for (i = 0; i <= n - 4; i += 4) {
			line8 = vld1q_u8(p);
			p += 16;

			line32 = vreinterpretq_s32_u8(vqtbl1q_u8(line8, tbl0));
			sum = vmlaq_n_s32(sum, line32, c[i]);
			line32 = vreinterpretq_s32_u8(vqtbl1q_u8(line8, tbl1));
			sum = vmlaq_n_s32(sum, line32, c[i + 1]);
			line32 = vreinterpretq_s32_u8(vqtbl1q_u8(line8, tbl2));
			sum = vmlaq_n_s32(sum, line32, c[i + 2]);
			line32 = vreinterpretq_s32_u8(vqtbl1q_u8(line8, tbl3));
			sum = vmlaq_n_s32(sum, line32, c[i + 3]);
		}

		for (; i <= n - 2; i += 2) {
			line8 = vreinterpretq_u8_u64(vdupq_n_u64(*(uint64_t *) p));
			p += 8;

			line32 = vreinterpretq_s32_u8(vqtbl1q_u8(line8, tbl0));
			sum = vmlaq_n_s32(sum, line32, c[i]);
			line32 = vreinterpretq_s32_u8(vqtbl1q_u8(line8, tbl1));
			sum = vmlaq_n_s32(sum, line32, c[i + 1]);
		}

		if (i < n) {
			line8 = vreinterpretq_u8_u32(vdupq_n_u32(*(uint32_t *) p));
			p += 4;

			line32 = vreinterpretq_s32_u8(vqtbl1q_u8(line8, tbl0));
			sum = vmlaq_n_s32(sum, line32, c[i]);
		}

		sum = vshrq_n_s32(sum, VIPS_INTERPOLATE_SHIFT);

		sum_16 = vqmovn_s32(sum);
		sum_8 = vqmovun_s16(vcombine_s16(sum_16, sum_16));
		*(uint32_t *) q = vget_lane_u32(vreinterpret_u32_u8(sum_8), 0);

		X += Xstep;
	}
}

void
reduceh_uchar_simd_3bands(VipsPel *pout, VipsPel *pin,
	int32_t n, int32_t width,
	int16_t *restrict cs[VIPS_TRANSFORM_SCALE + 1],
	double Xstart, double Xstep)
{
	int32_t x, i;
	double X = Xstart;

	uint8x16_t line8;
	int32x4_t line32;
	int32x4_t sum;
	int16x4_t sum_16;
	uint8x8_t sum_8;

	const int32x4_t initial = vdupq_n_s32(VIPS_INTERPOLATE_SCALE >> 1);

	//  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
	// r0 g0 b0 r1 g1 b1 r2 g2 b2 r3 g3 b3
	const uint8x16_t tbl0 = {
		0, 16, 16, 16, 1, 16, 16, 16,
		2, 16, 16, 16, 16, 16, 16, 16
	};
	const uint8x16_t tbl1 = {
		3, 16, 16, 16, 4, 16, 16, 16,
		5, 16, 16, 16, 16, 16, 16, 16
	};
	const uint8x16_t tbl2 = {
		6, 16, 16, 16, 7, 16, 16, 16,
		8, 16, 16, 16, 16, 16, 16, 16
	};
	const uint8x16_t tbl3 = {
		9, 16, 16, 16, 10, 16, 16, 16,
		11, 16, 16, 16, 16, 16, 16, 16
	};

	/* We need to load 4-byte aligned groups but we have a 3-band image.
	 * So when we load or save data, we load or save a few redundant bytes.
	 * We can safely do it until width-1 since we won't get out of
	 * buffers range.
	 */
	for (x = 0; x < width - 1; x++) {
		const int ix = (int) X;
		const int sx = X * VIPS_TRANSFORM_SCALE * 2;
		const int six = sx & (VIPS_TRANSFORM_SCALE * 2 - 1);
		const int tx = (six + 1) >> 1;
		const int16_t *c = cs[tx];

		uint8_t *restrict p = pin + ix * 3;
		uint8_t *restrict q = pout + x * 3;

		sum = initial;

		for (i = 0; i <= n - 4; i += 4) {
			line8 = vld1q_u8(p);
			p += 12;

			line32 = vreinterpretq_s32_u8(vqtbl1q_u8(line8, tbl0));
			sum = vmlaq_n_s32(sum, line32, c[i]);
			line32 = vreinterpretq_s32_u8(vqtbl1q_u8(line8, tbl1));
			sum = vmlaq_n_s32(sum, line32, c[i + 1]);
			line32 = vreinterpretq_s32_u8(vqtbl1q_u8(line8, tbl2));
			sum = vmlaq_n_s32(sum, line32, c[i + 2]);
			line32 = vreinterpretq_s32_u8(vqtbl1q_u8(line8, tbl3));
			sum = vmlaq_n_s32(sum, line32, c[i + 3]);
		}

		for (; i <= n - 2; i += 2) {
			line8 = vreinterpretq_u8_u64(vdupq_n_u64(*(uint64_t *) p));
			p += 6;

			line32 = vreinterpretq_s32_u8(vqtbl1q_u8(line8, tbl0));
			sum = vmlaq_n_s32(sum, line32, c[i]);
			line32 = vreinterpretq_s32_u8(vqtbl1q_u8(line8, tbl1));
			sum = vmlaq_n_s32(sum, line32, c[i + 1]);
		}

		if (i < n) {
			line8 = vreinterpretq_u8_u32(vdupq_n_u32(*(uint32_t *) p));
			p += 3;

			line32 = vreinterpretq_s32_u8(vqtbl1q_u8(line8, tbl0));
			sum = vmlaq_n_s32(sum, line32, c[i]);
		}

		sum = vshrq_n_s32(sum, VIPS_INTERPOLATE_SHIFT);

		sum_16 = vqmovn_s32(sum);
		sum_8 = vqmovun_s16(vcombine_s16(sum_16, sum_16));
		*(uint32_t *) q = vget_lane_u32(vreinterpret_u32_u8(sum_8), 0);

		X += Xstep;
	}

	/* Less optimal but safe approach for the last x.
	 * We can't load nor save 4 bytes anymore since we'll get out of
	 * buffers range. So for the last x, we carefully load 3 bytes and
	 * carefully save 3 bytes.
	 */
	const int ix = (int) X;
	const int sx = X * VIPS_TRANSFORM_SCALE * 2;
	const int six = sx & (VIPS_TRANSFORM_SCALE * 2 - 1);
	const int tx = (six + 1) >> 1;
	const int16_t *c = cs[tx];

	uint8_t *restrict p = pin + ix * 3;
	uint8_t *restrict q = pout + x * 3;

	sum = initial;

	for (i = 0; i < n; i++) {
		line32 = (int32x4_t){ p[0], p[1], p[2], 0 };
		p += 3;

		sum = vmlaq_n_s32(sum, line32, c[i]);
	}

	sum = vshrq_n_s32(sum, VIPS_INTERPOLATE_SHIFT);

	q[0] = vgetq_lane_s32(sum, 0);
	q[1] = vgetq_lane_s32(sum, 1);
	q[2] = vgetq_lane_s32(sum, 2);
}

void
reduceh_uchar_simd(VipsPel *pout, VipsPel *pin, int32_t bands,
	int32_t n, int32_t width,
	int16_t *restrict cs[VIPS_TRANSFORM_SCALE + 1],
	double Xstart, double Xstep)
{

	switch (bands) {
	case 4:
		return reduceh_uchar_simd_4bands(
			pout, pin, n, width, cs, Xstart, Xstep);
	case 3:
		return reduceh_uchar_simd_3bands(
			pout, pin, n, width, cs, Xstart, Xstep);
	default:
		g_assert_not_reached();
	}
}

#endif /*HAVE_NEON*/
