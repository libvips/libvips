#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/

#include <stdlib.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include "pconvolution.h"

#if HAVE_NEON

#include <arm_neon.h>

void
convi_uchar_simd(VipsPel *pout, VipsPel *pin,
	int32_t n, int32_t ne, int32_t offset, int32_t *restrict offsets,
	int16_t *restrict mant, int32_t exp)
{
	int32_t x, i;

	uint8x16_t line8;
	int32x4_t line32, col, vc;
	int32x4_t sum0, sum1, sum2, sum3;
	int16x8_t sum01, sum23;
	uint8x16_t sum0123;

	const int32_t initial1 = 1 << (exp - 1);
	const int32x4_t initial = vdupq_n_s32(initial1);
	const int32x4_t voffset = vdupq_n_s32(offset);

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

	for (x = 0; x <= ne - 16; x += 16) {
		uint8_t *restrict p = (uint8_t *) pin + x;
		uint8_t *restrict q = (uint8_t *) pout + x;

		sum0 = initial;
		sum1 = initial;
		sum2 = initial;
		sum3 = initial;

		for (i = 0; i < n; i++) {
			vc = vdupq_n_s32(mant[i]);

			line8 = vld1q_u8(p + offsets[i]);

			line32 = vreinterpretq_s32_u8(vqtbl1q_u8(line8, tbl0));
			sum0 = vmlaq_s32(sum0, line32, vc);
			line32 = vreinterpretq_s32_u8(vqtbl1q_u8(line8, tbl1));
			sum1 = vmlaq_s32(sum1, line32, vc);
			line32 = vreinterpretq_s32_u8(vqtbl1q_u8(line8, tbl2));
			sum2 = vmlaq_s32(sum2, line32, vc);
			line32 = vreinterpretq_s32_u8(vqtbl1q_u8(line8, tbl3));
			sum3 = vmlaq_s32(sum3, line32, vc);
		}

		sum0 = vshrq_n_s32(sum0, exp);
		sum1 = vshrq_n_s32(sum1, exp);
		sum2 = vshrq_n_s32(sum2, exp);
		sum3 = vshrq_n_s32(sum3, exp);

		sum0 = vaddq_s32(sum0, voffset);
		sum1 = vaddq_s32(sum1, voffset);
		sum2 = vaddq_s32(sum2, voffset);
		sum3 = vaddq_s32(sum3, voffset);

		sum01 = vqmovn_high_s32(vqmovn_s32(sum0), sum1);
		sum23 = vqmovn_high_s32(vqmovn_s32(sum2), sum3);
		sum0123 = vqmovun_high_s16(vqmovun_s16(sum01), sum23);

		vst1q_u8(q, sum0123);
	}

	for (; x <= ne - 8; x += 8) {
		uint8_t *restrict p = (uint8_t *) pin + x;
		uint8_t *restrict q = (uint8_t *) pout + x;

		sum0 = initial;
		sum1 = initial;

		for (i = 0; i < n; i++) {
			vc = vdupq_n_s32(mant[i]);

			/* Load 8 pels into uint8x16
			 */
			line8 = vreinterpretq_u8_u64(
				vdupq_n_u64(*(uint64_t *) (p + offsets[i])));

			line32 = vreinterpretq_s32_u8(vqtbl1q_u8(line8, tbl0));
			sum0 = vmlaq_s32(sum0, line32, vc);
			line32 = vreinterpretq_s32_u8(vqtbl1q_u8(line8, tbl1));
			sum1 = vmlaq_s32(sum1, line32, vc);
		}

		sum0 = vshrq_n_s32(sum0, exp);
		sum1 = vshrq_n_s32(sum1, exp);

		sum0 = vaddq_s32(sum0, voffset);
		sum1 = vaddq_s32(sum1, voffset);

		sum01 = vqmovn_high_s32(vqmovn_s32(sum0), sum1);

		vst1_u8(q, vqmovun_s16(sum01));
	}

	for (; x <= ne - 4; x += 4) {
		uint8_t *restrict p = (uint8_t *) pin + x;
		uint8_t *restrict q = (uint8_t *) pout + x;

		sum0 = initial;

		for (i = 0; i < n; i++) {
			/* Load 4 pels into uint8x16
			 */
			line8 = vreinterpretq_u8_u32(
				vdupq_n_u32(*(uint32_t *) (p + offsets[i])));

			line32 = vreinterpretq_s32_u8(vqtbl1q_u8(line8, tbl0));
			sum0 = vmlaq_n_s32(sum0, line32, mant[i]);
		}

		sum0 = vshrq_n_s32(sum0, exp);

		sum0 = vaddq_s32(sum0, voffset);

		const int16x4_t sum_16 = vqmovn_s32(sum0);
		const uint8x8_t sum_8 = vqmovun_s16(vcombine_s16(sum_16, sum_16));
		*(uint32_t *) q = vget_lane_u32(
			vreinterpret_u32_u8(sum_8), 0);
	}

	for (; x < ne; x++) {
		uint8_t *restrict p = (uint8_t *) pin + x;
		uint8_t *restrict q = (uint8_t *) pout + x;

		sum0 = int32x4_t{initial1, 0, 0, 0};

		i = 0;

		for (; i <= n - 4; i += 4) {
			/* Load four coeffs
			 */
			vc = vmovl_s16(vld1_s16(&mant[i]));

			col = int32x4_t{
				p[offsets[i]],
				p[offsets[i + 1]],
				p[offsets[i + 2]],
				p[offsets[i + 3]]
			};

			sum0 = vmlaq_s32(sum0, col, vc);
		}

		for (; i <= n - 2; i += 2) {
			/* Load two coeffs
			 */
			vc = vmovl_s16(vreinterpret_s16_s32(
				vdup_n_s32(*(int32_t *) &mant[i])));

			col = int32x4_t{
				p[offsets[i]],
				p[offsets[i + 1]],
				0,
				0
			};

			sum0 = vmlaq_s32(sum0, col, vc);
		}

		int32_t sum = vaddvq_s32(sum0);

		if (i < n)
			sum += (int32_t) (p[offsets[i]]) * mant[i];

		*q = (uint8_t) (sum >> exp) + offset;
	}
}

#endif /*HAVE_NEON*/
