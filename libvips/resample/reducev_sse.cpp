#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/

#include <stdlib.h>
#include <stdint.h>

#include <vips/vips.h>
#include <vips/internal.h>

#include "presample.h"

#if HAVE_SSE

#include <smmintrin.h>

void
reducev_uchar_simd(VipsPel *pout, VipsPel *pin,
	int32_t n, int32_t ne, int32_t lskip, const int16_t *restrict c)
{
	int32_t x, i;

	__m128i line8, line8_hi, line8_lo, line16, vc;
	__m128i sum0, sum1, sum2, sum3;

	const __m128i initial = _mm_set1_epi32(VIPS_INTERPOLATE_SCALE >> 1);
	const __m128i zero = _mm_setzero_si128();

	const __m128i tbl0 = _mm_set_epi8(
		-1, -1, -1, 3, -1, -1, -1, 2,
		-1, -1, -1, 1, -1, -1, -1, 0);
	const __m128i tbl1 = _mm_set_epi8(
		-1, -1, -1, 7, -1, -1, -1, 6,
		-1, -1, -1, 5, -1, -1, -1, 4);
	const __m128i tbl2 = _mm_set_epi8(
		-1, -1, -1, 11, -1, -1, -1, 10,
		-1, -1, -1, 9, -1, -1, -1, 8);
	const __m128i tbl3 = _mm_set_epi8(
		-1, -1, -1, 15, -1, -1, -1, 14,
		-1, -1, -1, 13, -1, -1, -1, 12);

	for (x = 0; x <= ne - 16; x += 16) {
		uint8_t *restrict p = (uint8_t *) pin + x;
		uint8_t *restrict q = (uint8_t *) pout + x;

		sum0 = initial;
		sum1 = initial;
		sum2 = initial;
		sum3 = initial;

		for (i = 0; i <= n - 2; i += 2) {
			/* Load two coeffs
			 */
			vc = _mm_set1_epi32(*(int32_t *) &c[i]);

			line8_hi = _mm_loadu_si128((__m128i *) p);
			p += lskip;

			line8_lo = _mm_loadu_si128((__m128i *) p);
			p += lskip;

			line8 = _mm_unpacklo_epi8(line8_hi, line8_lo);

			line16 = _mm_unpacklo_epi8(line8, zero);
			sum0 = _mm_add_epi32(sum0, _mm_madd_epi16(line16, vc));
			line16 = _mm_unpackhi_epi8(line8, zero);
			sum1 = _mm_add_epi32(sum1, _mm_madd_epi16(line16, vc));

			line8 = _mm_unpackhi_epi8(line8_hi, line8_lo);

			line16 = _mm_unpacklo_epi8(line8, zero);
			sum2 = _mm_add_epi32(sum2, _mm_madd_epi16(line16, vc));
			line16 = _mm_unpackhi_epi8(line8, zero);
			sum3 = _mm_add_epi32(sum3, _mm_madd_epi16(line16, vc));
		}

		if (i < n) {
			vc = _mm_set1_epi16(c[i]);

			line8 = _mm_loadu_si128((__m128i *) p);

			line16 = _mm_shuffle_epi8(line8, tbl0);
			sum0 = _mm_add_epi32(sum0, _mm_madd_epi16(line16, vc));
			line16 = _mm_shuffle_epi8(line8, tbl1);
			sum1 = _mm_add_epi32(sum1, _mm_madd_epi16(line16, vc));
			line16 = _mm_shuffle_epi8(line8, tbl2);
			sum2 = _mm_add_epi32(sum2, _mm_madd_epi16(line16, vc));
			line16 = _mm_shuffle_epi8(line8, tbl3);
			sum3 = _mm_add_epi32(sum3, _mm_madd_epi16(line16, vc));
		}

		sum0 = _mm_srai_epi32(sum0, VIPS_INTERPOLATE_SHIFT);
		sum1 = _mm_srai_epi32(sum1, VIPS_INTERPOLATE_SHIFT);
		sum2 = _mm_srai_epi32(sum2, VIPS_INTERPOLATE_SHIFT);
		sum3 = _mm_srai_epi32(sum3, VIPS_INTERPOLATE_SHIFT);

		sum0 = _mm_packs_epi32(sum0, sum1);
		sum2 = _mm_packs_epi32(sum2, sum3);
		sum0 = _mm_packus_epi16(sum0, sum2);

		_mm_storeu_si128((__m128i *) q, sum0);
	}

	for (; x <= ne - 8; x += 8) {
		uint8_t *restrict p = (uint8_t *) pin + x;
		uint8_t *restrict q = (uint8_t *) pout + x;

		sum0 = initial;
		sum1 = initial;

		for (i = 0; i <= n - 2; i += 2) {
			/* Load two coeffs
			 */
			vc = _mm_set1_epi32(*(int32_t *) &c[i]);

			line8_hi = _mm_loadu_si64(p);
			p += lskip;

			line8_lo = _mm_loadu_si64(p);
			p += lskip;

			line8 = _mm_unpacklo_epi8(line8_hi, line8_lo);

			line16 = _mm_unpacklo_epi8(line8, zero);
			sum0 = _mm_add_epi32(sum0, _mm_madd_epi16(line16, vc));
			line16 = _mm_unpackhi_epi8(line8, zero);
			sum1 = _mm_add_epi32(sum1, _mm_madd_epi16(line16, vc));
		}

		if (i < n) {
			vc = _mm_set1_epi16(c[i]);

			line8 = _mm_loadu_si64(p);

			line16 = _mm_shuffle_epi8(line8, tbl0);
			sum0 = _mm_add_epi32(sum0, _mm_madd_epi16(line16, vc));
			line16 = _mm_shuffle_epi8(line8, tbl1);
			sum1 = _mm_add_epi32(sum1, _mm_madd_epi16(line16, vc));
		}

		sum0 = _mm_srai_epi32(sum0, VIPS_INTERPOLATE_SHIFT);
		sum1 = _mm_srai_epi32(sum1, VIPS_INTERPOLATE_SHIFT);

		sum0 = _mm_packs_epi32(sum0, sum1);

		_mm_storeu_si64(q, _mm_packus_epi16(sum0, sum0));
	}

	for (; x <= ne - 4; x += 4) {
		uint8_t *restrict p = (uint8_t *) pin + x;
		uint8_t *restrict q = (uint8_t *) pout + x;

		sum0 = initial;

		for (i = 0; i <= n - 2; i += 2) {
			/* Load two coeffs
			 */
			vc = _mm_set1_epi32(*(int32_t *) &c[i]);

			line8_hi = _mm_cvtsi32_si128(*(int32_t *) p);
			p += lskip;

			line8_lo = _mm_cvtsi32_si128(*(int32_t *) p);
			p += lskip;

			line16 = _mm_unpacklo_epi8(
				_mm_unpacklo_epi8(line8_hi, line8_lo), zero);
			sum0 = _mm_add_epi32(sum0, _mm_madd_epi16(line16, vc));
		}

		if (i < n) {
			vc = _mm_set1_epi16(c[i]);

			line8 = _mm_cvtsi32_si128(*(int32_t *) p);

			line16 = _mm_shuffle_epi8(line8, tbl0);
			sum0 = _mm_add_epi32(sum0, _mm_madd_epi16(line16, vc));
		}

		sum0 = _mm_srai_epi32(sum0, VIPS_INTERPOLATE_SHIFT);

		sum0 = _mm_packs_epi32(sum0, sum0);
		sum0 = _mm_packus_epi16(sum0, sum0);
		*(uint32_t *) q = _mm_cvtsi128_si32(sum0);
	}

	for (; x < ne; x++) {
		uint8_t *restrict p = (uint8_t *) pin + x;
		uint8_t *restrict q = (uint8_t *) pout + x;

		sum0 = initial;

		for (i = 0; i <= n - 2; i += 2) {
			/* Load two coeffs
			 */
			vc = _mm_set1_epi32(*(int32_t *) &c[i]);

			line16 = _mm_cvtsi32_si128(p[0] + (p[lskip] << 16));
			p += lskip * 2;

			sum0 = _mm_add_epi32(sum0, _mm_madd_epi16(line16, vc));
		}

		int32_t sum = _mm_cvtsi128_si32(sum0);

		if (i < n)
			sum += (int32_t) (*p) * c[i];

		*q = (uint8_t) (sum >> VIPS_INTERPOLATE_SHIFT);
	}
}

#endif /*HAVE_SSE*/
