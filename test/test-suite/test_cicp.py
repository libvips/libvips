# vim: set fileencoding=utf-8 :

import pytest

import pyvips
from helpers import *


def make_cicp_image(r, g, b, primaries=1, transfer=1, mc=0, fmt="uchar"):
    """Create a 1x1 CICP-tagged image with given pixel values."""

    if fmt == "uchar":
        im = (pyvips.Image.black(1, 1, bands=3) + [r, g, b]).cast("uchar")
    elif fmt == "ushort":
        im = (pyvips.Image.black(1, 1, bands=3) + [r, g, b]).cast("ushort")
    else:
        raise ValueError(f"unsupported format: {fmt}")

    im = im.copy(interpretation="cicp")
    im.set_type(pyvips.GValue.gint_type, "cicp-colour-primaries", primaries)
    im.set_type(
        pyvips.GValue.gint_type, "cicp-transfer-characteristics", transfer
    )
    im.set_type(pyvips.GValue.gint_type, "cicp-matrix-coefficients", mc)
    im.set_type(pyvips.GValue.gint_type, "cicp-full-range-flag", 1)

    return im


# CICP transfer characteristic codes
TRANSFER_BT709 = 1
TRANSFER_BT470M = 4
TRANSFER_BT470BG = 5
TRANSFER_BT601 = 6
TRANSFER_SMPTE240 = 7
TRANSFER_LINEAR = 8
TRANSFER_SRGB = 13
TRANSFER_BT2020_10BIT = 14
TRANSFER_BT2020_12BIT = 15
TRANSFER_LOG_100 = 9
TRANSFER_LOG_100_SQRT10 = 10
TRANSFER_IEC61966 = 11
TRANSFER_BT1361 = 12
TRANSFER_PQ = 16
TRANSFER_SMPTE428 = 17
TRANSFER_HLG = 18

# CICP colour primaries codes
PRIMARIES_BT709 = 1
PRIMARIES_BT470M = 4
PRIMARIES_BT470BG = 5
PRIMARIES_BT601 = 6
PRIMARIES_SMPTE240 = 7
PRIMARIES_GENERIC_FILM = 8
PRIMARIES_BT2020 = 9
PRIMARIES_DCI_P3 = 11
PRIMARIES_DISPLAY_P3 = 12
PRIMARIES_EBU3213 = 22


@skip_if_no("CICP2scRGB")
class TestCICP:
    """Test CICP to scRGB conversion accuracy and colourspace routing."""

    # -- Transfer function accuracy tests --
    #
    # Expected values computed from the ITU-T H.273 / BT.2100 spec formulas
    # using double-precision Python.  Each test case is (signal_8bit, expected).

    def _check(self, transfer, cases, tolerance=0.001):
        for val, expected in cases:
            im = make_cicp_image(val, val, val, transfer=transfer)
            actual = im.CICP2scRGB()(0, 0)[0]
            assert abs(actual - expected) < tolerance, \
                f"transfer {transfer} at {val}/255: " \
                f"got {actual}, expected {expected}"

    def test_bt709_transfer(self):
        # BT.709: alpha=1.099297, signal_beta=4.5*0.018054, gamma=1/0.45
        self._check(TRANSFER_BT709, [
            (0, 0.0),
            (10, 0.008715),   # below threshold (linear segment)
            (20, 0.017429),   # below threshold
            (128, 0.261482),  # power segment
            (255, 1.0),
        ])

    def test_bt601_transfer(self):
        # BT.601 uses the same curve as BT.709
        self._check(TRANSFER_BT601, [
            (0, 0.0),
            (10, 0.008715),
            (128, 0.261482),
            (255, 1.0),
        ])

    def test_bt2020_10bit_transfer(self):
        self._check(TRANSFER_BT2020_10BIT, [
            (0, 0.0),
            (128, 0.261482),
            (255, 1.0),
        ])

    def test_bt2020_12bit_transfer(self):
        self._check(TRANSFER_BT2020_12BIT, [
            (0, 0.0),
            (128, 0.261482),
            (255, 1.0),
        ])

    def test_srgb_transfer(self):
        # IEC 61966-2-1: threshold 0.04045, exponent 2.4
        self._check(TRANSFER_SRGB, [
            (0, 0.0),
            (10, 0.003035),   # below threshold (linear segment)
            (11, 0.003347),   # just above threshold (power segment)
            (128, 0.215861),
            (255, 1.0),
        ])

    def test_pq_transfer(self):
        # BT.2100 PQ EOTF, output in scRGB units (1.0 = 80 nits)
        self._check(TRANSFER_PQ, [
            (0, 0.0),
            (64, 0.065321),
            (128, 1.175932),
            (192, 12.628401),
            (255, 125.0),     # 10000/80 nits
        ], tolerance=0.01)

    def test_pq_peak(self):
        # PQ signal 1.0 must map to exactly 10000/80 = 125.0
        im = make_cicp_image(255, 255, 255, transfer=TRANSFER_PQ)
        pixel = im.CICP2scRGB()(0, 0)
        assert abs(pixel[0] - 125.0) < 0.5

    def test_hlg_transfer(self):
        # BT.2100 Table 5 HLG: inverse OETF + OOTF (1000-nit reference).
        # Output is display-referred scRGB (1.0 = 80 nits).
        # For grey pixels: result = (1000/80) * InvOETF(v/255)^1.2
        self._check(TRANSFER_HLG, [
            (0, 0.0),
            (64, 0.121199),   # quadratic segment (E' <= 0.5)
            (127, 0.627765),  # just below transition
            (128, 0.639715),  # just above transition (exponential segment)
            (192, 2.585478),
            (255, 12.5),      # 1000/80 nits
        ], tolerance=0.01)

    def test_hlg_boundary(self):
        # HLG transition at E' = 0.5 (signal 127.5/255) must be continuous.
        # With OOTF applied, values are larger but the gap stays small.
        im_lo = make_cicp_image(127, 127, 127, transfer=TRANSFER_HLG)
        im_hi = make_cicp_image(128, 128, 128, transfer=TRANSFER_HLG)
        lo = im_lo.CICP2scRGB()(0, 0)[0]
        hi = im_hi.CICP2scRGB()(0, 0)[0]
        assert abs(hi - lo) < 0.02
        assert abs(lo - 0.627765) < 0.01
        assert abs(hi - 0.639715) < 0.01

    def test_hlg_peak(self):
        # HLG signal 1.0 must map to 1000/80 = 12.5 (1000-nit peak)
        im = make_cicp_image(255, 255, 255, transfer=TRANSFER_HLG)
        pixel = im.CICP2scRGB()(0, 0)
        assert abs(pixel[0] - 12.5) < 0.1

    def test_smpte240_transfer(self):
        # SMPTE 240M: alpha=1.1115, beta=0.0228, slope=4.0
        self._check(TRANSFER_SMPTE240, [
            (0, 0.0),
            (10, 0.009804),   # below threshold
            (23, 0.022549),   # just below threshold
            (128, 0.266928),
            (255, 1.0),
        ])

    def test_bt470m_gamma22(self):
        # Pure gamma 2.2
        self._check(TRANSFER_BT470M, [
            (0, 0.0),
            (64, 0.047776),
            (128, 0.219520),
            (255, 1.0),
        ])

    def test_bt470bg_gamma28(self):
        # Pure gamma 2.8
        self._check(TRANSFER_BT470BG, [
            (0, 0.0),
            (64, 0.020844),
            (128, 0.145170),
            (255, 1.0),
        ])

    def test_linear_transfer(self):
        # Linear: output = input / 255
        self._check(TRANSFER_LINEAR, [
            (0, 0.0),
            (64, 0.250980),
            (128, 0.501961),
            (255, 1.0),
        ], tolerance=0.0001)

    def test_log_100_transfer(self):
        # Logarithmic 100:1 range: Lc = 10^(2*(V-1))
        self._check(TRANSFER_LOG_100, [
            (0, 0.0),
            (1, 0.010182),
            (128, 0.100907),
            (255, 1.0),
        ])

    def test_log_100_sqrt10_transfer(self):
        # Logarithmic 100*sqrt(10):1 range: Lc = 10^(2.5*(V-1))
        self._check(TRANSFER_LOG_100_SQRT10, [
            (0, 0.0),
            (1, 0.003234),
            (128, 0.056872),
            (255, 1.0),
        ])

    def test_iec61966_transfer(self):
        # IEC 61966-2-4 (xvYCC): BT.709 curve with negative value support.
        # For positive 8-bit values, identical to BT.709.
        self._check(TRANSFER_IEC61966, [
            (0, 0.0),
            (10, 0.008715),
            (128, 0.261482),
            (255, 1.0),
        ])

    def test_bt1361_transfer(self):
        # BT.1361: same curve as IEC 61966-2-4
        self._check(TRANSFER_BT1361, [
            (0, 0.0),
            (10, 0.008715),
            (128, 0.261482),
            (255, 1.0),
        ])

    def test_smpte428_transfer(self):
        # SMPTE 428-1: V = (48*Lo/52.37)^(1/2.6)
        # Inverse: Lo = (52.37/48)*V^2.6, scaled by 48/80 for scRGB
        self._check(TRANSFER_SMPTE428, [
            (0, 0.0),
            (64, 0.017991),
            (128, 0.109077),
            (255, 0.654625),
        ])

    # -- Primaries conversion tests --

    def test_bt709_primaries_identity(self):
        # BT.709 primaries with linear transfer: identity matrix,
        # output = normalized input
        im = make_cicp_image(200, 100, 50, primaries=PRIMARIES_BT709,
                             transfer=TRANSFER_LINEAR)
        pixel = im.CICP2scRGB()(0, 0)
        assert abs(pixel[0] - 200/255) < 0.0001
        assert abs(pixel[1] - 100/255) < 0.0001
        assert abs(pixel[2] - 50/255) < 0.0001

    def test_bt2020_primaries_matrix(self):
        # BT.2020 -> BT.709 matrix applied to (200, 100, 50)/255 with
        # linear transfer.  Expected values computed from the matrix in
        # CICP2scRGB.c.
        im = make_cicp_image(200, 100, 50, primaries=PRIMARIES_BT2020,
                             transfer=TRANSFER_LINEAR)
        pixel = im.CICP2scRGB()(0, 0)
        assert abs(pixel[0] - 1.057614) < 0.0001
        assert abs(pixel[1] - 0.344951) < 0.0001
        assert abs(pixel[2] - 0.165680) < 0.0001

    def test_display_p3_primaries_grey(self):
        # For a grey pixel (equal R=G=B), primaries conversion should
        # preserve greyness since white point is the same (D65)
        im = make_cicp_image(128, 128, 128,
                             primaries=PRIMARIES_DISPLAY_P3,
                             transfer=TRANSFER_LINEAR)
        pixel = im.CICP2scRGB()(0, 0)
        # All channels should be very close to each other
        assert abs(pixel[0] - pixel[1]) < 0.001
        assert abs(pixel[1] - pixel[2]) < 0.001

    def test_bt470m_primaries_matrix(self):
        # BT.470M -> BT.709 with Bradford adaptation (Illuminant C -> D65)
        im = make_cicp_image(200, 100, 50, primaries=PRIMARIES_BT470M,
                             transfer=TRANSFER_LINEAR)
        pixel = im.CICP2scRGB()(0, 0)
        assert abs(pixel[0] - 0.991160) < 0.001
        assert abs(pixel[1] - 0.368377) < 0.001
        assert abs(pixel[2] - 0.171418) < 0.001

    def test_bt470bg_primaries_grey(self):
        # BT.470BG (D65 white) should preserve grey
        im = make_cicp_image(128, 128, 128,
                             primaries=PRIMARIES_BT470BG,
                             transfer=TRANSFER_LINEAR)
        pixel = im.CICP2scRGB()(0, 0)
        assert abs(pixel[0] - pixel[1]) < 0.001
        assert abs(pixel[1] - pixel[2]) < 0.001

    def test_bt601_primaries_matrix(self):
        # BT.601 -> BT.709
        im = make_cicp_image(200, 100, 50, primaries=PRIMARIES_BT601,
                             transfer=TRANSFER_LINEAR)
        pixel = im.CICP2scRGB()(0, 0)
        assert abs(pixel[0] - 0.758590) < 0.001
        assert abs(pixel[1] - 0.395904) < 0.001
        assert abs(pixel[2] - 0.194268) < 0.001

    def test_smpte240_primaries_same_as_bt601(self):
        # SMPTE 240M shares primaries with BT.601
        im601 = make_cicp_image(200, 100, 50, primaries=PRIMARIES_BT601,
                                transfer=TRANSFER_LINEAR)
        im240 = make_cicp_image(200, 100, 50, primaries=PRIMARIES_SMPTE240,
                                transfer=TRANSFER_LINEAR)
        p601 = im601.CICP2scRGB()(0, 0)
        p240 = im240.CICP2scRGB()(0, 0)
        assert abs(p601[0] - p240[0]) < 0.0001
        assert abs(p601[1] - p240[1]) < 0.0001
        assert abs(p601[2] - p240[2]) < 0.0001

    def test_generic_film_primaries_matrix(self):
        # Generic film -> BT.709 with Bradford adaptation (Illuminant C -> D65)
        im = make_cicp_image(200, 100, 50,
                             primaries=PRIMARIES_GENERIC_FILM,
                             transfer=TRANSFER_LINEAR)
        pixel = im.CICP2scRGB()(0, 0)
        assert abs(pixel[0] - 0.921438) < 0.001
        assert abs(pixel[1] - 0.377255) < 0.001
        assert abs(pixel[2] - 0.171312) < 0.001

    def test_ebu3213_primaries_grey(self):
        # EBU 3213 (D65 white) should preserve grey
        im = make_cicp_image(128, 128, 128,
                             primaries=PRIMARIES_EBU3213,
                             transfer=TRANSFER_LINEAR)
        pixel = im.CICP2scRGB()(0, 0)
        assert abs(pixel[0] - pixel[1]) < 0.001
        assert abs(pixel[1] - pixel[2]) < 0.001

    # -- Format tests --

    def test_ushort_input(self):
        # 16-bit input should produce consistent results with 8-bit
        # for the same normalized signal
        im8 = make_cicp_image(128, 128, 128, transfer=TRANSFER_BT709,
                              fmt="uchar")
        # 128/255 ~ 32896/65535 (closest ushort equivalent)
        ushort_val = round(128 / 255.0 * 65535)
        im16 = make_cicp_image(ushort_val, ushort_val, ushort_val,
                               transfer=TRANSFER_BT709, fmt="ushort")
        pixel8 = im8.CICP2scRGB()(0, 0)[0]
        pixel16 = im16.CICP2scRGB()(0, 0)[0]
        assert abs(pixel8 - pixel16) < 0.001

    def test_output_format(self):
        # Output should always be float scRGB
        im = make_cicp_image(128, 128, 128)
        result = im.CICP2scRGB()
        assert result.format == "float"
        assert result.interpretation == "scrgb"
        assert result.bands == 3

    # -- Colourspace routing tests --

    def test_cicp_to_all_colourspaces(self):
        # Verify CICP can convert to every supported colour space
        im = make_cicp_image(128, 100, 80)
        target_spaces = [
            "xyz", "lab", "lch", "cmc", "labs", "scrgb", "hsv",
            "srgb", "yxy", "b-w", "rgb16", "grey16", "oklab", "oklch",
            "cmyk",
        ]
        for space in target_spaces:
            out = im.colourspace(space)
            assert out.interpretation == space, \
                f"CICP->{space} interpretation mismatch"

    def test_cicp_to_cicp_identity(self):
        # CICP -> CICP should preserve pixel values exactly
        im = make_cicp_image(200, 100, 50)
        out = im.colourspace("cicp")
        pixel = out(0, 0)
        assert pixel[0] == 200
        assert pixel[1] == 100
        assert pixel[2] == 50

    def test_cicp_to_srgb_bt709(self):
        # BT.709 128/255 -> linear 0.261482 -> sRGB OETF -> 8-bit 140
        im = make_cicp_image(128, 128, 128, transfer=TRANSFER_BT709)
        srgb = im.colourspace("srgb")
        pixel = srgb(0, 0)
        assert abs(pixel[0] - 140) < 2
        assert abs(pixel[1] - 140) < 2
        assert abs(pixel[2] - 140) < 2

    def test_cicp_to_lab_roundtrip(self):
        # CICP -> Lab -> scRGB should match direct CICP -> scRGB
        im = make_cicp_image(180, 120, 80)
        direct = im.colourspace("scrgb")
        via_lab = im.colourspace("lab").colourspace("scrgb")
        d = direct(0, 0)
        v = via_lab(0, 0)
        # Lab round-trip has limited precision
        assert abs(d[0] - v[0]) < 0.01
        assert abs(d[1] - v[1]) < 0.01
        assert abs(d[2] - v[2]) < 0.01

    @skip_if_no("jxlsave")
    def test_jxl_srgb_not_tagged_cicp(self):
        im = (pyvips.Image.black(64, 64, bands=3) + [128, 100, 80]) \
            .cast("uchar").copy(interpretation="srgb")
        buf = im.jxlsave_buffer()
        out = pyvips.Image.new_from_buffer(buf, "")
        assert out.interpretation == "srgb", \
            f"sRGB JXL loaded as {out.interpretation}, expected srgb"

    @skip_if_no("jxlsave")
    def test_jxl_cicp_pixel_preservation(self):
        im = make_cicp_image(100, 100, 100,
                             primaries=PRIMARIES_DISPLAY_P3,
                             transfer=TRANSFER_PQ)
        buf = im.jxlsave_buffer()
        out = pyvips.Image.new_from_buffer(buf, "")
        pixel = out(0, 0)
        # The value should be near the input, not clipped to 255
        # (100 is well within 0-255 so lossy JXL should stay close)
        assert pixel[0] < 200, \
            f"pixel value {pixel[0]} suggests sRGB conversion (expected ~100)"
        assert out.interpretation == "cicp"

    @skip_if_no("jxlsave")
    def test_jxl_cicp_ushort_preserved(self):
        im = make_cicp_image(30000, 20000, 10000,
                             primaries=PRIMARIES_DISPLAY_P3,
                             transfer=TRANSFER_PQ, fmt="ushort")
        buf = im.jxlsave_buffer()
        out = pyvips.Image.new_from_buffer(buf, "")
        assert out.format == "ushort", \
            f"JXL output is {out.format}, expected ushort"

    @skip_if_no("jxlsave")
    def test_jxl_gamma_roundtrip(self):
        # libjxl stores gamma as the OETF exponent (1/display_gamma).
        # Verify BT.470M (gamma 2.2) and BT.470BG (gamma 2.8) survive
        # a JXL save/load round-trip.
        for transfer, name in [
            (TRANSFER_BT470M, "BT.470M"),
            (TRANSFER_BT470BG, "BT.470BG"),
        ]:
            im = make_cicp_image(128, 128, 128,
                                 primaries=PRIMARIES_BT709,
                                 transfer=transfer)
            buf = im.jxlsave_buffer()
            out = pyvips.Image.new_from_buffer(buf, "")
            assert out.get("cicp-transfer-characteristics") == transfer, \
                f"{name} transfer lost in JXL round-trip: " \
                f"got {out.get('cicp-transfer-characteristics')}, expected {transfer}"

    @skip_if_no("jxlsave")
    def test_jxl_hdr_cicp_over_icc(self):
        """HDR CICP encoding must be used over ICC on save, since ICC
        cannot describe PQ or HLG transfer functions."""
        # Get a valid ICC profile
        srgb = (pyvips.Image.black(64, 64, bands=3) + 128).cast("uchar")
        srgb = srgb.copy(interpretation="srgb")
        with_icc = srgb.colourspace("lab").icc_export(output_profile="sRGB")
        icc_profile = with_icc.get("icc-profile-data")

        # Create a CICP HDR image and attach the ICC profile
        im = make_cicp_image(128, 128, 128,
                             primaries=PRIMARIES_BT2020,
                             transfer=TRANSFER_PQ)
        im.set_type(pyvips.GValue.blob_type,
                     "icc-profile-data", icc_profile)

        buf = im.jxlsave_buffer()
        out = pyvips.Image.new_from_buffer(buf, "")

        # The structured CICP encoding must survive, not the ICC profile
        assert out.interpretation == "cicp", \
            f"HDR JXL with ICC loaded as {out.interpretation}, expected cicp"
        assert out.get("cicp-transfer-characteristics") == TRANSFER_PQ
        assert out.get("cicp-colour-primaries") == PRIMARIES_BT2020

    @skip_if_no("jxlsave")
    def test_jxl_cicp_metadata_roundtrip(self):
        im = make_cicp_image(128, 128, 128,
                             primaries=PRIMARIES_BT2020,
                             transfer=TRANSFER_HLG)
        buf = im.jxlsave_buffer()
        out = pyvips.Image.new_from_buffer(buf, "")
        assert out.get("cicp-colour-primaries") == PRIMARIES_BT2020
        assert out.get("cicp-transfer-characteristics") == TRANSFER_HLG
        assert out.get("cicp-matrix-coefficients") == 0

    # -- HEIF/AVIF regression tests --

    @skip_if_no("heifsave")
    def test_heif_cicp_identity_matrix_saves(self):
        im = make_cicp_image(128, 100, 80,
                             primaries=PRIMARIES_DISPLAY_P3,
                             transfer=TRANSFER_PQ)
        # This should not raise -- previously failed with:
        # "Subsampling must be 0 with AOM_CICP_MC_IDENTITY"
        buf = im.heifsave_buffer()
        assert len(buf) > 0

    @skip_if_no("heifsave")
    def test_heif_cicp_ushort_pixel_roundtrip(self):
        # Use values representative of 10-bit PQ content in full
        # 16-bit range (~37000, ~22000 are typical after loader shift)
        r, g, b = 37888, 22272, 12544
        im = make_cicp_image(r, g, b,
                             primaries=PRIMARIES_DISPLAY_P3,
                             transfer=TRANSFER_PQ, fmt="ushort")
        im.set_type(pyvips.GValue.gint_type, "bits-per-sample", 10)
        buf = im.heifsave_buffer()
        out = pyvips.Image.new_from_buffer(buf, "")
        pixel = out(0, 0)
        # After lossy AVIF compression the values won't be exact, but
        # they should be in the right ballpark -- definitely not zero.
        assert pixel[0] > 10000, \
            f"R channel {pixel[0]} is near zero (data corruption)"
        assert pixel[1] > 5000, \
            f"G channel {pixel[1]} is near zero (data corruption)"
        assert pixel[2] > 3000, \
            f"B channel {pixel[2]} is near zero (data corruption)"

    @skip_if_no("heifsave")
    def test_heif_cicp_bitdepth_from_metadata(self):
        im = make_cicp_image(30000, 20000, 10000,
                             primaries=PRIMARIES_DISPLAY_P3,
                             transfer=TRANSFER_PQ, fmt="ushort")
        im.set_type(pyvips.GValue.gint_type, "bits-per-sample", 10)
        buf = im.heifsave_buffer()
        out = pyvips.Image.new_from_buffer(buf, "")
        assert out.format == "ushort", \
            f"HEIF output is {out.format}, expected ushort (10-bit)"
        assert out.get("bits-per-sample") == 10

    @skip_if_no("heifsave")
    def test_heif_cicp_nclx_metadata_roundtrip(self):
        im = make_cicp_image(128, 128, 128,
                             primaries=PRIMARIES_DISPLAY_P3,
                             transfer=TRANSFER_PQ)
        buf = im.heifsave_buffer()
        out = pyvips.Image.new_from_buffer(buf, "")
        assert out.interpretation == "cicp"
        assert out.get("cicp-colour-primaries") == PRIMARIES_DISPLAY_P3
        assert out.get("cicp-transfer-characteristics") == TRANSFER_PQ
        assert out.get("cicp-matrix-coefficients") == 0
        assert out.get("cicp-full-range-flag") == 1

    @skip_if_no("heifsave")
    def test_heif_cicp_matrix_coefficients_preserved(self):
        """
        Non-zero matrix_coefficients (e.g. MC=6 BT.601) must survive an AVIF
        round-trip. Hardcoding matrix_coefficients=0 led to the encoder using
        GBR instead of YCbCr, doubling file size and slightly shifting colors.
        """
        im = make_cicp_image(128, 128, 128,
                             primaries=PRIMARIES_DISPLAY_P3,
                             transfer=TRANSFER_PQ, mc=6)
        buf = im.heifsave_buffer()
        out = pyvips.Image.new_from_buffer(buf, "")
        assert out.get("cicp-matrix-coefficients") == 6, \
            f"MC={out.get('cicp-matrix-coefficients')}, expected 6 (BT.601)"

    @skip_if_no("heifsave")
    def test_heif_hdr_nclx_with_icc(self):
        """HDR NCLX metadata must be extracted even when an ICC profile
        is also present, since ICC cannot describe PQ or HLG."""
        # Get a valid ICC profile via icc_export
        srgb = (pyvips.Image.black(64, 64, bands=3) + 128).cast("uchar")
        srgb = srgb.copy(interpretation="srgb")
        with_icc = srgb.colourspace("lab").icc_export(output_profile="sRGB")
        icc_profile = with_icc.get("icc-profile-data")

        # Create a CICP HDR image and attach the ICC profile
        im = make_cicp_image(128, 128, 128,
                             primaries=PRIMARIES_BT2020,
                             transfer=TRANSFER_PQ)
        im.set_type(pyvips.GValue.blob_type,
                     "icc-profile-data", icc_profile)

        buf = im.heifsave_buffer()
        out = pyvips.Image.new_from_buffer(buf, "")

        # The loader must use CICP despite ICC being present
        assert out.interpretation == "cicp", \
            f"HDR HEIF with ICC loaded as {out.interpretation}, expected cicp"
        assert out.get("cicp-transfer-characteristics") == TRANSFER_PQ
        assert out.get("cicp-colour-primaries") == PRIMARIES_BT2020

    # -- PNG regression tests --

    @skip_if_no("pngsave")
    def test_png_cicp_lossless_roundtrip(self):
        im = make_cicp_image(37888, 22272, 12544,
                             primaries=PRIMARIES_DISPLAY_P3,
                             transfer=TRANSFER_PQ, fmt="ushort")
        buf = im.pngsave_buffer()
        out = pyvips.Image.new_from_buffer(buf, "")
        pixel = out(0, 0)
        assert pixel[0] == 37888
        assert pixel[1] == 22272
        assert pixel[2] == 12544
        assert out.get("cicp-colour-primaries") == PRIMARIES_DISPLAY_P3
        assert out.get("cicp-transfer-characteristics") == TRANSFER_PQ
