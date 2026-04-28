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

    im = im.copy(interpretation="rgb16" if fmt == "ushort" else "srgb")
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
TRANSFER_LOG_100 = 9
TRANSFER_LOG_100_SQRT10 = 10
TRANSFER_IEC61966 = 11
TRANSFER_BT1361 = 12
TRANSFER_SRGB = 13
TRANSFER_BT2020_10BIT = 14
TRANSFER_BT2020_12BIT = 15
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

# Expected values computed from the ITU-T H.273 / BT.2100 spec formulas
# using double-precision Python.
# Format: (transfer_code, name, [(signal_8bit, expected_linear)], tolerance)
TRANSFER_CASES = [
    (TRANSFER_BT709, "BT.709", [
        (0, 0.0), (10, 0.008715), (20, 0.017429),
        (128, 0.261482), (255, 1.0),
    ], 0.001),
    (TRANSFER_BT601, "BT.601", [
        (0, 0.0), (10, 0.008715), (128, 0.261482), (255, 1.0),
    ], 0.001),
    (TRANSFER_BT2020_10BIT, "BT.2020 10-bit", [
        (0, 0.0), (128, 0.261482), (255, 1.0),
    ], 0.001),
    (TRANSFER_BT2020_12BIT, "BT.2020 12-bit", [
        (0, 0.0), (128, 0.261482), (255, 1.0),
    ], 0.001),
    (TRANSFER_SRGB, "sRGB", [
        (0, 0.0), (10, 0.003035), (11, 0.003347),
        (128, 0.215861), (255, 1.0),
    ], 0.001),
    (TRANSFER_PQ, "PQ", [
        (0, 0.0), (64, 0.065321), (128, 1.175932),
        (192, 12.628401), (255, 125.0),
    ], 0.01),
    (TRANSFER_HLG, "HLG", [
        (0, 0.0), (64, 0.121199), (127, 0.627765),
        (128, 0.639715), (192, 2.585478), (255, 12.5),
    ], 0.01),
    (TRANSFER_SMPTE240, "SMPTE 240M", [
        (0, 0.0), (10, 0.009804), (23, 0.022549),
        (128, 0.266928), (255, 1.0),
    ], 0.001),
    (TRANSFER_BT470M, "BT.470M gamma 2.2", [
        (0, 0.0), (64, 0.047776), (128, 0.219520), (255, 1.0),
    ], 0.001),
    (TRANSFER_BT470BG, "BT.470BG gamma 2.8", [
        (0, 0.0), (64, 0.020844), (128, 0.145170), (255, 1.0),
    ], 0.001),
    (TRANSFER_LINEAR, "Linear", [
        (0, 0.0), (64, 0.250980), (128, 0.501961), (255, 1.0),
    ], 0.0001),
    (TRANSFER_LOG_100, "Log 100", [
        (0, 0.0), (1, 0.010182), (128, 0.100907), (255, 1.0),
    ], 0.001),
    (TRANSFER_LOG_100_SQRT10, "Log 100*sqrt10", [
        (0, 0.0), (1, 0.003234), (128, 0.056872), (255, 1.0),
    ], 0.001),
    (TRANSFER_IEC61966, "IEC 61966-2-4", [
        (0, 0.0), (10, 0.008715), (128, 0.261482), (255, 1.0),
    ], 0.001),
    (TRANSFER_BT1361, "BT.1361", [
        (0, 0.0), (10, 0.008715), (128, 0.261482), (255, 1.0),
    ], 0.001),
    (TRANSFER_SMPTE428, "SMPTE 428", [
        (0, 0.0), (64, 0.017991), (128, 0.109077), (255, 0.654625),
    ], 0.001),
]

# Primaries tests with specific expected pixel values.
# Input is (200, 100, 50)/255 with linear transfer.
# Expected values computed from the matrices in CICP2scRGB.c.
PRIMARIES_MATRIX_CASES = [
    (PRIMARIES_BT709, "BT.709", (200/255, 100/255, 50/255), 0.0001),
    (PRIMARIES_BT2020, "BT.2020", (1.057614, 0.344951, 0.165680), 0.0001),
    (PRIMARIES_BT470M, "BT.470M", (0.991160, 0.368377, 0.171418), 0.001),
    (PRIMARIES_BT601, "BT.601", (0.758590, 0.395904, 0.194268), 0.001),
    (PRIMARIES_GENERIC_FILM, "Generic film", (0.921438, 0.377255, 0.171312), 0.001),
]

# Primaries with D65 white point should preserve grey.
PRIMARIES_GREY_CASES = [
    (PRIMARIES_DISPLAY_P3, "Display P3"),
    (PRIMARIES_BT470BG, "BT.470BG"),
    (PRIMARIES_EBU3213, "EBU 3213"),
]


@skip_if_no("CICP2scRGB")
class TestCICP:
    """Test CICP to scRGB conversion accuracy and colourspace routing."""

    # -- Transfer function accuracy tests --

    @pytest.mark.parametrize("transfer,name,cases,tolerance", TRANSFER_CASES,
                             ids=[c[1] for c in TRANSFER_CASES])
    def test_transfer(self, transfer, name, cases, tolerance):
        for val, expected in cases:
            im = make_cicp_image(val, val, val, transfer=transfer)
            actual = im.CICP2scRGB()(0, 0)[0]
            assert abs(actual - expected) < tolerance, \
                f"{name} at {val}/255: got {actual}, expected {expected}"

    def test_pq_peak(self):
        # PQ signal 1.0 must map to exactly 10000/80 = 125.0
        im = make_cicp_image(255, 255, 255, transfer=TRANSFER_PQ)
        pixel = im.CICP2scRGB()(0, 0)
        assert abs(pixel[0] - 125.0) < 0.5

    def test_hlg_boundary(self):
        # HLG transition at E' = 0.5 (signal 127.5/255) must be continuous.
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

    # -- Primaries conversion tests --

    @pytest.mark.parametrize("primaries,name,expected,tolerance",
                             PRIMARIES_MATRIX_CASES,
                             ids=[c[1] for c in PRIMARIES_MATRIX_CASES])
    def test_primaries_matrix(self, primaries, name, expected, tolerance):
        im = make_cicp_image(200, 100, 50, primaries=primaries,
                             transfer=TRANSFER_LINEAR)
        pixel = im.CICP2scRGB()(0, 0)
        for i, ch in enumerate("RGB"):
            assert abs(pixel[i] - expected[i]) < tolerance, \
                f"{name} {ch}: got {pixel[i]}, expected {expected[i]}"

    @pytest.mark.parametrize("primaries,name", PRIMARIES_GREY_CASES,
                             ids=[c[1] for c in PRIMARIES_GREY_CASES])
    def test_primaries_grey_preservation(self, primaries, name):
        im = make_cicp_image(128, 128, 128, primaries=primaries,
                             transfer=TRANSFER_LINEAR)
        pixel = im.CICP2scRGB()(0, 0)
        assert abs(pixel[0] - pixel[1]) < 0.001
        assert abs(pixel[1] - pixel[2]) < 0.001

    def test_smpte240_primaries_same_as_bt601(self):
        im601 = make_cicp_image(200, 100, 50, primaries=PRIMARIES_BT601,
                                transfer=TRANSFER_LINEAR)
        im240 = make_cicp_image(200, 100, 50, primaries=PRIMARIES_SMPTE240,
                                transfer=TRANSFER_LINEAR)
        p601 = im601.CICP2scRGB()(0, 0)
        p240 = im240.CICP2scRGB()(0, 0)
        for i in range(3):
            assert abs(p601[i] - p240[i]) < 0.0001

    # -- Format tests --

    def test_ushort_input(self):
        im8 = make_cicp_image(128, 128, 128, transfer=TRANSFER_BT709,
                              fmt="uchar")
        ushort_val = round(128 / 255.0 * 65535)
        im16 = make_cicp_image(ushort_val, ushort_val, ushort_val,
                               transfer=TRANSFER_BT709, fmt="ushort")
        pixel8 = im8.CICP2scRGB()(0, 0)[0]
        pixel16 = im16.CICP2scRGB()(0, 0)[0]
        assert abs(pixel8 - pixel16) < 0.001

    def test_output_format(self):
        im = make_cicp_image(128, 128, 128)
        result = im.CICP2scRGB()
        assert result.format == "float"
        assert result.interpretation == "scrgb"
        assert result.bands == 3

    # -- JXL round-trip tests --

    @skip_if_no("jxlsave")
    def test_jxl_srgb_not_tagged_cicp(self):
        im = (pyvips.Image.black(64, 64, bands=3) + [128, 100, 80]) \
            .cast("uchar").copy(interpretation="srgb")
        buf = im.jxlsave_buffer()
        out = pyvips.Image.new_from_buffer(buf, "")
        assert out.interpretation == "srgb"

    @skip_if_no("jxlsave")
    def test_jxl_cicp_pixel_preservation(self):
        im = make_cicp_image(100, 100, 100,
                             primaries=PRIMARIES_DISPLAY_P3,
                             transfer=TRANSFER_PQ)
        buf = im.jxlsave_buffer()
        out = pyvips.Image.new_from_buffer(buf, "")
        pixel = out(0, 0)
        assert pixel[0] < 200, \
            f"pixel value {pixel[0]} suggests sRGB conversion"
        assert out.get_typeof("cicp-transfer-characteristics") != 0

    @skip_if_no("jxlsave")
    def test_jxl_cicp_ushort_preserved(self):
        im = make_cicp_image(30000, 20000, 10000,
                             primaries=PRIMARIES_DISPLAY_P3,
                             transfer=TRANSFER_PQ, fmt="ushort")
        buf = im.jxlsave_buffer()
        out = pyvips.Image.new_from_buffer(buf, "")
        assert out.format == "ushort"

    @skip_if_no("jxlsave")
    @pytest.mark.parametrize("transfer,name", [
        (TRANSFER_BT470M, "BT.470M"),
        (TRANSFER_BT470BG, "BT.470BG"),
    ])
    def test_jxl_gamma_roundtrip(self, transfer, name):
        im = make_cicp_image(128, 128, 128,
                             primaries=PRIMARIES_BT709,
                             transfer=transfer)
        buf = im.jxlsave_buffer()
        out = pyvips.Image.new_from_buffer(buf, "")
        assert out.get("cicp-transfer-characteristics") == transfer, \
            f"{name} transfer lost in JXL round-trip"

    @skip_if_no("jxlsave")
    def test_jxl_hdr_cicp_over_icc(self):
        """HDR CICP encoding must be used over ICC on save, since ICC
        cannot describe PQ or HLG transfer functions."""
        srgb = (pyvips.Image.black(64, 64, bands=3) + 128).cast("uchar")
        srgb = srgb.copy(interpretation="srgb")
        with_icc = srgb.colourspace("lab").icc_export(output_profile="sRGB")
        icc_profile = with_icc.get("icc-profile-data")

        im = make_cicp_image(128, 128, 128,
                             primaries=PRIMARIES_BT2020,
                             transfer=TRANSFER_PQ)
        im.set_type(pyvips.GValue.blob_type,
                     "icc-profile-data", icc_profile)

        buf = im.jxlsave_buffer()
        out = pyvips.Image.new_from_buffer(buf, "")

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

    @skip_if_no("jxlsave")
    @pytest.mark.parametrize("primaries,name", [
        (PRIMARIES_BT470M, "BT.470M"),
        (PRIMARIES_BT470BG, "BT.470BG"),
        (PRIMARIES_BT601, "BT.601"),
        (PRIMARIES_GENERIC_FILM, "GenericFilm"),
        (PRIMARIES_EBU3213, "EBU3213"),
        (PRIMARIES_DCI_P3, "DCI-P3"),
        (PRIMARIES_DISPLAY_P3, "Display P3"),
    ])
    def test_jxl_custom_primaries_roundtrip(self, primaries, name):
        """Custom primaries must survive a JXL save/load roundtrip."""
        im = make_cicp_image(128, 128, 128,
                             primaries=primaries,
                             transfer=TRANSFER_SRGB)
        buf = im.jxlsave_buffer()
        out = pyvips.Image.new_from_buffer(buf, "")
        assert out.get_typeof("cicp-colour-primaries") != 0, \
            f"{name}: expected cicp metadata"
        assert out.get("cicp-colour-primaries") == primaries, \
            f"{name}: primaries {out.get('cicp-colour-primaries')} != {primaries}"

    # -- HEIF/AVIF regression tests --

    @skip_if_no("heifsave")
    def test_heif_cicp_identity_matrix_saves(self):
        im = make_cicp_image(128, 100, 80,
                             primaries=PRIMARIES_DISPLAY_P3,
                             transfer=TRANSFER_PQ)
        buf = im.heifsave_buffer(compression="av1")
        assert len(buf) > 0

    @skip_if_no("heifsave")
    def test_heif_cicp_ushort_pixel_roundtrip(self):
        r, g, b = 37888, 22272, 12544
        im = make_cicp_image(r, g, b,
                             primaries=PRIMARIES_DISPLAY_P3,
                             transfer=TRANSFER_PQ, fmt="ushort")
        im.set_type(pyvips.GValue.gint_type, "bits-per-sample", 12)
        buf = im.heifsave_buffer(compression="av1")
        out = pyvips.Image.new_from_buffer(buf, "")
        pixel = out(0, 0)
        assert pixel[0] > 10000, f"R channel {pixel[0]} near zero"
        assert pixel[1] > 5000, f"G channel {pixel[1]} near zero"
        assert pixel[2] > 3000, f"B channel {pixel[2]} near zero"

    @skip_if_no("heifsave")
    def test_heif_cicp_bitdepth_from_metadata(self):
        im = make_cicp_image(30000, 20000, 10000,
                             primaries=PRIMARIES_DISPLAY_P3,
                             transfer=TRANSFER_PQ, fmt="ushort")
        im.set_type(pyvips.GValue.gint_type, "bits-per-sample", 12)
        buf = im.heifsave_buffer(compression="av1")
        out = pyvips.Image.new_from_buffer(buf, "")
        assert out.format == "ushort"
        assert out.get("bits-per-sample") == 12

    @skip_if_no("heifsave")
    def test_heif_cicp_nclx_metadata_roundtrip(self):
        im = make_cicp_image(128, 128, 128,
                             primaries=PRIMARIES_DISPLAY_P3,
                             transfer=TRANSFER_PQ)
        buf = im.heifsave_buffer(compression="av1")
        out = pyvips.Image.new_from_buffer(buf, "")
        assert out.get("cicp-colour-primaries") == PRIMARIES_DISPLAY_P3
        assert out.get("cicp-transfer-characteristics") == TRANSFER_PQ
        assert out.get("cicp-matrix-coefficients") == 0
        assert out.get("cicp-full-range-flag") == 1

    @skip_if_no("heifsave")
    def test_heif_cicp_matrix_coefficients_preserved(self):
        im = make_cicp_image(128, 128, 128,
                             primaries=PRIMARIES_DISPLAY_P3,
                             transfer=TRANSFER_PQ, mc=6)
        buf = im.heifsave_buffer(compression="av1")
        out = pyvips.Image.new_from_buffer(buf, "")
        assert out.get("cicp-matrix-coefficients") == 6

    @skip_if_no("heifsave")
    def test_heif_hdr_nclx_with_icc(self):
        """HDR NCLX metadata must be extracted even when an ICC profile
        is also present, since ICC cannot describe PQ or HLG."""
        srgb = (pyvips.Image.black(64, 64, bands=3) + 128).cast("uchar")
        srgb = srgb.copy(interpretation="srgb")
        with_icc = srgb.colourspace("lab").icc_export(output_profile="sRGB")
        icc_profile = with_icc.get("icc-profile-data")

        im = make_cicp_image(128, 128, 128,
                             primaries=PRIMARIES_BT2020,
                             transfer=TRANSFER_PQ)
        im.set_type(pyvips.GValue.blob_type,
                     "icc-profile-data", icc_profile)

        buf = im.heifsave_buffer(compression="av1")
        out = pyvips.Image.new_from_buffer(buf, "")

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
        # cICP chunk requires libpng >= 1.6.45
        if out.get_typeof("cicp-colour-primaries"):
            assert out.get("cicp-colour-primaries") == PRIMARIES_DISPLAY_P3
            assert out.get("cicp-transfer-characteristics") == TRANSFER_PQ

