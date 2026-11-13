# vim: set fileencoding=utf-8 :

import pytest

import pyvips
from helpers import *

# CICP transfer characteristic codes
TRANSFER_BT709 = 1
TRANSFER_UNSPECIFIED = 2
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
PRIMARIES_UNSPECIFIED = 2
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
        (0, 0.0), (64, 0.025742), (128, 0.463424),
        (192, 4.976661), (255, 49.261086),
    ], 0.004),
    (TRANSFER_HLG, "HLG", [
        (0, 0.0), (64, 0.047763), (127, 0.247395),
        (128, 0.252104), (192, 1.018908), (255, 4.926109),
    ], 0.004),
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
        (0, 0.0), (64, 0.029985), (128, 0.181795), (255, 1.091042),
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
        # PQ signal 1.0 is 10000 nits, with reference white (203 nits) at 1.0
        im = make_cicp_image(255, 255, 255, transfer=TRANSFER_PQ)
        pixel = im.CICP2scRGB()(0, 0)
        assert abs(pixel[0] - 10000 / 203) < 0.2

    def test_hlg_boundary(self):
        # HLG transition at E' = 0.5 (signal 127.5/255) must be continuous.
        im_lo = make_cicp_image(127, 127, 127, transfer=TRANSFER_HLG)
        im_hi = make_cicp_image(128, 128, 128, transfer=TRANSFER_HLG)
        lo = im_lo.CICP2scRGB()(0, 0)[0]
        hi = im_hi.CICP2scRGB()(0, 0)[0]
        assert abs(hi - lo) < 0.008
        assert abs(lo - 0.247395) < 0.004
        assert abs(hi - 0.252104) < 0.004

    def test_hlg_peak(self):
        # HLG signal 1.0 is the 1000-nit peak, with reference white at 1.0
        im = make_cicp_image(255, 255, 255, transfer=TRANSFER_HLG)
        pixel = im.CICP2scRGB()(0, 0)
        assert abs(pixel[0] - 1000 / 203) < 0.05

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

    def test_CICP2scRGB_keeps_cicp_clli_metadata(self):
        im = make_cicp_image(128, 128, 128,
                             primaries=PRIMARIES_BT2020,
                             transfer=TRANSFER_PQ)
        add_clli(im)
        result = im.CICP2scRGB()
        assert result.get("cicp-colour-primaries") == PRIMARIES_BT2020
        assert result.get("cicp-transfer-characteristics") == TRANSFER_PQ
        assert result.get("clli-max-content-light-level") == 1624

    @pytest.mark.parametrize("transfer,name,cases,tolerance", TRANSFER_CASES,
                             ids=[c[1] for c in TRANSFER_CASES])
    def test_transfer_roundtrip(self, transfer, name, cases, tolerance):
        for val, _ in cases:
            if val == 0:
                continue
            im = make_cicp_image(val, val, val, transfer=transfer)
            scrgb = im.CICP2scRGB()
            result = scrgb.scRGB2CICP(transfer_characteristics=transfer)
            pixel = result(0, 0)
            assert abs(pixel[0] - val) <= 1, \
                f"{name} at {val}: got {pixel[0]}, expected {val}"

    @pytest.mark.parametrize("transfer,name", [
        (TRANSFER_PQ, "PQ"),
        (TRANSFER_HLG, "HLG"),
        (TRANSFER_SRGB, "sRGB"),
    ])
    def test_transfer_shadow_roundtrip(self, transfer, name):
        for val in range(1, 4096, 37):
            im = make_cicp_image(val, val, val, transfer=transfer,
                                 fmt="ushort")
            scrgb = im.CICP2scRGB()
            result = scrgb.scRGB2CICP(transfer_characteristics=transfer,
                                      depth=16)
            got = result(0, 0)[0]
            assert abs(got - val) <= 1, \
                f"{name} shadow at {val}/65535: got {got}, expected {val}"

    @pytest.mark.parametrize("primaries,name,_expected,_tolerance",
                             PRIMARIES_MATRIX_CASES,
                             ids=[c[1] for c in PRIMARIES_MATRIX_CASES])
    def test_primaries_roundtrip(self, primaries, name, _expected, _tolerance):
        im = make_cicp_image(200, 100, 50, primaries=primaries,
                             transfer=TRANSFER_LINEAR)
        scrgb = im.CICP2scRGB()
        result = scrgb.scRGB2CICP(colour_primaries=primaries,
                                  transfer_characteristics=TRANSFER_LINEAR)
        pixel = result(0, 0)
        assert abs(pixel[0] - 200) <= 1, \
            f"{name} R: got {pixel[0]}, expected 200"
        assert abs(pixel[1] - 100) <= 1, \
            f"{name} G: got {pixel[1]}, expected 100"
        assert abs(pixel[2] - 50) <= 1, \
            f"{name} B: got {pixel[2]}, expected 50"

    def test_scRGB2CICP_output_format_8bit(self):
        im = pyvips.Image.black(1, 1, bands=3).copy(interpretation="scrgb") \
             + [0.5, 0.5, 0.5]
        result = im.scRGB2CICP()
        assert result.format == "uchar"
        assert result.bands == 3

    def test_scRGB2CICP_output_format_16bit(self):
        im = pyvips.Image.black(1, 1, bands=3).copy(interpretation="scrgb") \
             + [0.5, 0.5, 0.5]
        result = im.scRGB2CICP(depth=16)
        assert result.format == "ushort"
        assert result.bands == 3

    def test_scRGB2CICP_metadata_set(self):
        im = pyvips.Image.black(1, 1, bands=3).copy(interpretation="scrgb") \
             + [0.5, 0.5, 0.5]
        result = im.scRGB2CICP(colour_primaries=PRIMARIES_BT2020,
                               transfer_characteristics=TRANSFER_PQ)
        assert result.get("cicp-colour-primaries") == PRIMARIES_BT2020
        assert result.get("cicp-transfer-characteristics") == TRANSFER_PQ
        assert result.get("cicp-matrix-coefficients") == 0
        assert result.get("cicp-full-range-flag") == 1

    def test_scRGB2CICP_keeps_clli_metadata(self):
        im = pyvips.Image.black(1, 1, bands=3).copy(interpretation="scrgb") \
             + [0.5, 0.5, 0.5]
        add_clli(im)
        result = im.scRGB2CICP(colour_primaries=PRIMARIES_BT2020,
                               transfer_characteristics=TRANSFER_PQ)
        assert result.get("cicp-colour-primaries") == PRIMARIES_BT2020
        assert result.get("cicp-transfer-characteristics") == TRANSFER_PQ
        assert result.get("clli-max-content-light-level") == 1624
        assert result.get("clli-max-frame-average-light-level") == 182

    def test_scRGB2CICP_ushort_roundtrip(self):
        ushort_val = round(128 / 255.0 * 65535)
        im = make_cicp_image(ushort_val, ushort_val, ushort_val,
                             transfer=TRANSFER_SRGB, fmt="ushort")
        scrgb = im.CICP2scRGB()
        result = scrgb.scRGB2CICP(depth=16)
        pixel = result(0, 0)
        assert abs(pixel[0] - ushort_val) <= 1

    def test_bt2020_pq_roundtrip(self):
        im = make_cicp_image(128, 100, 80,
                             primaries=PRIMARIES_BT2020,
                             transfer=TRANSFER_PQ)
        scrgb = im.CICP2scRGB()
        result = scrgb.scRGB2CICP(colour_primaries=PRIMARIES_BT2020,
                                  transfer_characteristics=TRANSFER_PQ)
        pixel = result(0, 0)
        assert abs(pixel[0] - 128) <= 1
        assert abs(pixel[1] - 100) <= 1
        assert abs(pixel[2] - 80) <= 1

    def test_display_p3_hlg_roundtrip(self):
        im = make_cicp_image(180, 120, 60,
                             primaries=PRIMARIES_DISPLAY_P3,
                             transfer=TRANSFER_HLG)
        scrgb = im.CICP2scRGB()
        result = scrgb.scRGB2CICP(colour_primaries=PRIMARIES_DISPLAY_P3,
                                  transfer_characteristics=TRANSFER_HLG)
        pixel = result(0, 0)
        assert abs(pixel[0] - 180) <= 1
        assert abs(pixel[1] - 120) <= 1
        assert abs(pixel[2] - 60) <= 1

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
        buf = im.heifsave_buffer(compression="av1",
                                 subsample_mode="on")
        out = pyvips.Image.new_from_buffer(buf, "")
        assert out.get("cicp-matrix-coefficients") == 0

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
    @pytest.mark.parametrize("save_options", [
        {"keep": "none"},
        {"strip": True},
        {"keep": "icc"},
        {"keep": pyvips.ForeignKeep.ICC | pyvips.ForeignKeep.GAINMAP},
    ], ids=["keep-none", "strip", "keep-icc", "keep-icc-gainmap"])
    def test_heif_cicp_nclx_kept_for_colour_signalling(self, save_options):
        im = make_cicp_image(128, 128, 128,
                             primaries=PRIMARIES_BT2020,
                             transfer=TRANSFER_PQ)
        buf = im.heifsave_buffer(compression="av1", **save_options)
        out = pyvips.Image.new_from_buffer(buf, "")
        assert out.get("cicp-colour-primaries") == PRIMARIES_BT2020
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
    def test_heif_cicp_matrix_coefficients_preserved_with_subsample(self):
        im = make_cicp_image(128, 128, 128,
                             primaries=PRIMARIES_DISPLAY_P3,
                             transfer=TRANSFER_PQ, mc=6,
                             width=64, height=64)
        buf = im.heifsave_buffer(compression="av1",
                                 subsample_mode="on")
        out = pyvips.Image.new_from_buffer(buf, "")
        assert out.get("cicp-colour-primaries") == PRIMARIES_DISPLAY_P3
        assert out.get("cicp-transfer-characteristics") == TRANSFER_PQ
        assert out.get("cicp-matrix-coefficients") == 6
        assert out.get("cicp-full-range-flag") == 1

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

    @skip_if_no("heifsave")
    @pytest.mark.parametrize("transfer", [TRANSFER_PQ, TRANSFER_HLG],
                             ids=["pq", "hlg"])
    def test_heif_hdr_nclx_with_profile_option(self, transfer):
        im = make_cicp_image(128, 128, 128,
                             primaries=PRIMARIES_BT2020,
                             transfer=transfer)

        buf = im.heifsave_buffer(compression="av1",
                                 profile=SRGB_FILE)
        out = pyvips.Image.new_from_buffer(buf, "")

        assert out.get_typeof("icc-profile-data") != 0
        assert out.get("cicp-transfer-characteristics") == transfer
        assert out.get("cicp-colour-primaries") == PRIMARIES_BT2020

    @skip_if_no("heifsave")
    @pytest.mark.xfail(raises=pyvips.error.Error, reason="requires libheif >= 1.19.0")
    def test_heif_clli_roundtrip_keep_none(self):
        im = make_cicp_image(128, 128, 128,
                             primaries=PRIMARIES_BT2020,
                             transfer=TRANSFER_PQ)
        add_clli(im)
        buf = im.heifsave_buffer(compression="av1", keep="none")
        out = pyvips.Image.new_from_buffer(buf, "")
        assert out.get("clli-max-content-light-level") == 1624
        assert out.get("clli-max-frame-average-light-level") == 182

    @skip_if_no("heifsave")
    @pytest.mark.xfail(raises=pyvips.error.Error, reason="requires libheif >= 1.19.0")
    def test_heif_clli_roundtrip_without_input_cicp(self):
        im = pyvips.Image.black(128, 128, bands=3)
        add_clli(im)
        buf = im.heifsave_buffer(compression="av1", keep="none")
        out = pyvips.Image.new_from_buffer(buf, "")
        assert out.get("clli-max-content-light-level") == 1624
        assert out.get("clli-max-frame-average-light-level") == 182

    @skip_if_no("heifsave")
    @pytest.mark.xfail(raises=pyvips.error.Error, reason="requires libheif >= 1.19.0")
    def test_heif_clli_invalid_values_not_written(self):
        im = make_cicp_image(128, 128, 128,
                             primaries=PRIMARIES_BT2020,
                             transfer=TRANSFER_PQ)
        add_clli(im, max_content_light_level=70000)
        with pytest.raises(pyvips.error.Error, match="CLLI: values out of range"):
            im.heifsave_buffer(compression="av1")

    @skip_if_no("heifsave")
    @pytest.mark.xfail(raises=pyvips.error.Error, reason="requires libheif >= 1.19.0")
    def test_heif_clli_partial_values_not_written(self):
        im = make_cicp_image(128, 128, 128,
                             primaries=PRIMARIES_BT2020,
                             transfer=TRANSFER_PQ)
        im.set_type(pyvips.GValue.gint_type,
                    "clli-max-content-light-level", 1624)
        buf = im.heifsave_buffer(compression="av1")
        out = pyvips.Image.new_from_buffer(buf, "")
        assert out.get_typeof("clli-max-content-light-level") == 0
        assert out.get_typeof("clli-max-frame-average-light-level") == 0

    @skip_if_no("heifsave")
    @pytest.mark.parametrize("mc,full_range", [(6, 1), (9, 1), (1, 0)],
                             ids=["bt601", "bt2020", "limited"])
    def test_heif_lossless_ignores_the_record_matrix_and_range(
            self, mc, full_range):
        xy = pyvips.Image.xyz(16, 16)
        im = (xy[0] * 16).bandjoin([xy[1] * 16, (xy[0] + xy[1]) * 8]) \
            .cast("uchar").copy(interpretation="srgb")
        tagged = set_cicp(im.copy(), PRIMARIES_BT709, TRANSFER_SRGB,
                          mc=mc, full_range=full_range)

        buf = tagged.heifsave_buffer(compression="av1", lossless=True)
        out = pyvips.Image.new_from_buffer(buf, "")

        assert (out - im).abs().max() == 0
        assert out.get("cicp-matrix-coefficients") == 0
        assert out.get("cicp-full-range-flag") == 1

    # -- PNG regression tests --

    @skip_if_no("pngsave")
    @pytest.mark.xfail(raises=pyvips.error.Error, reason="requires libpng >= 1.6.45")
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

    @skip_if_no("pngsave")
    @skip_if_no("pngload")
    @pytest.mark.parametrize(
        "max_cll,max_fall,save_options", [
            (1624, 182, {}),
            (1624, 182, {"keep": "none"})
        ], ids=["default", "keep-none"])
    @pytest.mark.xfail(raises=pyvips.error.Error, reason="requires libpng >= 1.6.46")
    def test_png_clli_roundtrip(self, max_cll, max_fall, save_options):
        im = pyvips.Image.black(1, 1, bands=3) + [17, 34, 51]
        add_clli(im, max_cll, max_fall)

        encoded = im.pngsave_buffer(**save_options)
        out = pyvips.Image.new_from_buffer(encoded, "")
        assert out.get("clli-max-content-light-level") == max_cll
        assert out.get("clli-max-frame-average-light-level") == max_fall
        assert out(0, 0) == [17.0, 34.0, 51.0]

    @skip_if_no("pngsave")
    @skip_if_no("pngload")
    @pytest.mark.xfail(raises=pyvips.error.Error, reason="requires libpng >= 1.6.46")
    def test_png_cicp_and_clli_coexist(self):
        im = make_cicp_image(
            37_888, 22_272, 12_544,
            primaries=PRIMARIES_DISPLAY_P3,
            transfer=TRANSFER_PQ,
            fmt="ushort"
        )
        add_clli(im)

        encoded = im.pngsave_buffer()
        out = pyvips.Image.new_from_buffer(encoded, "")
        assert out.get("cicp-colour-primaries") == PRIMARIES_DISPLAY_P3
        assert out.get("cicp-transfer-characteristics") == TRANSFER_PQ
        assert out.get("clli-max-content-light-level") == 1624
        assert out.get("clli-max-frame-average-light-level") == 182

    def test_thumbnail_returns_cicp_to_its_own_encoding(self):
        im = make_cicp_image(
            37_888, 22_272, 12_544,
            primaries=PRIMARIES_BT2020, transfer=TRANSFER_PQ,
            fmt="ushort", width=32, height=32
        )

        out = pyvips.Image.thumbnail_image(im, 16)

        assert out.format == "ushort"
        assert out.interpretation == "rgb16"
        assert out.get("cicp-colour-primaries") == PRIMARIES_BT2020
        assert out.get("cicp-transfer-characteristics") == TRANSFER_PQ

    def test_thumbnail_leaves_cicp_alone_without_linear(self):
        im = make_cicp_image(
            37_888, 22_272, 12_544,
            primaries=PRIMARIES_BT2020, transfer=TRANSFER_PQ,
            fmt="ushort", width=32, height=32
        )
        im = (im + pyvips.Image.xyz(32, 32).bandjoin(0) * 300).cast("ushort")
        im = set_cicp(im.copy(interpretation="rgb16"),
                      PRIMARIES_BT2020, TRANSFER_PQ)

        out = pyvips.Image.thumbnail_image(im, 32)

        assert (out - im).abs().max() == 0
        assert out.get("cicp-transfer-characteristics") == TRANSFER_PQ

    def test_thumbnail_honours_output_profile_for_cicp(self):
        im = make_cicp_image(
            37_888, 22_272, 12_544,
            primaries=PRIMARIES_BT2020, transfer=TRANSFER_PQ,
            fmt="ushort", width=32, height=32
        )

        out = pyvips.Image.thumbnail_image(im, 16, output_profile="srgb")

        assert out.format == "uchar"
        assert out.interpretation == "srgb"
        assert out.get_typeof("cicp-colour-primaries") == 0
        assert out.get_typeof("cicp-transfer-characteristics") == 0

    def test_thumbnail_averages_cicp_in_linear_light(self):
        xy = pyvips.Image.xyz(32, 32)
        cell = ((xy[0] + xy[1]) % 2) * 30_000
        im = set_cicp(cell.bandjoin([cell, cell]).cast("ushort")
                      .copy(interpretation="rgb16"),
                      PRIMARIES_BT2020, TRANSFER_PQ)

        out = pyvips.Image.thumbnail_image(im, 1, linear=True)

        light = im.CICP2scRGB().avg()
        expected = ((pyvips.Image.black(1, 1, bands=3) + light)
                    .copy(interpretation="scrgb")
                    .scRGB2CICP(colour_primaries=PRIMARIES_BT2020,
                                transfer_characteristics=TRANSFER_PQ,
                                depth=16))
        assert out(0, 0) == expected(0, 0)

    @pytest.mark.parametrize("primaries,transfer,peak,fmt,space,options", [
        (PRIMARIES_BT709, TRANSFER_SRGB, 255, "uchar", "srgb", {}),
        (PRIMARIES_UNSPECIFIED, TRANSFER_UNSPECIFIED, 40_000, "ushort",
         "rgb16", {}),
    ], ids=["decodable", "unspecified",])
    def test_thumbnail_cicp_matches_the_same_image_untagged(
            self, primaries, transfer, peak, fmt, space, options):
        xy = pyvips.Image.xyz(32, 32)
        cell = ((xy[0] + xy[1]) % 2) * peak
        checks = (cell.bandjoin([cell, cell])
                  .cast(fmt).copy(interpretation=space))
        tagged = set_cicp(checks.copy(), primaries, transfer)

        a = pyvips.Image.thumbnail_image(tagged, 16, **options)
        b = pyvips.Image.thumbnail_image(checks, 16, **options)

        # we can get tiny rounding errors at the corners
        assert (a.colourspace("srgb") - b.colourspace("srgb")).abs().max() < 2

    @skip_if_no("heifsave")
    @skip_if_no("pngsave")
    @skip_if_no("uhdrsave")
    @skip_if_no_CICP_PNG()
    @pytest.mark.parametrize("begin_format,end_format", [
        (".jpg", ".avif"),
        (".jpg", ".png"),
        (".jpg", ".jpg"),
        (".jpg", ".jxl"),

        (".avif", ".avif"),
        (".avif", ".png"),
        (".avif", ".jpg"),
        (".avif", ".jxl"),

        (".png", ".avif"),
        (".png", ".png"),
        (".png", ".jpg"),
        (".png", ".jxl"),

        (".jxl", ".avif"),
        (".jxl", ".png"),
        (".jxl", ".jpg"),
        (".jxl", ".jxl"),
    ])
    def test_thumnail_hdr_format(self, begin_format, end_format):
        uhdr = pyvips.Image.thumbnail(UHDR_FILE, 100)
        base = uhdr.write_to_buffer(begin_format)

        # copy_memory() to make sure we can reuse this result
        thumb = pyvips.Image.thumbnail_buffer(base, 50).copy_memory()
        buffer = thumb.write_to_buffer(end_format)
        thumb2 = pyvips.Image.new_from_buffer(buffer, "")

        assert is_hdr(thumb)
        assert is_hdr(thumb2)

        max1 = to_scRGB(thumb).max()
        max2 = to_scRGB(thumb2).max()
        assert abs(max1 - max2) < 2
