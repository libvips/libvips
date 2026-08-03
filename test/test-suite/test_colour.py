# vim: set fileencoding=utf-8 :
import pytest

import pyvips
from helpers import *


def line_image(rows, interpretation):
    """Make a width x 1 three band float image from a list of triples."""
    bands = [pyvips.Image.new_from_array([[row[i] for row in rows]])
             for i in range(3)]
    im = bands[0].bandjoin(bands[1:]).cast(pyvips.BandFormat.FLOAT)
    return im.copy(interpretation=interpretation)


class TestColour:
    def test_colourspace(self):
        # mid-grey in Lab ... put 42 in the extra band, it should be copied
        # unmodified
        test = pyvips.Image.black(100, 100) + [50, 0, 0, 42]
        test = test.copy(interpretation=pyvips.Interpretation.LAB)

        # a long series should come in a circle
        im = test
        for col in colour_colourspaces + [pyvips.Interpretation.LAB]:
            im = im.colourspace(col)
            assert im.interpretation == col

            for i in range(0, 4):
                min_l = im.extract_band(i).min()
                max_h = im.extract_band(i).max()
                assert pytest.approx(min_l, abs=0.03) == max_h

            pixel = im(10, 10)
            if col == pyvips.Interpretation.SCRGB:
                assert pytest.approx(pixel[3], 0.0001) == 42.0 / 255.0
            else:
                assert pytest.approx(pixel[3], 0.01) == 42

        # alpha won't be equal for RGB16, but it should be preserved if we go
        # there and back
        im = im.colourspace(pyvips.Interpretation.RGB16)
        im = im.colourspace(pyvips.Interpretation.LAB)

        before = test(10, 10)
        after = im(10, 10)
        assert_almost_equal_objects(before, after, threshold=0.1)

        # go between every pair of colour spaces
        for start in colour_colourspaces:
            for end in colour_colourspaces:
                im = test.colourspace(start)
                im2 = im.colourspace(end)
                im3 = im2.colourspace(pyvips.Interpretation.LAB)

                before = test(10, 10)
                after = im3(10, 10)

                assert_almost_equal_objects(before, after, threshold=0.1)

        # test Lab->XYZ on mid-grey
        # checked against http://www.brucelindbloom.com
        im = test.colourspace(pyvips.Interpretation.XYZ)
        after = im(10, 10)
        assert_almost_equal_objects(after, [17.5064, 18.4187, 20.0547, 42])

        # grey->colour->grey should be equal
        for mono_fmt in mono_colourspaces:
            test_grey = test.colourspace(mono_fmt)
            im = test_grey
            for col in colour_colourspaces + [mono_fmt]:
                im = im.colourspace(col)
                assert im.interpretation == col
            [before, alpha_before] = test_grey(10, 10)
            [after, alpha_after] = im(10, 10)
            assert abs(alpha_after - alpha_before) < 1
            if mono_fmt == pyvips.Interpretation.GREY16:
                # GREY16 can wind up rather different due to rounding
                assert abs(after - before) < 30
            else:
                # but 8-bit we should hit exactly
                assert abs(after - before) < 1

        # we should be able to go from cmyk to any 3-band space and back again,
        # approximately
        cmyk = test.colourspace(pyvips.Interpretation.CMYK)
        for end in colour_colourspaces:
            im = cmyk.colourspace(end)
            im2 = im.colourspace(pyvips.Interpretation.CMYK)

            before = cmyk(10, 10)
            after = im2(10, 10)

            assert_almost_equal_objects(before, after, threshold=10)

    # test results from Bruce Lindbloom's calculator:
    # http://www.brucelindbloom.com
    def test_dE00(self):
        # put 42 in the extra band, it should be copied unmodified
        reference = pyvips.Image.black(100, 100) + [50, 10, 20, 42]
        reference = reference.copy(interpretation=pyvips.Interpretation.LAB)
        sample = pyvips.Image.black(100, 100) + [40, -20, 10]
        sample = sample.copy(interpretation=pyvips.Interpretation.LAB)

        difference = reference.dE00(sample)
        result, alpha = difference(10, 10)
        assert pytest.approx(result, 0.001) == 30.238
        assert pytest.approx(alpha, 0.001) == 42.0

    def test_dE00_sharma(self):
        # test data from Sharma, Wu and Dalal, "The CIEDE2000 color-difference
        # formula: implementation notes, supplementary test data, and
        # mathematical observations", Color Res. Appl. 30(1) 2005, table 1
        #
        # L1, a1, b1, L2, a2, b2, dE00
        sharma = [
            [50.0000, 2.6772, -79.7751, 50.0000, 0.0000, -82.7485, 2.0425],
            [50.0000, 3.1571, -77.2803, 50.0000, 0.0000, -82.7485, 2.8615],
            [50.0000, 2.8361, -74.0200, 50.0000, 0.0000, -82.7485, 3.4412],
            [50.0000, -1.3802, -84.2814, 50.0000, 0.0000, -82.7485, 1.0000],
            [50.0000, -1.1848, -84.8006, 50.0000, 0.0000, -82.7485, 1.0000],
            [50.0000, -0.9009, -85.5211, 50.0000, 0.0000, -82.7485, 1.0000],
            [50.0000, 0.0000, 0.0000, 50.0000, -1.0000, 2.0000, 2.3669],
            [50.0000, -1.0000, 2.0000, 50.0000, 0.0000, 0.0000, 2.3669],
            [50.0000, 2.4900, -0.0010, 50.0000, -2.4900, 0.0009, 7.1792],
            [50.0000, 2.4900, -0.0010, 50.0000, -2.4900, 0.0010, 7.1792],
            [50.0000, 2.4900, -0.0010, 50.0000, -2.4900, 0.0011, 7.2195],
            [50.0000, 2.4900, -0.0010, 50.0000, -2.4900, 0.0012, 7.2195],
            [50.0000, -0.0010, 2.4900, 50.0000, 0.0009, -2.4900, 4.8045],
            [50.0000, -0.0010, 2.4900, 50.0000, 0.0010, -2.4900, 4.8045],
            [50.0000, -0.0010, 2.4900, 50.0000, 0.0011, -2.4900, 4.7461],
            [50.0000, 2.5000, 0.0000, 50.0000, 0.0000, -2.5000, 4.3065],
            [50.0000, 2.5000, 0.0000, 73.0000, 25.0000, -18.0000, 27.1492],
            [50.0000, 2.5000, 0.0000, 61.0000, -5.0000, 29.0000, 22.8977],
            [50.0000, 2.5000, 0.0000, 56.0000, -27.0000, -3.0000, 31.9030],
            [50.0000, 2.5000, 0.0000, 58.0000, 24.0000, 15.0000, 19.4535],
            [50.0000, 2.5000, 0.0000, 50.0000, 3.1736, 0.5854, 1.0000],
            [50.0000, 2.5000, 0.0000, 50.0000, 3.2972, 0.0000, 1.0000],
            [50.0000, 2.5000, 0.0000, 50.0000, 1.8634, 0.5757, 1.0000],
            [50.0000, 2.5000, 0.0000, 50.0000, 3.2592, 0.3350, 1.0000],
            [60.2574, -34.0099, 36.2677, 60.4626, -34.1751, 39.4387, 1.2644],
            [63.0109, -31.0961, -5.8663, 62.8187, -29.7946, -4.0864, 1.2630],
            [61.2901, 3.7196, -5.3901, 61.4292, 2.2480, -4.9620, 1.8731],
            [35.0831, -44.1164, 3.7933, 35.0232, -40.0716, 1.5901, 1.8645],
            [22.7233, 20.0904, -46.6940, 23.0331, 14.9730, -42.5619, 2.0373],
            [36.4612, 47.8580, 18.3852, 36.2715, 50.5065, 21.2231, 1.4146],
            [90.8027, -2.0831, 1.4410, 91.1528, -1.6435, 0.0447, 1.4441],
            [90.9257, -0.5406, -0.9208, 88.6381, -0.8985, -0.7239, 1.5381],
            [6.7747, -0.2908, -2.4247, 5.8714, -0.0985, -2.2286, 0.6377],
            [2.0776, 0.0795, -1.1350, 0.9033, -0.0636, -0.5514, 0.9082],
        ]

        # pairs 10 and 14 have h1' and h2' exactly 180 apart, where dE00
        # jumps. In double precision they land one ulp either side of the
        # boundary: 10 the documented way, 14 not, giving 4.7461 instead
        del sharma[13]

        lab = pyvips.Interpretation.LAB
        reference = line_image([row[0:3] for row in sharma], lab)
        sample = line_image([row[3:6] for row in sharma], lab)

        difference = reference.dE00(sample)
        for i, row in enumerate(sharma):
            assert pytest.approx(difference(i, 0)[0], abs=0.001) == row[6]

        # two more cases, computed from the published formula and checked
        # against an independent implementation: the first has h1' and h2'
        # exactly 180 apart, so the branch is not picked by rounding, the
        # second sits just inside the 180 limit in the blue region, where R_T
        # is large and the sign of dH' shows up
        extra = [
            [50.0, 0.0, 25.0, 50.0, 0.0, -25.0, 36.5813],
            [50.0, -31.0, 8.0, 50.0, 60.0, -16.0, 43.7673],
        ]

        reference = line_image([row[0:3] for row in extra], lab)
        sample = line_image([row[3:6] for row in extra], lab)

        difference = reference.dE00(sample)
        for i, row in enumerate(extra):
            assert pytest.approx(difference(i, 0)[0], abs=0.001) == row[6]

    def test_dE76(self):
        # put 42 in the extra band, it should be copied unmodified
        reference = pyvips.Image.black(100, 100) + [50, 10, 20, 42]
        reference = reference.copy(interpretation=pyvips.Interpretation.LAB)
        sample = pyvips.Image.black(100, 100) + [40, -20, 10]
        sample = sample.copy(interpretation=pyvips.Interpretation.LAB)

        difference = reference.dE76(sample)
        result, alpha = difference(10, 10)
        assert pytest.approx(result, 0.001) == 33.166
        assert pytest.approx(alpha, 0.001) == 42.0

    # the vips CMC calculation is based on distance in a colorspace
    # derived from the CMC formula, so it won't match exactly ...
    # see vips_LCh2CMC() for details
    def test_dECMC(self):
        reference = pyvips.Image.black(100, 100) + [50, 10, 20, 42]
        reference = reference.copy(interpretation=pyvips.Interpretation.LAB)
        sample = pyvips.Image.black(100, 100) + [55, 11, 23]
        sample = sample.copy(interpretation=pyvips.Interpretation.LAB)

        difference = reference.dECMC(sample)
        result, alpha = difference(10, 10)
        assert result < 6
        assert pytest.approx(alpha, 0.001) == 42.0

    @skip_if_no("icc_import")
    def test_icc(self):
        test = pyvips.Image.new_from_file(JPEG_FILE)

        im = test.icc_import().icc_export()
        assert im.dE76(test).max() < 6

        im = test.icc_import()
        im2 = im.icc_export(depth=16)
        assert im2.format == pyvips.BandFormat.USHORT
        im3 = im2.icc_import()
        assert (im - im3).abs().max() < 3

        im = test.icc_import(intent=pyvips.Intent.ABSOLUTE)
        im2 = im.icc_export(intent=pyvips.Intent.ABSOLUTE)
        assert im2.dE76(test).max() < 6

        im = test.icc_import()
        im2 = im.icc_export(output_profile=SRGB_FILE)
        im3 = im.colourspace(pyvips.Interpretation.SRGB)
        assert im2.dE76(im3).max() < 6

        before_profile = test.get("icc-profile-data")
        im = test.icc_transform(SRGB_FILE)
        after_profile = im.get("icc-profile-data")
        im2 = test.icc_import()
        im3 = im2.colourspace(pyvips.Interpretation.SRGB)
        assert im.dE76(im3).max() < 6
        assert len(before_profile) != len(after_profile)

        im = test.icc_import(input_profile=SRGB_FILE)
        im2 = test.icc_import()
        assert 6 < im.dE76(im2).max()

        im = test.icc_import(pcs=pyvips.PCS.XYZ)
        assert im.interpretation == pyvips.Interpretation.XYZ

        im = test.icc_import()
        assert im.interpretation == pyvips.Interpretation.LAB

    # a float image should transform the same as the equivalent 8-bit image
    @skip_if_no("icc_import")
    def test_icc_float_input(self):
        test = pyvips.Image.new_from_file(JPEG_FILE)
        test_float = (test / 255).cast(pyvips.BandFormat.FLOAT)

        from_uchar = test.icc_import(input_profile=SRGB_FILE)
        from_float = test_float.icc_import(input_profile=SRGB_FILE)

        assert from_float.avg() > 1
        assert (from_uchar - from_float).abs().max() < 3

    # even without lcms, we should have a working approximation
    def test_cmyk(self):
        test = pyvips.Image.new_from_file(JPEG_FILE)

        im = test.colourspace("cmyk").colourspace("srgb")

        before = test(150, 210)
        after = im(150, 210)

        assert_almost_equal_objects(before, after, threshold=10)


if __name__ == '__main__':
    pytest.main()
