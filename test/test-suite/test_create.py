# vim: set fileencoding=utf-8 :
import pytest

import pyvips
from helpers import assert_almost_equal_objects


class TestCreate:
    def test_black(self):
        im = pyvips.Image.black(100, 100)

        assert im.width == 100
        assert im.height == 100
        assert im.format == pyvips.BandFormat.UCHAR
        assert im.bands == 1
        for i in range(0, 100):
            pixel = im(i, i)
            assert len(pixel) == 1
            assert pixel[0] == 0

        im = pyvips.Image.black(100, 100, bands=3)

        assert im.width == 100
        assert im.height == 100
        assert im.format == pyvips.BandFormat.UCHAR
        assert im.bands == 3
        for i in range(0, 100):
            pixel = im(i, i)
            assert len(pixel) == 3
            assert_almost_equal_objects(pixel, [0, 0, 0])

    def test_buildlut(self):
        M = pyvips.Image.new_from_array([[0, 0],
                                         [255, 100]])
        lut = M.buildlut()
        assert lut.width == 256
        assert lut.height == 1
        assert lut.bands == 1
        p = lut(0, 0)
        assert p[0] == 0.0
        p = lut(255, 0)
        assert p[0] == 100.0
        p = lut(10, 0)
        assert p[0] == 100 * 10.0 / 255.0

        M = pyvips.Image.new_from_array([[0, 0, 100],
                                         [255, 100, 0],
                                         [128, 10, 90]])
        lut = M.buildlut()
        assert lut.width == 256
        assert lut.height == 1
        assert lut.bands == 2
        p = lut(0, 0)
        assert_almost_equal_objects(p, [0.0, 100.0])
        p = lut(64, 0)
        assert_almost_equal_objects(p, [5.0, 95.0])

    def test_eye(self):
        im = pyvips.Image.eye(100, 90)
        assert im.width == 100
        assert im.height == 90
        assert im.bands == 1
        assert im.format == pyvips.BandFormat.FLOAT
        assert im.max() == 1.0
        assert im.min() == -1.0

        im = pyvips.Image.eye(100, 90, uchar=True)
        assert im.width == 100
        assert im.height == 90
        assert im.bands == 1
        assert im.format == pyvips.BandFormat.UCHAR
        assert im.max() == 255.0
        assert im.min() == 0.0

    @pytest.mark.skipif(pyvips.type_find("VipsOperation", "fwfft") == 0,
                        reason="no FFTW, skipping test")
    def test_fractsurf(self):
        im = pyvips.Image.fractsurf(100, 90, 2.5)
        assert im.width == 100
        assert im.height == 90
        assert im.bands == 1
        assert im.format == pyvips.BandFormat.FLOAT

    def test_gaussmat(self):
        im = pyvips.Image.gaussmat(1, 0.1)
        assert im.width == 5
        assert im.height == 5
        assert im.bands == 1
        assert im.format == pyvips.BandFormat.DOUBLE
        assert im.max() == 20
        total = im.avg() * im.width * im.height
        scale = im.get("scale")
        assert total == scale
        p = im(im.width / 2, im.height / 2)
        assert p[0] == 20.0

        im = pyvips.Image.gaussmat(1, 0.1,
                                   separable=True, precision="float")
        assert im.width == 5
        assert im.height == 1
        assert im.bands == 1
        assert im.format == pyvips.BandFormat.DOUBLE
        assert im.max() == 1.0
        total = im.avg() * im.width * im.height
        scale = im.get("scale")
        assert total == scale
        p = im(im.width / 2, im.height / 2)
        assert p[0] == 1.0

    def test_gaussnoise(self):
        im = pyvips.Image.gaussnoise(100, 90)
        assert im.width == 100
        assert im.height == 90
        assert im.bands == 1
        assert im.format == pyvips.BandFormat.FLOAT

        im = pyvips.Image.gaussnoise(100, 90, sigma=10, mean=100)
        assert im.width == 100
        assert im.height == 90
        assert im.bands == 1
        assert im.format == pyvips.BandFormat.FLOAT

        sigma = im.deviate()
        mean = im.avg()

        assert sigma == pytest.approx(10, abs=0.4)
        assert mean == pytest.approx(100, abs=0.4)

    def test_grey(self):
        im = pyvips.Image.grey(100, 90)
        assert im.width == 100
        assert im.height == 90
        assert im.bands == 1
        assert im.format == pyvips.BandFormat.FLOAT

        p = im(0, 0)
        assert p[0] == 0.0
        p = im(99, 0)
        assert p[0] == 1.0
        p = im(0, 89)
        assert p[0] == 0.0
        p = im(99, 89)
        assert p[0] == 1.0

        im = pyvips.Image.grey(100, 90, uchar=True)
        assert im.width == 100
        assert im.height == 90
        assert im.bands == 1
        assert im.format == pyvips.BandFormat.UCHAR

        p = im(0, 0)
        assert p[0] == 0
        p = im(99, 0)
        assert p[0] == 255
        p = im(0, 89)
        assert p[0] == 0
        p = im(99, 89)
        assert p[0] == 255

    def test_identity(self):
        im = pyvips.Image.identity()
        assert im.width == 256
        assert im.height == 1
        assert im.bands == 1
        assert im.format == pyvips.BandFormat.UCHAR

        p = im(0, 0)
        assert p[0] == 0.0
        p = im(255, 0)
        assert p[0] == 255.0
        p = im(128, 0)
        assert p[0] == 128.0

        im = pyvips.Image.identity(ushort=True)
        assert im.width == 65536
        assert im.height == 1
        assert im.bands == 1
        assert im.format == pyvips.BandFormat.USHORT

        p = im(0, 0)
        assert p[0] == 0
        p = im(99, 0)
        assert p[0] == 99
        p = im(65535, 0)
        assert p[0] == 65535

    def test_invertlut(self):
        lut = pyvips.Image.new_from_array([[0.1, 0.2, 0.3, 0.1],
                                           [0.2, 0.4, 0.4, 0.2],
                                           [0.7, 0.5, 0.6, 0.3]])
        im = lut.invertlut()
        assert im.width == 256
        assert im.height == 1
        assert im.bands == 3
        assert im.format == pyvips.BandFormat.DOUBLE

        p = im(0, 0)
        assert_almost_equal_objects(p, [0, 0, 0])
        p = im(255, 0)
        assert_almost_equal_objects(p, [1, 1, 1])
        p = im(0.2 * 255, 0)
        assert p[0] == pytest.approx(0.1, abs=0.1)
        p = im(0.3 * 255, 0)
        assert p[1] == pytest.approx(0.1, abs=0.1)
        p = im(0.1 * 255, 0)
        assert p[2] == pytest.approx(0.1, abs=0.1)

    def test_matrixinvert(self):
        # 4x4 matrix to check if PLU decomposition works
        mat = pyvips.Image.new_from_array([[4, 0, 0, 0],
                                           [0, 0, 2, 0],
                                           [0, 1, 2, 0],
                                           [1, 0, 0, 1]])
        im = mat.matrixinvert()
        assert im.width == 4
        assert im.height == 4
        assert im.bands == 1
        assert im.format == pyvips.BandFormat.DOUBLE

        p = im(0, 0)
        assert p[0] == 0.25
        p = im(3, 3)
        assert p[0] == 1.0

    def test_logmat(self):
        im = pyvips.Image.logmat(1, 0.1)
        assert im.width == 7
        assert im.height == 7
        assert im.bands == 1
        assert im.format == pyvips.BandFormat.DOUBLE
        assert im.max() == 20
        total = im.avg() * im.width * im.height
        scale = im.get("scale")
        assert total == scale
        p = im(im.width / 2, im.height / 2)
        assert p[0] == 20.0

        im = pyvips.Image.logmat(1, 0.1,
                                 separable=True, precision="float")
        assert im.width == 7
        assert im.height == 1
        assert im.bands == 1
        assert im.format == pyvips.BandFormat.DOUBLE
        assert im.max() == 1.0
        total = im.avg() * im.width * im.height
        scale = im.get("scale")
        assert total == scale
        p = im(im.width / 2, im.height / 2)
        assert p[0] == 1.0

    def test_mask_butterworth_band(self):
        im = pyvips.Image.mask_butterworth_band(128, 128, 2,
                                                0.5, 0.5, 0.7,
                                                0.1)
        assert im.width == 128
        assert im.height == 128
        assert im.bands == 1
        assert im.format == pyvips.BandFormat.FLOAT
        assert im.max() == pytest.approx(1, abs=0.01)
        p = im(32, 32)
        assert p[0] == 1.0

        im = pyvips.Image.mask_butterworth_band(128, 128, 2,
                                                0.5, 0.5, 0.7,
                                                0.1, uchar=True, optical=True)
        assert im.width == 128
        assert im.height == 128
        assert im.bands == 1
        assert im.format == pyvips.BandFormat.UCHAR
        assert im.max() == 255
        p = im(32, 32)
        assert p[0] == 255.0
        p = im(64, 64)
        assert p[0] == 255.0

        im = pyvips.Image.mask_butterworth_band(128, 128, 2,
                                                0.5, 0.5, 0.7,
                                                0.1, uchar=True, optical=True,
                                                nodc=True)
        assert im.width == 128
        assert im.height == 128
        assert im.bands == 1
        assert im.format == pyvips.BandFormat.UCHAR
        assert im.max() == 255
        p = im(32, 32)
        assert p[0] == 255.0
        p = im(64, 64)
        assert p[0] != 255

    def test_mask_butterworth(self):
        im = pyvips.Image.mask_butterworth(128, 128, 2, 0.7, 0.1,
                                           nodc=True)
        assert im.width == 128
        assert im.height == 128
        assert im.bands == 1
        assert im.format == pyvips.BandFormat.FLOAT
        assert im.min() == pytest.approx(0, abs=0.01)
        p = im(0, 0)
        assert p[0] == 0.0
        v, x, y = im.maxpos()
        assert x == 64
        assert y == 64

        im = pyvips.Image.mask_butterworth(128, 128, 2, 0.7, 0.1,
                                           optical=True, uchar=True)
        assert im.width == 128
        assert im.height == 128
        assert im.bands == 1
        assert im.format == pyvips.BandFormat.UCHAR
        assert im.min() == pytest.approx(0, abs=0.01)
        p = im(64, 64)
        assert p[0] == 255

    def test_mask_butterworth_ring(self):
        im = pyvips.Image.mask_butterworth_ring(128, 128, 2, 0.7, 0.1, 0.5,
                                                nodc=True)
        assert im.width == 128
        assert im.height == 128
        assert im.bands == 1
        assert im.format == pyvips.BandFormat.FLOAT
        p = im(45, 0)
        assert p[0] == pytest.approx(1.0, abs=0.0001)
        v, x, y = im.minpos()
        assert x == 64
        assert y == 64

    def test_mask_fractal(self):
        im = pyvips.Image.mask_fractal(128, 128, 2.3)
        assert im.width == 128
        assert im.height == 128
        assert im.bands == 1
        assert im.format == pyvips.BandFormat.FLOAT

    def test_mask_gaussian_band(self):
        im = pyvips.Image.mask_gaussian_band(128, 128, 0.5, 0.5, 0.7, 0.1)
        assert im.width == 128
        assert im.height == 128
        assert im.bands == 1
        assert im.format == pyvips.BandFormat.FLOAT
        assert im.max() == pytest.approx(1, abs=0.01)
        p = im(32, 32)
        assert p[0] == 1.0

    def test_mask_gaussian(self):
        im = pyvips.Image.mask_gaussian(128, 128, 0.7, 0.1,
                                        nodc=True)
        assert im.width == 128
        assert im.height == 128
        assert im.bands == 1
        assert im.format == pyvips.BandFormat.FLOAT
        assert im.min() == pytest.approx(0, abs=0.01)
        p = im(0, 0)
        assert p[0] == 0.0

    def test_mask_gaussian_ring(self):
        im = pyvips.Image.mask_gaussian_ring(128, 128, 0.7, 0.1, 0.5,
                                             nodc=True)
        assert im.width == 128
        assert im.height == 128
        assert im.bands == 1
        assert im.format == pyvips.BandFormat.FLOAT
        p = im(45, 0)
        assert p[0] == pytest.approx(1.0, abs=0.001)

    def test_mask_ideal_band(self):
        im = pyvips.Image.mask_ideal_band(128, 128, 0.5, 0.5, 0.7)
        assert im.width == 128
        assert im.height == 128
        assert im.bands == 1
        assert im.format == pyvips.BandFormat.FLOAT
        assert im.max() == pytest.approx(1, abs=0.01)
        p = im(32, 32)
        assert p[0] == 1.0

    def test_mask_ideal(self):
        im = pyvips.Image.mask_ideal(128, 128, 0.7,
                                     nodc=True)
        assert im.width == 128
        assert im.height == 128
        assert im.bands == 1
        assert im.format == pyvips.BandFormat.FLOAT
        assert im.min() == pytest.approx(0, abs=0.01)
        p = im(0, 0)
        assert p[0] == 0.0

    def test_mask_gaussian_ring_2(self):
        im = pyvips.Image.mask_ideal_ring(128, 128, 0.7, 0.5,
                                          nodc=True)
        assert im.width == 128
        assert im.height == 128
        assert im.bands == 1
        assert im.format == pyvips.BandFormat.FLOAT
        p = im(45, 0)
        assert p[0] == pytest.approx(1, abs=0.001)

    def test_sines(self):
        im = pyvips.Image.sines(128, 128)
        assert im.width == 128
        assert im.height == 128
        assert im.bands == 1
        assert im.format == pyvips.BandFormat.FLOAT

    @pytest.mark.skipif(pyvips.type_find("VipsOperation", "text") == 0,
                        reason="no text, skipping test")
    def test_text(self):
        im = pyvips.Image.text("Hello, world!")
        assert im.width > 10
        assert im.height > 10
        assert im.bands == 1
        assert im.format == pyvips.BandFormat.UCHAR
        assert im.max() == 255
        assert im.min() == 0

        # test autofit
        im = pyvips.Image.text("Hello, world!", width=500, height=500)
        # quite a large threshold, since we need to work with a huge range of 
        # text rendering systems
        assert abs(im.width - 500) < 50

    def test_tonelut(self):
        im = pyvips.Image.tonelut()
        assert im.bands == 1
        assert im.format == pyvips.BandFormat.USHORT
        assert im.width == 32768
        assert im.height == 1
        assert im.hist_ismonotonic()

    def test_xyz(self):
        im = pyvips.Image.xyz(128, 128)
        assert im.bands == 2
        assert im.format == pyvips.BandFormat.UINT
        assert im.width == 128
        assert im.height == 128
        p = im(45, 35)
        assert_almost_equal_objects(p, [45, 35])

    def test_zone(self):
        im = pyvips.Image.zone(128, 128)
        assert im.width == 128
        assert im.height == 128
        assert im.bands == 1
        assert im.format == pyvips.BandFormat.FLOAT

    @pytest.mark.skipif(pyvips.type_find("VipsOperation", "worley") == 0,
                        reason="no worley, skipping test")
    def test_worley(self):
        im = pyvips.Image.worley(512, 512)
        assert im.width == 512
        assert im.height == 512
        assert im.bands == 1
        assert im.format == pyvips.BandFormat.FLOAT

    @pytest.mark.skipif(pyvips.type_find("VipsOperation", "perlin") == 0,
                        reason="no perlin, skipping test")
    def test_perlin(self):
        im = pyvips.Image.perlin(512, 512)
        assert im.width == 512
        assert im.height == 512
        assert im.bands == 1
        assert im.format == pyvips.BandFormat.FLOAT


if __name__ == '__main__':
    pytest.main()
