# vim: set fileencoding=utf-8 :
import pytest

import pyvips
from helpers import JPEG_FILE


class TestHistogram:
    def test_hist_cum(self):
        im = pyvips.Image.identity()

        sum = im.avg() * 256

        cum = im.hist_cum()

        p = cum(255, 0)
        assert p[0] == sum

    def test_hist_equal(self):
        im = pyvips.Image.new_from_file(JPEG_FILE)

        im2 = im.hist_equal()

        assert im.width == im2.width
        assert im.height == im2.height

        assert im.avg() < im2.avg()
        assert im.deviate() < im2.deviate()

    def test_hist_ismonotonic(self):
        im = pyvips.Image.identity()
        assert im.hist_ismonotonic()

    def test_hist_local(self):
        im = pyvips.Image.new_from_file(JPEG_FILE)

        im2 = im.hist_local(10, 10)

        assert im.width == im2.width
        assert im.height == im2.height

        assert im.avg() < im2.avg()
        assert im.deviate() < im2.deviate()

        if pyvips.at_least_libvips(8, 5):
            im3 = im.hist_local(10, 10, max_slope=3)

            assert im.width == im3.width
            assert im.height == im3.height

            assert im3.deviate() < im2.deviate()

    def test_hist_match(self):
        im = pyvips.Image.identity()
        im2 = pyvips.Image.identity()

        matched = im.hist_match(im2)

        assert (im - matched).abs().max() == 0.0

    def test_hist_norm(self):
        im = pyvips.Image.identity()
        im2 = im.hist_norm()

        assert (im - im2).abs().max() == 0.0

    def test_hist_plot(self):
        im = pyvips.Image.identity()
        im2 = im.hist_plot()

        assert im2.width == 256
        assert im2.height == 256
        assert im2.format == pyvips.BandFormat.UCHAR
        assert im2.bands == 1

    def test_hist_map(self):
        im = pyvips.Image.identity()

        im2 = im.maplut(im)

        assert (im - im2).abs().max() == 0.0

    def test_percent(self):
        im = pyvips.Image.new_from_file(JPEG_FILE).extract_band(1)

        pc = im.percent(90)

        msk = im <= pc
        n_set = (msk.avg() * msk.width * msk.height) / 255.0
        pc_set = 100 * n_set / (msk.width * msk.height)

        assert pytest.approx(pc_set, 0.5) == 90

    def test_hist_entropy(self):
        im = pyvips.Image.new_from_file(JPEG_FILE).extract_band(1)

        ent = im.hist_find().hist_entropy()

        assert pytest.approx(ent, 0.01) == 6.67

    def test_stdif(self):
        im = pyvips.Image.new_from_file(JPEG_FILE)

        im2 = im.stdif(10, 10)

        assert im.width == im2.width
        assert im.height == im2.height

        # new mean should be closer to target mean
        assert abs(im.avg() - 128) > abs(im2.avg() - 128)

    def test_case(self):
        # slice into two at 128, we should get 50% of pixels in each half
        x = pyvips.Image.grey(256, 256, uchar=True)
        index = pyvips.Image.switch([x < 128, x >= 128])

        y = index.case([10, 20])
        assert y.avg() == 15

        # slice into four 
        index = pyvips.Image.switch([
            x < 64, 
            x >= 64 and x < 128,
            x >= 128 and x < 192,
            x >= 192
        ])
        assert index.case([10, 20, 30, 40]).avg() == 25

        # values over N should use the last value
        assert index.case([10, 20, 30]).avg() == 22.5

if __name__ == '__main__':
    pytest.main()
