# vim: set fileencoding=utf-8 :
import pytest

import pyvips


class TestMorphology:
    def test_countlines(self):
        im = pyvips.Image.black(100, 100)
        im = im.draw_line(255, 0, 50, 100, 50)
        n_lines = im.countlines(pyvips.Direction.HORIZONTAL)
        assert n_lines == 1

    def test_labelregions(self):
        im = pyvips.Image.black(100, 100)
        im = im.draw_circle(255, 50, 50, 25, fill=True)
        mask, opts = im.labelregions(segments=True)

        assert opts['segments'] == 3
        assert mask.max() == 2

    def test_erode(self):
        im = pyvips.Image.black(100, 100)
        im = im.draw_circle(255, 50, 50, 25, fill=True)
        im2 = im.erode([[128, 255, 128],
                        [255, 255, 255],
                        [128, 255, 128]])
        assert im.width == im2.width
        assert im.height == im2.height
        assert im.bands == im2.bands
        assert im.avg() > im2.avg()

    def test_dilate(self):
        im = pyvips.Image.black(100, 100)
        im = im.draw_circle(255, 50, 50, 25, fill=True)
        im2 = im.dilate([[128, 255, 128],
                         [255, 255, 255],
                         [128, 255, 128]])
        assert im.width == im2.width
        assert im.height == im2.height
        assert im.bands == im2.bands
        assert im2.avg() > im.avg()

    def test_rank(self):
        im = pyvips.Image.black(100, 100)
        im = im.draw_circle(255, 50, 50, 25, fill=True)
        im2 = im.rank(3, 3, 8)
        assert im.width == im2.width
        assert im.height == im2.height
        assert im.bands == im2.bands
        assert im2.avg() > im.avg()


if __name__ == '__main__':
    pytest.main()
