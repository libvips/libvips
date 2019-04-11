# vim: set fileencoding=utf-8 :
import pytest

import pyvips


class TestDraw:
    def test_draw_circle(self):
        im = pyvips.Image.black(100, 100)
        im = im.draw_circle(100, 50, 50, 25)
        pixel = im(25, 50)
        assert len(pixel) == 1
        assert pixel[0] == 100
        pixel = im(26, 50)
        assert len(pixel) == 1
        assert pixel[0] == 0

        im = pyvips.Image.black(100, 100)
        im = im.draw_circle(100, 50, 50, 25, fill=True)
        pixel = im(25, 50)
        assert len(pixel) == 1
        assert pixel[0] == 100
        pixel = im(26, 50)
        assert pixel[0] == 100
        pixel = im(24, 50)
        assert pixel[0] == 0

    def test_draw_flood(self):
        im = pyvips.Image.black(100, 100)
        im = im.draw_circle(100, 50, 50, 25)
        im = im.draw_flood(100, 50, 50)

        im2 = pyvips.Image.black(100, 100)
        im2 = im2.draw_circle(100, 50, 50, 25, fill=True)

        diff = (im - im2).abs().max()
        assert diff == 0

    def test_draw_image(self):
        im = pyvips.Image.black(51, 51)
        im = im.draw_circle(100, 25, 25, 25, fill=True)

        im2 = pyvips.Image.black(100, 100)
        im2 = im2.draw_image(im, 25, 25)

        im3 = pyvips.Image.black(100, 100)
        im3 = im3.draw_circle(100, 50, 50, 25, fill=True)

        diff = (im2 - im3).abs().max()
        assert diff == 0

    def test_draw_line(self):
        im = pyvips.Image.black(100, 100)
        im = im.draw_line(100, 0, 0, 100, 0)
        pixel = im(0, 0)
        assert len(pixel) == 1
        assert pixel[0] == 100
        pixel = im(0, 1)
        assert len(pixel) == 1
        assert pixel[0] == 0

    def test_draw_mask(self):
        mask = pyvips.Image.black(51, 51)
        mask = mask.draw_circle(128, 25, 25, 25, fill=True)

        im = pyvips.Image.black(100, 100)
        im = im.draw_mask(200, mask, 25, 25)

        im2 = pyvips.Image.black(100, 100)
        im2 = im2.draw_circle(100, 50, 50, 25, fill=True)

        diff = (im - im2).abs().max()
        assert diff == 0

    def test_draw_rect(self):
        im = pyvips.Image.black(100, 100)
        im = im.draw_rect(100, 25, 25, 50, 50, fill=True)

        im2 = pyvips.Image.black(100, 100)
        for y in range(25, 75):
            im2 = im2.draw_line(100, 25, y, 74, y)

        diff = (im - im2).abs().max()
        assert diff == 0

    def test_draw_smudge(self):
        im = pyvips.Image.black(100, 100)
        im = im.draw_circle(100, 50, 50, 25, fill=True)

        im2 = im.draw_smudge(10, 10, 50, 50)

        im3 = im.crop(10, 10, 50, 50)

        im4 = im2.draw_image(im3, 10, 10)

        diff = (im4 - im).abs().max()
        assert diff == 0


if __name__ == '__main__':
    pytest.main()
