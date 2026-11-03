# vim: set fileencoding=utf-8 :
import array

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

    def test_rank_16bit(self):
        # large windows on 16-bit images use a histogram, check it against
        # sorting each window
        width = 24
        height = 20
        values = [[(x * 7919 + y * 104729) % 65536 if (x + y) % 5 else 1000
                   for x in range(width)]
                  for y in range(height)]

        for fmt, offset in [('ushort', 0), ('short', -32768)]:
            data = array.array('H' if fmt == 'ushort' else 'h',
                               [v + offset for row in values for v in row])
            im = pyvips.Image.new_from_memory(data.tobytes(),
                                              width, height, 1, fmt)

            for w, h, index in [(5, 5, 12), (7, 3, 5), (4, 4, 3),
                                (11, 11, 0), (12, 12, 143)]:
                im2 = im.rank(w, h, index)
                result = array.array(data.typecode)
                result.frombytes(im2.write_to_memory())

                for y in range(height):
                    for x in range(width):
                        window = sorted(
                            values[min(max(y + j - h // 2, 0), height - 1)]
                                  [min(max(x + i - w // 2, 0), width - 1)]
                            for j in range(h) for i in range(w))
                        assert result[y * width + x] == window[index] + offset


if __name__ == '__main__':
    pytest.main()
