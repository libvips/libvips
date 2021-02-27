# vim: set fileencoding=utf-8 :
import pytest

import pyvips
from helpers import MOSAIC_FILES, MOSAIC_MARKS, MOSAIC_VERTICAL_MARKS

class TestMosaicing:

    def test_lrmerge(self):
        left = pyvips.Image.new_from_file(MOSAIC_FILES[0])
        right = pyvips.Image.new_from_file(MOSAIC_FILES[1])
        join = left.merge(right, 'horizontal', 10 - left.width, 0)

        assert join.width == left.width + right.width - 10
        assert join.height == max(left.height, right.height)
        assert join.bands == 1

    def test_tbmerge(self):
        top = pyvips.Image.new_from_file(MOSAIC_FILES[0])
        bottom = pyvips.Image.new_from_file(MOSAIC_FILES[2])
        join = top.merge(bottom, 'vertical', 0, 10 - top.height)

        assert join.width == max(top.width, bottom.width)
        assert join.height == top.height + bottom.height - 10
        assert join.bands == 1

    def test_lrmosaic(self):
        left = pyvips.Image.new_from_file(MOSAIC_FILES[0])
        right = pyvips.Image.new_from_file(MOSAIC_FILES[1])
        join = left.mosaic(right, 'horizontal', left.width - 30, 0, 30, 0)

        assert join.width == 1014
        assert join.height == 379
        assert join.bands == 1

    def test_tbmosaic(self):
        top = pyvips.Image.new_from_file(MOSAIC_FILES[0])
        bottom = pyvips.Image.new_from_file(MOSAIC_FILES[2])
        join = top.mosaic(bottom, 'vertical', 0, top.height - 30, 0, 30)

        assert join.width == 542
        assert join.height == 688
        assert join.bands == 1

    def test_mosaic(self):
        # ported from https://github.com/libvips/nip2/tree/master/share/nip2/data/examples/1_point_mosaic

        mosaiced_image = None

        for i in range(0, len(MOSAIC_FILES), 2):
            files = MOSAIC_FILES[i:i + 2]
            marks = MOSAIC_MARKS[i:i + 2]

            im = pyvips.Image.new_from_file(files[0])
            sec_im = pyvips.Image.new_from_file(files[1])
            horizontal_part = im.mosaic(sec_im, 
                    pyvips.Direction.HORIZONTAL,
                    marks[0][0], marks[0][1], 
                    marks[1][0], marks[1][1])

            if mosaiced_image is None:
                mosaiced_image = horizontal_part
            else:
                vertical_marks = MOSAIC_VERTICAL_MARKS[i - 2:i]
                mosaiced_image = mosaiced_image.mosaic(horizontal_part, 
                       pyvips.Direction.VERTICAL, 
                       vertical_marks[1][0], vertical_marks[1][1],
                       vertical_marks[0][0], vertical_marks[0][1])

        # Uncomment to see output file
        #mosaiced_image.write_to_file('after.jpg')

        # hard to test much more than this
        assert mosaiced_image.width == 1005
        assert mosaiced_image.height == 1295
        assert mosaiced_image.interpretation == pyvips.Interpretation.B_W
        assert mosaiced_image.bands == 1

    def test_globalbalance(self):
        mosaiced_image = None

        for i in range(0, len(MOSAIC_FILES), 2):
            files = MOSAIC_FILES[i:i + 2]
            marks = MOSAIC_MARKS[i:i + 2]

            im = pyvips.Image.new_from_file(files[0])
            sec_im = pyvips.Image.new_from_file(files[1])
            horizontal_part = im.mosaic(sec_im, 
                    pyvips.Direction.HORIZONTAL,
                    marks[0][0], marks[0][1], 
                    marks[1][0], marks[1][1])

            if mosaiced_image is None:
                mosaiced_image = horizontal_part
            else:
                vertical_marks = MOSAIC_VERTICAL_MARKS[i - 2:i]
                mosaiced_image = mosaiced_image.mosaic(horizontal_part, 
                       pyvips.Direction.VERTICAL, 
                       vertical_marks[1][0], vertical_marks[1][1],
                       vertical_marks[0][0], vertical_marks[0][1])

        mosaiced_image = mosaiced_image.globalbalance()

        # Uncomment to see output file
        #mosaiced_image.write_to_file('after.jpg')

        # hard to test much more than this
        assert mosaiced_image.width == 1005
        assert mosaiced_image.height == 1295
        assert mosaiced_image.interpretation == pyvips.Interpretation.B_W
        assert mosaiced_image.format == pyvips.BandFormat.FLOAT
        assert mosaiced_image.bands == 1

if __name__ == '__main__':
    pytest.main()
