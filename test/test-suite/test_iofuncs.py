# vim: set fileencoding=utf-8 :
import pytest

import pyvips


class TestIofuncs:
    def test_new_from_image(self):
        im = pyvips.Image.mask_ideal(100, 100, 0.5,
                                     reject=True, optical=True)

        im2 = im.new_from_image(12)

        assert im2.width == im.width
        assert im2.height == im.height
        assert im2.interpretation == im.interpretation
        assert im2.format == im.format
        assert im2.xres == im.xres
        assert im2.yres == im.yres
        assert im2.xoffset == im.xoffset
        assert im2.yoffset == im.yoffset
        assert im2.bands == 1
        assert im2.avg() == 12

        im2 = im.new_from_image([1, 2, 3])

        assert im2.bands == 3
        assert im2.avg() == 2

    def test_new_from_memory(self):
        s = bytearray(200)
        im = pyvips.Image.new_from_memory(s, 20, 10, 1, 'uchar')

        assert im.width == 20
        assert im.height == 10
        assert im.format == 'uchar'
        assert im.bands == 1
        assert im.avg() == 0

        im += 10

        assert im.avg() == 10

    @pytest.mark.skipif(not pyvips.at_least_libvips(8, 5),
                        reason="requires libvips >= 8.5")
    def test_get_fields(self):
        im = pyvips.Image.black(10, 10)
        fields = im.get_fields()
        # we might add more fields later
        assert len(fields) > 10
        assert fields[0] == 'width'

    def test_write_to_memory(self):
        s = bytearray(200)
        im = pyvips.Image.new_from_memory(s, 20, 10, 1, 'uchar')
        t = im.write_to_memory()

        assert s == t


if __name__ == '__main__':
    pytest.main()
