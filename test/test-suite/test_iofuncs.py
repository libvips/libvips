# vim: set fileencoding=utf-8 :
import pytest

import pyvips
import tempfile
from helpers import temp_filename


class TestIofuncs:
    tempdir = None

    @classmethod
    def setup_class(cls):
        cls.tempdir = tempfile.mkdtemp()

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

    def test_revalidate(self):
        filename = temp_filename(self.tempdir, '.v')

        im1 = pyvips.Image.black(10, 10)
        im1.write_to_file(filename)

        load1 = pyvips.Image.new_from_file(filename);
        assert load1.width == im1.width

        im2 = pyvips.Image.black(20, 20)
        im2.write_to_file(filename)

        # this will use the old, cached load
        load2 = pyvips.Image.new_from_file(filename);
        assert load2.width == im1.width

        # load again with "revalidate" and we should see the new image
        load2 = pyvips.Image.new_from_file(filename, revalidate=True);
        assert load2.width == im2.width

        # load once more without revalidate and we should see the cached 
        # new image
        load2 = pyvips.Image.new_from_file(filename)
        assert load2.width == im2.width


if __name__ == '__main__':
    pytest.main()
