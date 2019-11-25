# vim: set fileencoding=utf-8 :

import sys
import os
import shutil
import tempfile
import pytest

import pyvips
from helpers import \
    JPEG_FILE, PNG_FILE, TIF_FILE, \
    WEBP_FILE, \
    temp_filename, assert_almost_equal_objects, have, skip_if_no


class TestStream:
    tempdir = None

    @classmethod
    def setup_class(cls):
        # for now, only run these tests if we have the stream pyvips installed
        if pyvips.__version__ != "2.1.10":
            pytest.skip("tests cannot run with pyvips {}"
                        .format(pyvips.__version__))

        cls.tempdir = tempfile.mkdtemp()

        cls.colour = pyvips.Image.jpegload(JPEG_FILE)
        cls.mono = cls.colour.extract_band(1)
        # we remove the ICC profile: the RGB one will no longer be appropriate
        cls.mono.remove("icc-profile-data")
        cls.rad = cls.colour.float2rad()
        cls.rad.remove("icc-profile-data")
        cls.cmyk = cls.colour.bandjoin(cls.mono)
        cls.cmyk = cls.cmyk.copy(interpretation=pyvips.Interpretation.CMYK)
        cls.cmyk.remove("icc-profile-data")

    @classmethod
    def teardown_class(cls):
        shutil.rmtree(cls.tempdir, ignore_errors=True)

    def test_streami_new_from_file(self):
        x = pyvips.Streami.new_from_file(JPEG_FILE)

        assert x.filename() == JPEG_FILE

    @skip_if_no("jpegload_stream")
    def test_image_new_from_stream_file(self):
        x = pyvips.Streami.new_from_file(JPEG_FILE)
        y = pyvips.Image.new_from_stream(x, "")

        assert y.width == 1024
        assert y.height == 768

    def test_streamo_new_to_file(self):
        filename = temp_filename(self.tempdir, ".jpg")
        x = pyvips.Streamo.new_to_file(filename)

        assert x.filename() == filename

    @skip_if_no("jpegload_stream")
    def test_image_write_to_stream_file(self):
        filename = temp_filename(self.tempdir, ".jpg")
        x = pyvips.Streamo.new_to_file(filename)
        self.colour.write_to_stream(x, ".jpg")
        with open(filename, 'rb') as f:
            data = f.read()
        data2 = self.colour.write_to_buffer(".jpg")

        assert data == data2

    def test_streami_new_memory(self):
        data = self.colour.write_to_buffer(".jpg")
        x = pyvips.Streami.new_from_memory(data)

        assert x.filename() == None

    @skip_if_no("jpegload_stream")
    def test_image_new_from_stream_memory(self):
        data = self.colour.write_to_buffer(".jpg")
        x = pyvips.Streami.new_from_memory(data)
        y = pyvips.Image.new_from_stream(x, "")

        assert y.width == 1024
        assert y.height == 768

    def test_streamo_new_memory(self):
        x = pyvips.Streamo.new_to_memory()

        assert x.filename() == None

    @skip_if_no("jpegload_stream")
    def test_image_write_to_stream_filename(self):
        x = pyvips.Streamo.new_to_memory()
        self.colour.write_to_stream(x, ".jpg")
        y = self.colour.write_to_buffer(".jpg")

        assert x.get("blob") == y

if __name__ == '__main__':
    pytest.main()
