# vim: set fileencoding=utf-8 :

import sys
import os
import shutil
import tempfile
import pytest

import pyvips
from helpers import \
    JPEG_FILE, PNG_FILE, TIF_FILE, \
    temp_filename, assert_almost_equal_objects, have, skip_if_no


class TestConnection:
    tempdir = None

    @classmethod
    def setup_class(cls):
        cls.tempdir = tempfile.mkdtemp()
        cls.colour = pyvips.Image.jpegload(JPEG_FILE)
        cls.mono = cls.colour.extract_band(1).copy()
        # we remove the ICC profile: the RGB one will no longer be appropriate
        cls.mono.remove("icc-profile-data")
        cls.rad = cls.colour.float2rad().copy()
        cls.rad.remove("icc-profile-data")
        cls.cmyk = cls.colour.bandjoin(cls.mono)
        cls.cmyk = cls.cmyk.copy(interpretation=pyvips.Interpretation.CMYK)
        cls.cmyk.remove("icc-profile-data")

    @classmethod
    def teardown_class(cls):
        shutil.rmtree(cls.tempdir, ignore_errors=True)
        cls.colour = None
        cls.mono = None
        cls.rad = None
        cls.cmyk = None

    def test_source_new_from_file(self):
        x = pyvips.Source.new_from_file(JPEG_FILE)

        assert x.filename() == JPEG_FILE

    @skip_if_no("jpegload_source")
    def test_image_new_from_source_file(self):
        x = pyvips.Source.new_from_file(JPEG_FILE)
        y = pyvips.Image.new_from_source(x, "")

        assert y.width == 290
        assert y.height == 442

    def test_target_new_to_file(self):
        filename = temp_filename(self.tempdir, ".jpg")
        x = pyvips.Target.new_to_file(filename)

        assert x.filename() == filename

    @skip_if_no("jpegload_source")
    def test_image_write_to_target_file(self):
        filename = temp_filename(self.tempdir, ".jpg")
        x = pyvips.Target.new_to_file(filename)
        self.colour.write_to_target(x, ".jpg")
        with open(filename, 'rb') as f:
            data = f.read()
        data2 = self.colour.write_to_buffer(".jpg")

        assert data == data2

    def test_source_new_memory(self):
        data = self.colour.write_to_buffer(".jpg")
        x = pyvips.Source.new_from_memory(data)

        assert x.filename() == None

    @skip_if_no("jpegload_source")
    def test_image_new_from_source_memory(self):
        data = self.colour.write_to_buffer(".jpg")
        x = pyvips.Source.new_from_memory(data)
        y = pyvips.Image.new_from_source(x, "")

        assert y.width == 290
        assert y.height == 442

    def test_target_new_memory(self):
        x = pyvips.Target.new_to_memory()

        assert x.filename() == None

    @skip_if_no("jpegload_source")
    def test_image_write_to_target_memory(self):
        x = pyvips.Target.new_to_memory()
        self.colour.write_to_target(x, ".jpg")
        y = self.colour.write_to_buffer(".jpg")

        assert x.get("blob") == y

    @skip_if_no("matrixload_source")
    @skip_if_no("matrixsave_target")
    def test_connection_matrix(self):
        x = pyvips.Target.new_to_memory()
        self.mono.matrixsave_target(x)
        y = pyvips.Source.new_from_memory(x.get("blob"))
        im = pyvips.Image.matrixload_source(y)

        assert (im - self.mono).abs().max() == 0

    @skip_if_no("csvload_source")
    @skip_if_no("csvsave_target")
    def test_connection_csv(self):
        x = pyvips.Target.new_to_memory()
        self.mono.csvsave_target(x)
        y = pyvips.Source.new_from_memory(x.get("blob"))
        im = pyvips.Image.csvload_source(y)

        assert (im - self.mono).abs().max() == 0

    @skip_if_no("ppmload_source")
    @skip_if_no("ppmsave_target")
    def test_connection_ppm(self):
        x = pyvips.Target.new_to_memory()
        self.mono.ppmsave_target(x)
        y = pyvips.Source.new_from_memory(x.get("blob"))
        im = pyvips.Image.ppmload_source(y)

        assert (im - self.mono).abs().max() == 0

if __name__ == '__main__':
    pytest.main()
