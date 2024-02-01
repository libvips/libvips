# vim: set fileencoding=utf-8 :
import sys
import os
import shutil
import tempfile
import pytest

import pyvips
from helpers import \
    IMAGES, JPEG_FILE, SRGB_FILE, MATLAB_FILE, PNG_FILE, TIF_FILE, OME_FILE, \
    ANALYZE_FILE, GIF_FILE, WEBP_FILE, EXR_FILE, FITS_FILE, OPENSLIDE_FILE, \
    PDF_FILE, SVG_FILE, SVGZ_FILE, SVG_GZ_FILE, GIF_ANIM_FILE, DICOM_FILE, \
    BMP_FILE, NIFTI_FILE, ICO_FILE, CUR_FILE, TGA_FILE, SGI_FILE, AVIF_FILE, \
    AVIF_FILE_HUGE, TRUNCATED_FILE, \
    GIF_ANIM_EXPECTED_PNG_FILE, GIF_ANIM_DISPOSE_BACKGROUND_FILE, \
    GIF_ANIM_DISPOSE_BACKGROUND_EXPECTED_PNG_FILE, \
    GIF_ANIM_DISPOSE_PREVIOUS_FILE, \
    GIF_ANIM_DISPOSE_PREVIOUS_EXPECTED_PNG_FILE, \
    temp_filename, assert_almost_equal_objects, have, skip_if_no, \
    TIF1_FILE, TIF2_FILE, TIF4_FILE, WEBP_LOOKS_LIKE_SVG_FILE, \
    WEBP_ANIMATED_FILE, JP2K_FILE, RGBA_FILE

class TestForeign:
    tempdir = None

    @classmethod
    def setup_class(cls):
        cls.tempdir = tempfile.mkdtemp()

        cls.colour = pyvips.Image.jpegload(JPEG_FILE)
        cls.rgba = pyvips.Image.new_from_file(RGBA_FILE)
        cls.mono = cls.colour.extract_band(1).copy()
        # we remove the ICC profile: the RGB one will no longer be appropriate
        cls.mono.remove("icc-profile-data")
        cls.rad = cls.colour.float2rad().copy()
        cls.rad.remove("icc-profile-data")
        cls.cmyk = cls.colour.bandjoin(cls.mono)
        cls.cmyk = cls.cmyk.copy(interpretation=pyvips.Interpretation.CMYK)
        cls.cmyk.remove("icc-profile-data")

        im = pyvips.Image.new_from_file(GIF_FILE)
        cls.onebit = im[1] > 128

    @classmethod
    def teardown_class(cls):
        shutil.rmtree(cls.tempdir, ignore_errors=True)
        cls.colour = None
        cls.rgba = None
        cls.mono = None
        cls.rad = None
        cls.cmyk = None
        cls.onebit = None

    # we have test files for formats which have a clear standard
    def file_loader(self, loader, test_file, validate):
        im = pyvips.Operation.call(loader, test_file)
        validate(im)
        im = pyvips.Image.new_from_file(test_file)
        validate(im)

    def buffer_loader(self, loader, test_file, validate):
        with open(test_file, 'rb') as f:
            buf = f.read()

        im = pyvips.Operation.call(loader, buf)
        validate(im)
        im = pyvips.Image.new_from_buffer(buf, "")
        validate(im)

    def save_load(self, format, im):
        x = pyvips.Image.new_temp_file(format)
        im.write(x)

        assert im.width == x.width
        assert im.height == x.height
        assert im.bands == x.bands
        max_diff = (im - x).abs().max()
        assert max_diff == 0

    def save_load_file(self, format, options, im, max_diff=0):
        # yuk!
        # but we can't set format parameters for pyvips.Image.new_temp_file()
        filename = temp_filename(self.tempdir, format)

        im.write_to_file(filename + options)
        x = pyvips.Image.new_from_file(filename)

        assert im.width == x.width
        assert im.height == x.height
        assert im.bands == x.bands
        assert (im - x).abs().max() <= max_diff
        x = None

    def save_load_buffer(self, saver, loader, im, max_diff=0, **kwargs):
        buf = pyvips.Operation.call(saver, im, **kwargs)
        x = pyvips.Operation.call(loader, buf)

        assert im.width == x.width
        assert im.height == x.height
        assert im.bands == x.bands
        assert (im - x).abs().max() <= max_diff

    def save_buffer_tempfile(self, saver, suf, im, max_diff=0):
        filename = temp_filename(self.tempdir, suf)

        buf = pyvips.Operation.call(saver, im)
        f = open(filename, 'wb')
        f.write(buf)
        f.close()

        x = pyvips.Image.new_from_file(filename)

        assert im.width == x.width
        assert im.height == x.height
        assert im.bands == x.bands
        assert (im - x).abs().max() <= max_diff

    def test_vips(self):
        self.save_load_file(".v", "", self.colour)

        # check we can save and restore metadata
        filename = temp_filename(self.tempdir, ".v")
        self.colour.write_to_file(filename)
        x = pyvips.Image.new_from_file(filename)
        before_exif = self.colour.get("exif-data")
        after_exif = x.get("exif-data")

        assert len(before_exif) == len(after_exif)
        for i in range(len(before_exif)):
            assert before_exif[i] == after_exif[i]

        # https://github.com/libvips/libvips/issues/1847
        filename = temp_filename(self.tempdir, ".v")
        x = pyvips.Image.black(16, 16) + 128
        x.write_to_file(filename)

        x = pyvips.Image.new_from_file(filename)
        assert x.width == 16
        assert x.height == 16
        assert x.bands == 1
        assert x.avg() == 128

        x = None

    @skip_if_no("jpegload")
    def test_jpeg(self):
        def jpeg_valid(im):
            a = im(10, 10)
            # different versions of libjpeg decode have slightly different
            # rounding
            assert_almost_equal_objects(a, [141, 127, 90], threshold=3)
            profile = im.get("icc-profile-data")
            assert len(profile) == 564
            assert im.width == 290
            assert im.height == 442
            assert im.bands == 3

        self.file_loader("jpegload", JPEG_FILE, jpeg_valid)
        self.save_load("%s.jpg", self.mono)
        self.save_load("%s.jpg", self.colour)

        self.buffer_loader("jpegload_buffer", JPEG_FILE, jpeg_valid)
        self.save_load_buffer("jpegsave_buffer", "jpegload_buffer",
                              self.colour, 80)

        # see if we have exif parsing: our test image has this field
        x = pyvips.Image.new_from_file(JPEG_FILE)
        if x.get_typeof("exif-ifd0-Orientation") != 0:
            # we need a copy of the image to set the new metadata on
            # otherwise we get caching problems

            # can set, save and load new orientation
            x = pyvips.Image.new_from_file(JPEG_FILE)
            x = x.copy()

            x.set("orientation", 2)

            filename = temp_filename(self.tempdir, '.jpg')
            x.write_to_file(filename)

            x = pyvips.Image.new_from_file(filename)
            y = x.get("orientation")
            assert y == 2

            # can remove orientation, save, load again, orientation
            # has reset
            x = x.copy()
            x.remove("orientation")

            filename = temp_filename(self.tempdir, '.jpg')
            x.write_to_file(filename)

            x = pyvips.Image.new_from_file(filename)
            y = x.get("orientation")
            assert y == 1

            # autorotate load works
            x = pyvips.Image.new_from_file(JPEG_FILE)
            x = x.copy()

            x.set("orientation", 6)

            filename = temp_filename(self.tempdir, '.jpg')
            x.write_to_file(filename)

            x1 = pyvips.Image.new_from_file(filename)
            x2 = pyvips.Image.new_from_file(filename, autorotate=True)
            assert x1.width == x2.height
            assert x1.height == x2.width

            # sets incorrect orientation, save, load again, orientation
            # has reset to 1
            x = x.copy()
            x.set("orientation", 256)

            filename = temp_filename(self.tempdir, '.jpg')
            x.write_to_file(filename)

            x = pyvips.Image.new_from_file(filename)
            y = x.get("orientation")
            assert y == 1

            # can set, save and reload ASCII string fields
            x = pyvips.Image.new_from_file(JPEG_FILE)
            x = x.copy()

            x.set_type(pyvips.GValue.gstr_type,
                       "exif-ifd0-ImageDescription", "hello world")

            filename = temp_filename(self.tempdir, '.jpg')
            x.write_to_file(filename)

            x = pyvips.Image.new_from_file(filename)
            y = x.get("exif-ifd0-ImageDescription")
            # can't use == since the string will have an extra " (xx, yy, zz)"
            # format area at the end
            assert y.startswith("hello world")

            # can set, save and reload UTF16 string fields ... pyvips is
            # utf8, but it will be coded as utf16 and back for the XP* fields
            x = pyvips.Image.new_from_file(JPEG_FILE)
            x = x.copy()

            x.set_type(pyvips.GValue.gstr_type, "exif-ifd0-XPComment", u"йцук")

            filename = temp_filename(self.tempdir, '.jpg')
            x.write_to_file(filename)

            x = pyvips.Image.new_from_file(filename)
            y = x.get("exif-ifd0-XPComment")
            # can't use == since the string will have an extra " (xx, yy, zz)"
            # format area at the end
            assert y.startswith(u"йцук")

            # can set/save/load UserComment, a tag which has the
            # encoding in the first 8 bytes ... though libexif only supports
            # ASCII for this
            x = pyvips.Image.new_from_file(JPEG_FILE)
            x = x.copy()

            x.set_type(pyvips.GValue.gstr_type,
                       "exif-ifd2-UserComment", "hello world")

            filename = temp_filename(self.tempdir, '.jpg')
            x.write_to_file(filename)

            x = pyvips.Image.new_from_file(filename)
            y = x.get("exif-ifd2-UserComment")
            # can't use == since the string will have an extra " (xx, yy, zz)"
            # format area at the end
            assert y.startswith("hello world")

    @skip_if_no("jpegsave")
    def test_jpegsave(self):
        im = pyvips.Image.new_from_file(JPEG_FILE)

        q10 = im.jpegsave_buffer(Q=10)
        q10_subsample_auto = im.jpegsave_buffer(Q=10, subsample_mode="auto")
        q10_subsample_on = im.jpegsave_buffer(Q=10, subsample_mode="on")
        q10_subsample_off = im.jpegsave_buffer(Q=10, subsample_mode="off")

        q90 = im.jpegsave_buffer(Q=90)
        q90_subsample_auto = im.jpegsave_buffer(Q=90, subsample_mode="auto")
        q90_subsample_on = im.jpegsave_buffer(Q=90, subsample_mode="on")
        q90_subsample_off = im.jpegsave_buffer(Q=90, subsample_mode="off")

        # higher Q should mean a bigger buffer
        assert len(q90) > len(q10)

        assert len(q10_subsample_auto) == len(q10)
        assert len(q10_subsample_on) == len(q10_subsample_auto)
        assert len(q10_subsample_off) > len(q10)

        assert len(q90_subsample_auto) == len(q90)
        assert len(q90_subsample_on) < len(q90)
        assert len(q90_subsample_off) == len(q90_subsample_auto)

        # A non-zero restart_interval should result in a bigger file.
        # Otherwise, smaller restart intervals will have more restart markers
        # and therefore be larger
        r0 = im.jpegsave_buffer(restart_interval=0)
        r10 = im.jpegsave_buffer(restart_interval=10)
        r2 = im.jpegsave_buffer(restart_interval=2)
        assert len(r10) > len(r0)
        assert len(r2) > len(r10)

        # we should be able to reload jpegs with extra MCU markers
        im0 = pyvips.Image.jpegload_buffer(r0)
        im10 = pyvips.Image.jpegload_buffer(r10)
        assert im0.avg() == im10.avg()

    @skip_if_no("jpegsave")
    def test_jpegsave_exif(self):
        def exif_valid(im):
            assert im.get("exif-ifd2-UserComment").find("Undefined, 21 components, 21 bytes") != -1
            assert im.get("exif-ifd0-Software").find("ASCII, 14 components, 14 bytes") != -1
            assert im.get("exif-ifd0-XPComment").find("Byte, 28 components, 28 bytes") != -1

        def exif_removed(im):
            assert im.get_typeof("exif-ifd2-UserComment") == 0
            assert im.get_typeof("exif-ifd0-Software") == 0
            assert im.get_typeof("exif-ifd0-XPComment") == 0

        # first make sure we have exif support
        im = pyvips.Image.new_from_file(JPEG_FILE)
        if im.get_typeof("exif-ifd0-Orientation") != 0:
            x = im.copy()
            x.set_type(pyvips.GValue.gstr_type, "exif-ifd2-UserComment", "hello ( there") # tag_is_encoding
            x.set_type(pyvips.GValue.gstr_type, "exif-ifd0-Software", "hello ( there")    # tag_is_ascii
            x.set_type(pyvips.GValue.gstr_type, "exif-ifd0-XPComment", "hello ( there")   # tag_is_utf16
            buf = x.jpegsave_buffer()
            y = pyvips.Image.new_from_buffer(buf, "")
            exif_valid(y)
            # Reproduce https://github.com/libvips/libvips/issues/2388
            buf = y.jpegsave_buffer()
            z = pyvips.Image.new_from_buffer(buf, "")
            exif_valid(z)
            # Try whether we can remove EXIF, just to be sure
            z = z.copy()
            z.remove("exif-ifd2-UserComment")
            z.remove("exif-ifd0-Software")
            z.remove("exif-ifd0-XPComment")
            buf = z.jpegsave_buffer()
            im = pyvips.Image.new_from_buffer(buf, "")
            exif_removed(im)

    @skip_if_no("jpegsave")
    @pytest.mark.xfail(raises=pyvips.error.Error, reason="requires libexif >= 0.6.22")
    def test_jpegsave_exif_2_3_ascii(self):
        def exif_valid(exif_tags, im):
            for exif_tag in exif_tags:
                assert im.get(exif_tag).find("ASCII, 14 components, 14 bytes") != -1

        # first make sure we have exif support
        im = pyvips.Image.new_from_file(JPEG_FILE)
        if im.get_typeof("exif-ifd0-Orientation") != 0:
            x = im.copy()
            exif_tags = [
                "exif-ifd2-CameraOwnerName",
                "exif-ifd2-BodySerialNumber",
                "exif-ifd2-LensMake",
                "exif-ifd2-LensModel",
                "exif-ifd2-LensSerialNumber",
            ]
            for exif_tag in exif_tags:
                x.set_type(pyvips.GValue.gstr_type, exif_tag, "hello ( there")
            buf = x.jpegsave_buffer()
            y = pyvips.Image.new_from_buffer(buf, "")
            exif_valid(exif_tags, y)

    @skip_if_no("jpegsave")
    @pytest.mark.xfail(raises=pyvips.error.Error, reason="requires libexif >= 0.6.23")
    def test_jpegsave_exif_2_3_ascii_2(self):
        def exif_valid(exif_tags, im):
            for exif_tag in exif_tags:
                assert im.get(exif_tag).find("ASCII, 14 components, 14 bytes") != -1

        # first make sure we have exif support
        im = pyvips.Image.new_from_file(JPEG_FILE)
        if im.get_typeof("exif-ifd0-Orientation") != 0:
            x = im.copy()
            exif_tags = [
                "exif-ifd2-OffsetTime",
                "exif-ifd2-OffsetTimeOriginal",
                "exif-ifd2-OffsetTimeDigitized",
                "exif-ifd3-GPSLatitudeRef",
                "exif-ifd3-GPSLongitudeRef",
                "exif-ifd3-GPSSatellites",
                "exif-ifd3-GPSStatus",
                "exif-ifd3-GPSMeasureMode",
                "exif-ifd3-GPSSpeedRef",
                "exif-ifd3-GPSTrackRef",
                "exif-ifd3-GPSImgDirectionRef",
                "exif-ifd3-GPSMapDatum",
                "exif-ifd3-GPSDestLatitudeRef",
                "exif-ifd3-GPSDestLongitudeRef",
                "exif-ifd3-GPSDestBearingRef",
                "exif-ifd3-GPSDestDistanceRef",
                "exif-ifd3-GPSDateStamp",
            ]
            for exif_tag in exif_tags:
                x.set_type(pyvips.GValue.gstr_type, exif_tag, "hello ( there")

            buf = x.jpegsave_buffer()
            y = pyvips.Image.new_from_buffer(buf, "")
            exif_valid(exif_tags, y)

    @skip_if_no("jpegload")
    def test_truncated(self):
        # This should open (there's enough there for the header)
        im = pyvips.Image.new_from_file(TRUNCATED_FILE)
        # but this should fail with a warning, and knock TRUNCATED_FILE out of
        # the cache
        x = im.avg()

        # now we should open again, but it won't come from cache, it'll reload
        im = pyvips.Image.new_from_file(TRUNCATED_FILE)
        # and this should fail with a warning once more
        x = im.avg()

    @skip_if_no("pngload")
    def test_png(self):
        def png_valid(im):
            a = im(10, 10)
            assert_almost_equal_objects(a, [38671.0, 33914.0, 26762.0])
            assert im.width == 290
            assert im.height == 442
            assert im.bands == 3
            assert im.get("bits-per-sample") == 16

        self.file_loader("pngload", PNG_FILE, png_valid)
        self.buffer_loader("pngload_buffer", PNG_FILE, png_valid)
        self.save_load_buffer("pngsave_buffer", "pngload_buffer", self.colour)
        self.save_load("%s.png", self.mono)
        self.save_load("%s.png", self.colour)
        self.save_load_file(".png", "[interlace]", self.colour)
        self.save_load_file(".png", "[interlace]", self.mono)

        # size of a regular mono PNG
        len_mono = len(self.mono.write_to_buffer(".png"))

        # 4-bit should be smaller
        len_mono4 = len(self.mono.write_to_buffer(".png", bitdepth=4))
        assert( len_mono4 < len_mono )

        len_mono2 = len(self.mono.write_to_buffer(".png", bitdepth=2))
        assert( len_mono2 < len_mono4 )

        len_mono1 = len(self.mono.write_to_buffer(".png", bitdepth=1))
        assert( len_mono1 < len_mono2 )

        # take a 1-bit image to png and back
        onebit = self.mono > 128
        data = onebit.write_to_buffer(".png", bitdepth=1)
        after = pyvips.Image.new_from_buffer(data, "")
        assert( (onebit - after).abs().max() == 0 )
        assert after.get("bits-per-sample") == 1

        # we can't test palette save since we can't be sure libimagequant is
        # available and there's no easy test for its presence

        # see if we have exif parsing: our test jpg image has this field
        x = pyvips.Image.new_from_file(JPEG_FILE)
        if x.get_typeof("exif-ifd0-Orientation") != 0:
            # we need a copy of the image to set the new metadata on
            # otherwise we get caching problems

            # can set, save and load new orientation
            x = pyvips.Image.new_from_file(JPEG_FILE)
            x = x.copy()

            x.set("orientation", 2)

            filename = temp_filename(self.tempdir, '.png')
            x.write_to_file(filename)

            x = pyvips.Image.new_from_file(filename)
            y = x.get("orientation")
            assert y == 2

        # Add EXIF to new PNG
        im1 = pyvips.Image.black(8, 8)
        im1.set_type(pyvips.GValue.gstr_type,
            "exif-ifd0-ImageDescription", "test description")
        im2 = pyvips.Image.new_from_buffer(
            im1.write_to_buffer(".png"), "")
        assert im2.get("exif-ifd0-ImageDescription").startswith("test description")

    @skip_if_no("tiffload")
    def test_tiff(self):
        def tiff_valid(im):
            a = im(10, 10)
            assert_almost_equal_objects(a, [38671.0, 33914.0, 26762.0])
            assert im.width == 290
            assert im.height == 442
            assert im.bands == 3
            assert im.get("bits-per-sample") == 16

        self.file_loader("tiffload", TIF_FILE, tiff_valid)
        self.buffer_loader("tiffload_buffer", TIF_FILE, tiff_valid)

        def tiff1_valid(im):
            a = im(127, 0)
            assert_almost_equal_objects(a, [0.0])
            a = im(128, 0)
            assert_almost_equal_objects(a, [255.0])
            assert im.width == 256
            assert im.height == 4
            assert im.bands == 1
            assert im.get("bits-per-sample") == 1

        self.file_loader("tiffload", TIF1_FILE, tiff1_valid)

        def tiff2_valid(im):
            a = im(127, 0)
            assert_almost_equal_objects(a, [85.0])
            a = im(128, 0)
            assert_almost_equal_objects(a, [170.0])
            assert im.width == 256
            assert im.height == 4
            assert im.bands == 1
            assert im.get("bits-per-sample") == 2

        self.file_loader("tiffload", TIF2_FILE, tiff2_valid)

        def tiff4_valid(im):
            a = im(127, 0)
            assert_almost_equal_objects(a, [119.0])
            a = im(128, 0)
            assert_almost_equal_objects(a, [136.0])
            assert im.width == 256
            assert im.height == 4
            assert im.bands == 1
            assert im.get("bits-per-sample") == 4

        self.file_loader("tiffload", TIF4_FILE, tiff4_valid)

        self.save_load_buffer("tiffsave_buffer", "tiffload_buffer", self.colour)
        self.save_load("%s.tif", self.mono)
        self.save_load("%s.tif", self.colour)
        self.save_load("%s.tif", self.cmyk)
        self.save_load("%s.tif", self.rgba)
        self.save_load("%s.tif", self.onebit)

        self.save_load_file(".tif", "[bitdepth=1]", self.onebit)
        self.save_load_file(".tif", "[miniswhite]", self.onebit)
        self.save_load_file(".tif", "[bitdepth=1,miniswhite]", self.onebit)

        self.save_load_file(".tif", f"[profile={SRGB_FILE}]", self.colour)
        self.save_load_file(".tif", "[tile]", self.colour)
        self.save_load_file(".tif", "[tile,pyramid]", self.colour)
        self.save_load_file(".tif", "[tile,pyramid,subifd]", self.colour)
        self.save_load_file(".tif",
                            "[tile,pyramid,compression=jpeg]", self.colour, 80)
        self.save_load_file(".tif",
                            "[tile,pyramid,subifd,compression=jpeg]",
                            self.colour, 80)
        self.save_load_file(".tif", "[bigtiff]", self.colour)
        self.save_load_file(".tif", "[compression=jpeg]", self.colour, 80)
        self.save_load_file(".tif",
                            "[tile,tile-width=256]", self.colour, 10)

        im = pyvips.Image.new_from_file(TIF2_FILE)
        self.save_load_file(".tif", "[bitdepth=2]", im)
        im = pyvips.Image.new_from_file(TIF4_FILE)
        self.save_load_file(".tif", "[bitdepth=4]", im)

        filename = temp_filename(self.tempdir, '.tif')
        self.colour.write_to_file(filename, pyramid=True, compression="jpeg")
        x = pyvips.Image.new_from_file(filename, page=2)
        assert x.width == 72
        assert abs(x.avg() - 117.3) < 1

        filename = temp_filename(self.tempdir, '.tif')
        self.colour.write_to_file(filename, pyramid=True, subifd=True, compression="jpeg")
        x = pyvips.Image.new_from_file(filename, subifd=1)
        assert x.width == 72
        assert abs(x.avg() - 117.3) < 1

        filename = temp_filename(self.tempdir, '.tif')
        x = pyvips.Image.new_from_file(TIF_FILE)
        x = x.copy()
        x.set("orientation", 2)
        x.write_to_file(filename)
        x = pyvips.Image.new_from_file(filename)
        y = x.get("orientation")
        assert y == 2

        filename = temp_filename(self.tempdir, '.tif')
        x = pyvips.Image.new_from_file(TIF_FILE)
        x = x.copy()
        x.set("orientation", 2)
        x.write_to_file(filename)
        x = pyvips.Image.new_from_file(filename)
        y = x.get("orientation")
        assert y == 2
        x = x.copy()
        x.remove("orientation")

        filename = temp_filename(self.tempdir, '.tif')
        x.write_to_file(filename)
        x = pyvips.Image.new_from_file(filename)
        y = x.get("orientation")
        assert y == 1

        filename = temp_filename(self.tempdir, '.tif')
        x = pyvips.Image.new_from_file(TIF_FILE)
        x = x.copy()
        x.set("orientation", 6)
        x.write_to_file(filename)
        x1 = pyvips.Image.new_from_file(filename)
        x2 = pyvips.Image.new_from_file(filename, autorotate=True)
        assert x1.width == x2.height
        assert x1.height == x2.width

        filename = temp_filename(self.tempdir, '.tif')
        x = pyvips.Image.new_from_file(TIF_FILE)
        x = x.copy()
        x.write_to_file(filename, xres=100, yres=200, resunit="cm")
        x1 = pyvips.Image.new_from_file(filename)
        assert x1.get("resolution-unit") == "cm"
        assert x1.xres == 100
        assert x1.yres == 200

        filename = temp_filename(self.tempdir, '.tif')
        x = pyvips.Image.new_from_file(TIF_FILE)
        x = x.copy()
        x.write_to_file(filename, xres=100, yres=200, resunit="inch")
        x1 = pyvips.Image.new_from_file(filename)
        assert x1.get("resolution-unit") == "in"
        assert x1.xres == 100
        assert x1.yres == 200

        # OME support in 8.5
        x = pyvips.Image.new_from_file(OME_FILE)
        assert x.width == 439
        assert x.height == 167
        page_height = x.height

        x = pyvips.Image.new_from_file(OME_FILE, n=-1)
        assert x.width == 439
        assert x.height == page_height * 15

        x = pyvips.Image.new_from_file(OME_FILE, page=1, n=-1)
        assert x.width == 439
        assert x.height == page_height * 14

        x = pyvips.Image.new_from_file(OME_FILE, page=1, n=2)
        assert x.width == 439
        assert x.height == page_height * 2

        x = pyvips.Image.new_from_file(OME_FILE, n=-1)
        assert x(0, 166)[0] == 96
        assert x(0, 167)[0] == 0
        assert x(0, 168)[0] == 1

        filename = temp_filename(self.tempdir, '.tif')
        x.write_to_file(filename)

        x = pyvips.Image.new_from_file(filename, n=-1)
        assert x.width == 439
        assert x.height == page_height * 15
        assert x(0, 166)[0] == 96
        assert x(0, 167)[0] == 0
        assert x(0, 168)[0] == 1

        # pyr save to buffer added in 8.6
        x = pyvips.Image.new_from_file(TIF_FILE)
        buf = x.tiffsave_buffer(tile=True, pyramid=True)
        filename = temp_filename(self.tempdir, '.tif')
        x.tiffsave(filename, tile=True, pyramid=True)
        with open(filename, 'rb') as f:
            buf2 = f.read()
        assert len(buf) == len(buf2)

        filename = temp_filename(self.tempdir, '.tif')
        self.rgba.write_to_file(filename, premultiply=True)
        a = pyvips.Image.new_from_file(filename)
        b = self.rgba.premultiply().cast("uchar").unpremultiply().cast("uchar")
        assert (a == b).min() == 255

        a = pyvips.Image.new_from_buffer(buf, "", page=2)
        b = pyvips.Image.new_from_buffer(buf2, "", page=2)
        assert a.width == b.width
        assert a.height == b.height
        assert (a == b).min() == 255

        # just 0/255 in each band, shrink with mode and all pixels should be 0
        # or 255 in layer 1
        x = pyvips.Image.new_from_file(TIF_FILE) > 128
        for shrink in ["mode", "median", "max", "min"]:
            buf = x.tiffsave_buffer(pyramid=True, region_shrink=shrink)
            y = pyvips.Image.new_from_buffer(buf, "", page=1)
            z = y.hist_find(band=0)
            assert z(0, 0)[0] + z(255, 0)[0] == y.width * y.height

    @skip_if_no("jp2kload")
    @skip_if_no("tiffload")
    def test_tiffjp2k(self):
        self.save_load_file(".tif", "[tile,compression=jp2k]", self.colour, 80)
        self.save_load_file(".tif",
                            "[tile,pyramid,compression=jp2k]", self.colour, 80)
        self.save_load_file(".tif",
                            "[tile,pyramid,subifd,compression=jp2k]",
                            self.colour, 80)

    @skip_if_no("magickload")
    def test_magickload(self):
        def bmp_valid(im):
            a = im(100, 100)

            assert_almost_equal_objects(a, [227, 216, 201])
            assert im.width == 1419
            assert im.height == 1001
            assert im.get("bits-per-sample") == 8

        self.file_loader("magickload", BMP_FILE, bmp_valid)
        self.buffer_loader("magickload_buffer", BMP_FILE, bmp_valid)

        # we should have rgb or rgba for svg files ... different versions of
        # IM handle this differently. GM even gives 1 band.
        im = pyvips.Image.magickload(SVG_FILE)
        assert im.bands == 3 or im.bands == 4 or im.bands == 1

        # density should change size of generated svg
        im = pyvips.Image.magickload(SVG_FILE, density='100')
        width = im.width
        height = im.height
        im = pyvips.Image.magickload(SVG_FILE, density='200')
        # This seems to fail on travis, no idea why, some problem in their IM
        # perhaps
        # assert im.width == width * 2
        # assert im.height == height * 2

        im = pyvips.Image.magickload(GIF_ANIM_FILE)
        width = im.width
        height = im.height
        im = pyvips.Image.magickload(GIF_ANIM_FILE, n=-1)
        assert im.width == width
        assert im.height == height * 5

        # page/n let you pick a range of pages
        # 'n' param added in 8.5
        if pyvips.at_least_libvips(8, 5):
            im = pyvips.Image.magickload(GIF_ANIM_FILE)
            width = im.width
            height = im.height
            im = pyvips.Image.magickload(GIF_ANIM_FILE, page=1, n=2)
            assert im.width == width
            assert im.height == height * 2
            page_height = im.get("page-height")
            assert page_height == height

        # should work for dicom
        im = pyvips.Image.magickload(DICOM_FILE)
        assert im.width == 128
        assert im.height == 128
        # some IMs are 3 bands, some are 1, can't really test
        # assert im.bands == 1

        # libvips has its own sniffer for ICO, test that
        with open(ICO_FILE, 'rb') as f:
            buf = f.read()

        im = pyvips.Image.new_from_buffer(buf, "")
        assert im.width == 16
        assert im.height == 16

        # libvips has its own sniffer for CUR, test that
        with open(CUR_FILE, 'rb') as f:
            buf = f.read()

        im = pyvips.Image.new_from_buffer(buf, "")
        assert im.width == 32
        assert im.height == 32

        # libvips has its own sniffer for TGA, test that
        with open(TGA_FILE, 'rb') as f:
            buf = f.read()
        im = pyvips.Image.new_from_buffer(buf, "")
        assert im.width == 433
        assert im.height == 433

        # Test SGI/RGB files to sanity check that sniffers
        # aren't too broad
        with open(SGI_FILE, 'rb') as f:
            buf = f.read()
        im = pyvips.Image.new_from_buffer(buf, "")
        assert im.width == 433
        assert im.height == 433


        # load should see metadata like eg. icc profiles
        im = pyvips.Image.magickload(JPEG_FILE)
        assert len(im.get("icc-profile-data")) == 564

    # added in 8.7
    @skip_if_no("magicksave")
    def test_magicksave(self):
        # save to a file and load again ... we can't use save_load_file since
        # we want to make sure we use magickload/save
        # don't use BMP - GraphicsMagick always adds an alpha
        # don't use TIF - IM7 will save as 16-bit
        filename = temp_filename(self.tempdir, ".jpg")

        self.colour.magicksave(filename)
        x = pyvips.Image.magickload(filename)

        assert self.colour.width == x.width
        assert self.colour.height == x.height
        assert self.colour.bands == x.bands
        max_diff = (self.colour - x).abs().max()
        assert max_diff < 60
        assert len(x.get("icc-profile-data")) == 564

        self.save_load_buffer("magicksave_buffer", "magickload_buffer",
                              self.colour, 60, format="JPG")

        # try an animation
        if have("gifload"):
            x1 = pyvips.Image.new_from_file(GIF_ANIM_FILE, n=-1)
            w1 = x1.magicksave_buffer(format="GIF")
            x2 = pyvips.Image.new_from_buffer(w1, "", n=-1)
            assert x1.get("delay") == x2.get("delay")
            assert x1.get("page-height") == x2.get("page-height")
            # magicks vary in how they handle this ... just pray we are close
            assert abs(x1.get("gif-loop") - x2.get("gif-loop")) < 5

    @skip_if_no("webpload")
    def test_webp(self):
        def webp_valid(im):
            a = im(10, 10)
            # different webp versions use different rounding systems leading
            # to small variations
            assert_almost_equal_objects(a, [71, 166, 236], threshold=2)
            assert im.width == 550
            assert im.height == 368
            assert im.bands == 3

        self.file_loader("webpload", WEBP_FILE, webp_valid)
        self.buffer_loader("webpload_buffer", WEBP_FILE, webp_valid)
        self.save_load_buffer("webpsave_buffer", "webpload_buffer",
                              self.colour, 60)
        self.save_load("%s.webp", self.colour)

        # test lossless mode
        im = pyvips.Image.new_from_file(WEBP_FILE)
        buf = im.webpsave_buffer(lossless=True)
        im2 = pyvips.Image.new_from_buffer(buf, "")
        assert abs(im.avg() - im2.avg()) < 1

        # higher Q should mean a bigger buffer
        b1 = im.webpsave_buffer(Q=10)
        b2 = im.webpsave_buffer(Q=90)
        assert len(b2) > len(b1)

        # try saving an image with an ICC profile and reading it back ... if we
        # can do it, our webp supports metadata load/save
        buf = self.colour.webpsave_buffer()
        im = pyvips.Image.new_from_buffer(buf, "")
        if im.get_typeof("icc-profile-data") != 0:
            # verify that the profile comes back unharmed
            p1 = self.colour.get("icc-profile-data")
            p2 = im.get("icc-profile-data")
            assert p1 == p2

            # add tests for exif, xmp, ipct
            # the exif test will need us to be able to walk the header,
            # we can't just check exif-data

            # we can test that exif changes change the output of webpsave
            # first make sure we have exif support
            z = pyvips.Image.new_from_file(JPEG_FILE)
            if z.get_typeof("exif-ifd0-Orientation") != 0:
                x = self.colour.copy()
                x.set("orientation", 6)
                buf = x.webpsave_buffer()
                y = pyvips.Image.new_from_buffer(buf, "")
                assert y.get("orientation") == 6

        # try converting an animated gif to webp
        if have("gifload"):
            x1 = pyvips.Image.new_from_file(GIF_ANIM_FILE, n=-1)
            w1 = x1.webpsave_buffer(Q=10)

            # our test gif has delay 0 for the first frame set in error,
            # when converting to WebP this should result in a 100ms delay.
            expected_delay = [100 if d <= 10 else d for d in x1.get("delay")]

            x2 = pyvips.Image.new_from_buffer(w1, "", n=-1)
            assert x1.width == x2.width
            assert x1.height == x2.height
            assert expected_delay == x2.get("delay")
            assert x1.get("page-height") == x2.get("page-height")
            assert x1.get("gif-loop") == x2.get("gif-loop")

        # WebP image that happens to contain the string "<svg"
        if have("svgload"):
            x = pyvips.Image.new_from_file(WEBP_LOOKS_LIKE_SVG_FILE)
            assert x.get("vips-loader") == "webpload"

        # Animated WebP roundtrip
        x = pyvips.Image.new_from_file(WEBP_ANIMATED_FILE, n=-1)
        assert x.width == 13
        assert x.height == 16393
        buf = x.webpsave_buffer()

    @skip_if_no("analyzeload")
    def test_analyzeload(self):
        def analyze_valid(im):
            a = im(10, 10)
            assert pytest.approx(a[0]) == 3335
            assert im.width == 128
            assert im.height == 8064
            assert im.bands == 1

        self.file_loader("analyzeload", ANALYZE_FILE, analyze_valid)

    @skip_if_no("matload")
    def test_matload(self):
        def matlab_valid(im):
            a = im(10, 10)
            assert_almost_equal_objects(a, [38671.0, 33914.0, 26762.0])
            assert im.width == 290
            assert im.height == 442
            assert im.bands == 3

        self.file_loader("matload", MATLAB_FILE, matlab_valid)

    @skip_if_no("openexrload")
    def test_openexrload(self):
        def exr_valid(im):
            a = im(10, 10)
            assert_almost_equal_objects(a, [0.124512, 0.159668, 0.040375,
                                            1.0],
                                        threshold=0.00001)
            assert im.width == 610
            assert im.height == 406
            assert im.bands == 4

        self.file_loader("openexrload", EXR_FILE, exr_valid)

    @skip_if_no("fitsload")
    def test_fitsload(self):
        def fits_valid(im):
            a = im(10, 10)
            assert_almost_equal_objects(a, [-0.165013, -0.148553, 1.09122,
                                            -0.942242], threshold=0.00001)
            assert im.width == 200
            assert im.height == 200
            assert im.bands == 4

        self.file_loader("fitsload", FITS_FILE, fits_valid)
        self.save_load("%s.fits", self.mono)

    @skip_if_no("niftiload")
    def test_niftiload(self):
        def nifti_valid(im):
            a = im(30, 26)
            assert_almost_equal_objects(a, [131])
            assert im.width == 91
            assert im.height == 9919
            assert im.bands == 1

        self.file_loader("niftiload", NIFTI_FILE, nifti_valid)
        self.save_load("%s.nii.gz", self.mono)

    @skip_if_no("openslideload")
    def test_openslideload(self):
        def openslide_valid(im):
            a = im(10, 10)
            assert_almost_equal_objects(a, [244, 250, 243, 255])
            assert im.width == 2220
            assert im.height == 2967
            assert im.bands == 4

        self.file_loader("openslideload", OPENSLIDE_FILE, openslide_valid)

        source = pyvips.Source.new_from_file(OPENSLIDE_FILE)
        x = pyvips.Image.new_from_source(source, "")
        openslide_valid(x)

    @skip_if_no("pdfload")
    def test_pdfload(self):
        def pdf_valid(im):
            a = im(10, 10)
            assert_almost_equal_objects(a, [35, 31, 32, 255])
            assert im.width == 1134
            assert im.height == 680
            assert im.bands == 4

        self.file_loader("pdfload", PDF_FILE, pdf_valid)
        self.buffer_loader("pdfload_buffer", PDF_FILE, pdf_valid)

        im = pyvips.Image.new_from_file(PDF_FILE)
        x = pyvips.Image.new_from_file(PDF_FILE, scale=2)
        assert abs(im.width * 2 - x.width) < 2
        assert abs(im.height * 2 - x.height) < 2

        im = pyvips.Image.new_from_file(PDF_FILE)
        x = pyvips.Image.new_from_file(PDF_FILE, dpi=144)
        assert abs(im.width * 2 - x.width) < 2
        assert abs(im.height * 2 - x.height) < 2

    @skip_if_no("gifload")
    def test_gifload(self):
        def gif_valid(im):
            a = im(10, 10)
            assert_almost_equal_objects(a, [33, 33, 33, 255])
            assert im.width == 159
            assert im.height == 203
            assert im.bands == 3

        self.file_loader("gifload", GIF_FILE, gif_valid)
        self.buffer_loader("gifload_buffer", GIF_FILE, gif_valid)

        # test metadata
        x2 = pyvips.Image.new_from_file(GIF_FILE, n=-1)
        assert x2.get("n-pages") == 1
        assert x2.get("background") == [81, 81, 81]
        assert x2.get("interlaced") == 1
        assert x2.get("bits-per-sample") == 4

        x2 = pyvips.Image.new_from_file(GIF_ANIM_FILE, n=-1)
        # our test gif has delay 0 for the first frame set in error
        assert x2.get("delay") == [0, 50, 50, 50, 50]
        assert x2.get("loop") == 32761
        assert x2.get("background") == [255, 255, 255]
        assert x2.get_typeof("interlaced") == 0
        # test deprecated fields too
        assert x2.get("gif-loop") == 32760
        assert x2.get("gif-delay") == 0

        # test every pixel
        x1 = pyvips.Image.new_from_file(GIF_ANIM_FILE, n=-1)
        x2 = pyvips.Image.new_from_file(GIF_ANIM_EXPECTED_PNG_FILE)
        assert (x1 - x2).abs().max() == 0

        # test page handling
        x1 = pyvips.Image.new_from_file(GIF_ANIM_FILE)
        x2 = pyvips.Image.new_from_file(GIF_ANIM_FILE, n=2)
        assert x2.height == 2 * x1.height
        page_height = x2.get("page-height")
        assert page_height == x1.height

        x2 = pyvips.Image.new_from_file(GIF_ANIM_FILE, n=-1)
        assert x2.height == 5 * x1.height

        x2 = pyvips.Image.new_from_file(GIF_ANIM_FILE, page=1, n=-1)
        assert x2.height == 4 * x1.height

    @skip_if_no("gifload")
    def test_gifload_animation_dispose_background(self):
        x1 = pyvips.Image.new_from_file(GIF_ANIM_DISPOSE_BACKGROUND_FILE, n=-1)
        x2 = pyvips.Image.new_from_file(GIF_ANIM_DISPOSE_BACKGROUND_EXPECTED_PNG_FILE)
        assert (x1 - x2).abs().max() == 0

    @skip_if_no("gifload")
    def test_gifload_animation_dispose_previous(self):
        x1 = pyvips.Image.new_from_file(GIF_ANIM_DISPOSE_PREVIOUS_FILE, n=-1)
        x2 = pyvips.Image.new_from_file(GIF_ANIM_DISPOSE_PREVIOUS_EXPECTED_PNG_FILE)
        assert (x1 - x2).abs().max() == 0

    @skip_if_no("gifload")
    def test_gifload_truncated(self):
        # should load with just a warning
        truncated_gif = os.path.join(IMAGES, "truncated.gif")
        im = pyvips.Image.new_from_file(truncated_gif)
        assert im.width == 575

        # should fail on truncation and warning
        with pytest.raises(Exception):
            im = pyvips.Image.new_from_file(truncated_gif, fail_on="warning")
        with pytest.raises(Exception):
            im = pyvips.Image.new_from_file(truncated_gif, fail_on="truncated")

    @skip_if_no("gifload")
    def test_gifload_frame_error(self):
        # should load with just a warning
        truncated_gif = os.path.join(IMAGES, "garden.gif")
        im = pyvips.Image.new_from_file(truncated_gif)
        assert im.width == 800

        # should fail on warning only
        im = pyvips.Image.new_from_file(truncated_gif, fail_on="truncated")
        assert im.width == 800
        with pytest.raises(Exception):
            im = pyvips.Image.new_from_file(truncated_gif, fail_on="warning")

    @skip_if_no("svgload")
    def test_svgload(self):
        def svg_valid(im):
            a = im(10, 10)
            assert_almost_equal_objects(a, [0, 0, 0, 0])
            assert im.width == 736
            assert im.height == 552
            assert im.bands == 4

        self.file_loader("svgload", SVG_FILE, svg_valid)
        self.buffer_loader("svgload_buffer", SVG_FILE, svg_valid)

        self.file_loader("svgload", SVGZ_FILE, svg_valid)
        self.buffer_loader("svgload_buffer", SVGZ_FILE, svg_valid)

        self.file_loader("svgload", SVG_GZ_FILE, svg_valid)

        im = pyvips.Image.new_from_file(SVG_FILE)
        x = pyvips.Image.new_from_file(SVG_FILE, scale=2)
        assert abs(im.width * 2 - x.width) < 2
        assert abs(im.height * 2 - x.height) < 2

        im = pyvips.Image.new_from_file(SVG_FILE)
        x = pyvips.Image.new_from_file(SVG_FILE, dpi=144)
        assert abs(im.width * 2 - x.width) < 2
        assert abs(im.height * 2 - x.height) < 2

        with pytest.raises(pyvips.error.Error):
            svg = b'<svg xmlns="http://www.w3.org/2000/svg" width="0" height="0"></svg>'
            im = pyvips.Image.new_from_buffer(svg, "")

        # recognize dimensions for SVGs without width/height
        svg = b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"></svg>'
        im = pyvips.Image.new_from_buffer(svg, "")
        assert im.width == 100
        assert im.height == 100

        svg = b'<svg xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" /></svg>'
        im = pyvips.Image.new_from_buffer(svg, "")
        assert im.width == 100
        assert im.height == 100

        # width and height of 0.5 is valid
        svg = b'<svg xmlns="http://www.w3.org/2000/svg" width="0.5" height="0.5"></svg>'
        im = pyvips.Image.new_from_buffer(svg, "")
        assert im.width == 1
        assert im.height == 1

        # scale up
        svg = b'<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"></svg>'
        im = pyvips.Image.new_from_buffer(svg, "", scale=10000)
        assert im.width == 10000
        assert im.height == 10000

        # scale down
        svg = b'<svg xmlns="http://www.w3.org/2000/svg" width="100000" height="100000"></svg>'
        im = pyvips.Image.new_from_buffer(svg, "", scale=0.0001)
        assert im.width == 10
        assert im.height == 10

    def test_csv(self):
        self.save_load("%s.csv", self.mono)

    def test_matrix(self):
        self.save_load("%s.mat", self.mono)

    @skip_if_no("ppmload")
    def test_ppm(self):
        self.save_load("%s.ppm", self.mono)
        self.save_load("%s.ppm", self.colour)

        self.save_load_file("%s.ppm", "[ascii]", self.mono, 0)
        self.save_load_file("%s.ppm", "[ascii]", self.colour, 0)

        self.save_load_file("%s.ppm", "[ascii,bitdepth=1]", self.onebit, 0)

        rgb16 = self.colour.colourspace("rgb16")
        grey16 = self.mono.colourspace("rgb16")

        self.save_load("%s.ppm", grey16)
        self.save_load("%s.ppm", rgb16)

        self.save_load_file("%s.ppm", "[ascii]", grey16, 0)
        self.save_load_file("%s.ppm", "[ascii]", rgb16, 0)

        source = pyvips.Source.new_from_memory(b'P1\n#\n#\n1 1\n0\n')
        im = pyvips.Image.ppmload_source(source)
        assert im.height == 1
        assert im.width == 1

    @skip_if_no("radload")
    def test_rad(self):
        self.save_load("%s.hdr", self.colour)
        self.save_buffer_tempfile("radsave_buffer", ".hdr",
                                  self.rad, max_diff=0)

    @skip_if_no("dzsave")
    def test_dzsave(self):
        # dzsave is hard to test, there are so many options
        # test each option separately and hope they all function together
        # correctly

        # default deepzoom layout ... we must use png here, since we want to
        # test the overlap for equality
        filename = temp_filename(self.tempdir, '')
        self.colour.dzsave(filename, suffix=".png")

        # test horizontal overlap ... expect 256 step, overlap 1
        x = pyvips.Image.new_from_file(filename + "_files/9/0_0.png")
        assert x.width == 255
        y = pyvips.Image.new_from_file(filename + "_files/9/1_0.png")
        assert y.width == 37

        # the right two columns of x should equal the left two columns of y
        left = x.crop(x.width - 2, 0, 2, x.height)
        right = y.crop(0, 0, 2, y.height)
        assert (left - right).abs().max() == 0

        # test vertical overlap
        assert x.height == 255
        y = pyvips.Image.new_from_file(filename + "_files/9/0_1.png")
        assert y.height == 189

        # the bottom two rows of x should equal the top two rows of y
        top = x.crop(0, x.height - 2, x.width, 2)
        bottom = y.crop(0, 0, y.width, 2)
        assert (top - bottom).abs().max() == 0

        # there should be a bottom layer
        x = pyvips.Image.new_from_file(filename + "_files/0/0_0.png")
        assert x.width == 1
        assert x.height == 1

        # 9 should be the final layer
        assert not os.path.isdir(filename + "_files/10")

        # default google layout
        filename = temp_filename(self.tempdir, '')
        self.colour.dzsave(filename, layout="google")

        # test bottom-right tile ... default is 256x256 tiles, overlap 0
        x = pyvips.Image.new_from_file(filename + "/1/1/1.jpg")
        assert x.width == 256
        assert x.height == 256
        assert not os.path.exists(filename + "/1/1/2.jpg")
        assert not os.path.exists(filename + "/2")
        x = pyvips.Image.new_from_file(filename + "/blank.png")
        assert x.width == 256
        assert x.height == 256

        # google layout with overlap ... verify that we clip correctly

        # overlap 1, 510x510 pixels, 256 pixel tiles, should be exactly 2x2
        # tiles, though in fact the bottom and right edges will be white
        filename = temp_filename(self.tempdir, '')
        self.colour \
            .replicate(2, 2) \
            .crop(0, 0, 510, 510) \
            .dzsave(filename, layout="google", overlap=1, depth="one")

        x = pyvips.Image.new_from_file(filename + "/0/1/1.jpg")
        assert x.width == 256
        assert x.height == 256
        assert not os.path.exists(filename + "/0/2/2.jpg")

        # with 511x511, it'll fit exactly into 2x2 -- we we actually generate
        # 3x3, since we output the overlaps
        filename = temp_filename(self.tempdir, '')
        self.colour \
            .replicate(2, 2) \
            .crop(0, 0, 511, 511) \
            .dzsave(filename, layout="google", overlap=1, depth="one")

        x = pyvips.Image.new_from_file(filename + "/0/2/2.jpg")
        assert x.width == 256
        assert x.height == 256
        assert not os.path.exists(filename + "/0/3/3.jpg")

        # default zoomify layout
        filename = temp_filename(self.tempdir, '')
        self.colour.dzsave(filename, layout="zoomify")

        # 256x256 tiles, no overlap
        assert os.path.exists(filename + "/ImageProperties.xml")
        x = pyvips.Image.new_from_file(filename + "/TileGroup0/1-0-0.jpg")
        assert x.width == 256
        assert x.height == 256

        # test zip output
        filename = temp_filename(self.tempdir, '.zip')
        self.colour.dzsave(filename)
        assert os.path.exists(filename)
        assert not os.path.exists(filename + "_files")
        assert not os.path.exists(filename + ".dzi")

        # test compressed zip output
        filename2 = temp_filename(self.tempdir, '.zip')
        self.colour.dzsave(filename2, compression=-1)
        assert os.path.exists(filename2)
        with open(filename, 'rb') as f:
            buf1 = f.read()
        with open(filename2, 'rb') as f:
            buf2 = f.read()
        # compressed output should produce smaller file size
        assert len(buf2) < len(buf1)
        # check whether the *.dzi file is Deflate-compressed
        assert buf1.find(b'http://schemas.microsoft.com/deepzoom/2008') != -1
        assert buf2.find(b'http://schemas.microsoft.com/deepzoom/2008') == -1

        # test suffix
        filename = temp_filename(self.tempdir, '')
        self.colour.dzsave(filename, suffix=".png")

        x = pyvips.Image.new_from_file(filename + "_files/9/0_0.png")
        assert x.width == 255

        # test overlap
        filename = temp_filename(self.tempdir, '')
        self.colour.dzsave(filename, overlap=200)

        y = pyvips.Image.new_from_file(filename + "_files/9/1_1.jpeg")
        assert y.width == 236

        # test tile-size
        filename = temp_filename(self.tempdir, '')
        self.colour.dzsave(filename, tile_size=512)

        y = pyvips.Image.new_from_file(filename + "_files/9/0_0.jpeg")
        assert y.width == 290
        assert y.height == 442

        # test save to memory buffer
        filename = temp_filename(self.tempdir, '.zip')
        base = os.path.basename(filename)
        root, ext = os.path.splitext(base)

        self.colour.dzsave(filename)
        with open(filename, 'rb') as f:
            buf1 = f.read()
        buf2 = self.colour.dzsave_buffer(basename=root)
        assert len(buf1) == len(buf2)

        # we can't test the bytes are exactly equal -- the timestamp in
        # vips-properties.xml will be different

        # added in 8.7
        buf = self.colour.dzsave_buffer(region_shrink="mean")
        buf = self.colour.dzsave_buffer(region_shrink="mode")
        buf = self.colour.dzsave_buffer(region_shrink="median")

        # test keep=pyvips.ForeignKeep.ICC ... icc profiles should be
        # passed down
        filename = temp_filename(self.tempdir, '')
        self.colour.dzsave(filename, keep=1 << 3) # pyvips.ForeignKeep.ICC - https://github.com/libvips/pyvips/pull/429

        y = pyvips.Image.new_from_file(filename + "_files/0/0_0.jpeg")
        assert y.get_typeof("icc-profile-data") != 0

    @skip_if_no("heifload")
    def test_heifload(self):
        def heif_valid(im):
            a = im(10, 10)
            # different versions of libheif decode have slightly different
            # rounding
            assert_almost_equal_objects(a, [197.0, 181.0, 158.0], threshold=2)
            assert im.width == 3024
            assert im.height == 4032
            assert im.bands == 3

        self.file_loader("heifload", AVIF_FILE, heif_valid)
        self.buffer_loader("heifload_buffer", AVIF_FILE, heif_valid)

        with pytest.raises(Exception) as e_info:
            im = pyvips.Image.heifload(AVIF_FILE_HUGE)
            assert im.avg() == 0.0

        im = pyvips.Image.heifload(AVIF_FILE_HUGE, unlimited=True)
        assert im.avg() == 0.0

    @skip_if_no("heifsave")
    @pytest.mark.skipif(sys.platform == "darwin", reason="fails with latest libheif/aom from Homebrew")
    def test_avifsave(self):
        # TODO: Reduce the threshold once https://github.com/strukturag/libheif/issues/533 is resolved.
        self.save_load_buffer("heifsave_buffer", "heifload_buffer",
                              self.colour, 80, compression="av1",
                              lossless=True)
        self.save_load("%s.avif", self.colour)

    @skip_if_no("heifsave")
    @pytest.mark.skipif(sys.platform == "darwin", reason="fails with latest libheif/aom from Homebrew")
    @pytest.mark.skip()
    def test_avifsave_lossless(self):
        # this takes FOREVER
        im = pyvips.Image.new_from_file(AVIF_FILE)
        buf = im.heifsave_buffer(lossless=True, compression="av1")
        im2 = pyvips.Image.new_from_buffer(buf, "")
        # not in fact quite lossless
        assert abs(im.avg() - im2.avg()) < 3

    @skip_if_no("heifsave")
    @pytest.mark.skipif(sys.platform == "darwin", reason="fails with latest libheif/aom from Homebrew")
    def test_avifsave_Q(self):
        # higher Q should mean a bigger buffer, needs libheif >= v1.8.0,
        # see: https://github.com/libvips/libvips/issues/1757
        b1 = self.mono.heifsave_buffer(Q=10, compression="av1")
        b2 = self.mono.heifsave_buffer(Q=90, compression="av1")
        assert len(b2) > len(b1)

    @skip_if_no("heifsave")
    @pytest.mark.skipif(sys.platform == "darwin", reason="fails with latest libheif/aom from Homebrew")
    def test_avifsave_chroma(self):
        # Chroma subsampling should produce smaller file size for same Q
        b1 = self.colour.heifsave_buffer(compression="av1", subsample_mode="on")
        b2 = self.colour.heifsave_buffer(compression="av1", subsample_mode="off")
        assert len(b2) > len(b1)

    @skip_if_no("heifsave")
    @pytest.mark.skipif(sys.platform == "darwin", reason="fails with latest libheif/aom from Homebrew")
    def test_avifsave_icc(self):
        # try saving an image with an ICC profile and reading it back
        # not all libheif have profile support, so put it in an if
        buf = self.colour.heifsave_buffer(Q=10, compression="av1")
        im = pyvips.Image.new_from_buffer(buf, "")
        p1 = self.colour.get("icc-profile-data")
        if im.get_typeof("icc-profile-data") != 0:
            p2 = im.get("icc-profile-data")
            assert p1 == p2

        # add tests for xmp, ipct
        # the exif test will need us to be able to walk the header,
        # we can't just check exif-data

    @skip_if_no("heifsave")
    @pytest.mark.skipif(sys.platform == "darwin", reason="fails with latest libheif/aom from Homebrew")
    def test_avifsave_exif(self):
        # first make sure we have exif support
        x = pyvips.Image.new_from_file(JPEG_FILE)
        if x.get_typeof("exif-ifd0-Orientation") != 0:
            x = x.copy()
            x.set_type(pyvips.GValue.gstr_type, "exif-ifd0-XPComment", "banana")
            buf = x.heifsave_buffer(Q=10, compression="av1")
            y = pyvips.Image.new_from_buffer(buf, "")
            assert y.get("exif-ifd0-XPComment").startswith("banana")

    @skip_if_no("heifsave")
    @pytest.mark.skipif(sys.platform == "darwin", reason="fails with latest libheif/aom from Homebrew")
    def test_heicsave_16_to_12(self):
        rgb16 = self.colour.colourspace("rgb16")
        data = rgb16.heifsave_buffer(lossless=True)
        im = pyvips.Image.heifload_buffer(data)

        assert(im.width == rgb16.width)
        assert(im.format == rgb16.format)
        assert(im.interpretation == rgb16.interpretation)
        assert(im.get("bits-per-sample") == 12)
        # good grief, some kind of lossless
        assert((im - rgb16).abs().max() < 4500)

    @skip_if_no("heifsave")
    @pytest.mark.skipif(sys.platform == "darwin", reason="fails with latest libheif/aom from Homebrew")
    def test_heicsave_16_to_8(self):
        rgb16 = self.colour.colourspace("rgb16")
        data = rgb16.heifsave_buffer(lossless=True, bitdepth=8)
        im = pyvips.Image.heifload_buffer(data)

        assert(im.width == rgb16.width)
        assert(im.format == "uchar")
        assert(im.interpretation == "srgb")
        assert(im.get("bits-per-sample") == 8)
        # good grief, some kind of lossless
        assert((im - rgb16 / 256).abs().max() < 80)

    @skip_if_no("heifsave")
    @pytest.mark.skipif(sys.platform == "darwin", reason="fails with latest libheif/aom from Homebrew")
    def test_heicsave_8_to_16(self):
        data = self.colour.heifsave_buffer(lossless=True, bitdepth=12)
        im = pyvips.Image.heifload_buffer(data)

        assert(im.width == self.colour.width)
        assert(im.format == "ushort")
        assert(im.interpretation == "rgb16")
        assert(im.get("bits-per-sample") == 12)
        # good grief, some kind of lossless
        assert((im - self.colour * 256).abs().max() < 4500)

    @skip_if_no("jp2kload")
    def test_jp2kload(self):
        def jp2k_valid(im):
            a = im(402, 73)
            assert_almost_equal_objects(a, [141, 144, 73], threshold=2)
            assert im.width == 800
            assert im.height == 400
            assert im.bands == 3
            assert im.get("bits-per-sample") == 8

        self.file_loader("jp2kload", JP2K_FILE, jp2k_valid)
        self.buffer_loader("jp2kload_buffer", JP2K_FILE, jp2k_valid)

    @skip_if_no("jp2ksave")
    def test_jp2ksave(self):
        self.save_load_buffer("jp2ksave_buffer", "jp2kload_buffer",
                              self.colour, 80)

        buf = self.colour.jp2ksave_buffer(lossless=True)
        im2 = pyvips.Image.new_from_buffer(buf, "")
        assert (self.colour == im2).min() == 255

        # higher Q should mean a bigger buffer
        b1 = self.mono.jp2ksave_buffer(Q=10)
        b2 = self.mono.jp2ksave_buffer(Q=90)
        assert len(b2) > len(b1)

        # disabling chroma subsample should mean a bigger buffer
        b1 = self.colour.jp2ksave_buffer(subsample_mode="on")
        b2 = self.colour.jp2ksave_buffer(subsample_mode="off")
        assert len(b2) > len(b1)

        # enabling lossless should mean a bigger buffer
        b1 = self.colour.jp2ksave_buffer(lossless=False)
        b2 = self.colour.jp2ksave_buffer(lossless=True)
        assert len(b2) > len(b1)

        # 16-bit colour load and save
        im = self.colour.colourspace("rgb16")
        buf = im.jp2ksave_buffer(lossless=True)
        im2 = pyvips.Image.new_from_buffer(buf, "")
        assert (im == im2).min() == 255
        assert im2.get("bits-per-sample") == 16

        # openjpeg 32-bit load and save doesn't seem to work, comment out
        # im = self.colour.colourspace("rgb16").cast("uint") << 14
        # buf = im.jp2ksave_buffer(lossless=True)
        # im2 = pyvips.Image.new_from_buffer(buf, "")
        # assert (im == im2).min() == 255

    @skip_if_no("jxlsave")
    def test_jxlsave(self):
        # save and load with an icc profile
        self.save_load_buffer("jxlsave_buffer", "jxlload_buffer",
                              self.colour, 130)

        # with no icc profile
        no_profile = self.colour.copy()
        no_profile.remove("icc-profile-data")
        self.save_load_buffer("jxlsave_buffer", "jxlload_buffer",
                              no_profile, 120)

        # scrgb mode
        scrgb = self.colour.colourspace("scrgb")
        self.save_load_buffer("jxlsave_buffer", "jxlload_buffer",
                              scrgb, 120)

        # scrgb mode, no profile
        scrgb_no_profile = scrgb.copy()
        scrgb_no_profile.remove("icc-profile-data")
        self.save_load_buffer("jxlsave_buffer", "jxlload_buffer",
                              scrgb_no_profile, 120)

        # 16-bit mode
        rgb16 = self.colour.colourspace("rgb16").copy()
        # remove the ICC profile: the RGB one will no longer be appropriate
        rgb16.remove("icc-profile-data")
        self.save_load_buffer("jxlsave_buffer", "jxlload_buffer",
                              rgb16, 12000)

        # repeat for lossless mode
        self.save_load_buffer("jxlsave_buffer", "jxlload_buffer",
                              self.colour, 0, lossless=True)
        self.save_load_buffer("jxlsave_buffer", "jxlload_buffer",
                              no_profile, 0, lossless=True)
        self.save_load_buffer("jxlsave_buffer", "jxlload_buffer",
                              scrgb, 0, lossless=True)
        self.save_load_buffer("jxlsave_buffer", "jxlload_buffer",
                              scrgb_no_profile, 0, lossless=True)

        # lossy should be much smaller than lossless
        lossy = self.colour.jxlsave_buffer()
        lossless = self.colour.jxlsave_buffer(lossless=True)
        assert len(lossy) < len(lossless) / 5

    @skip_if_no("gifsave")
    def test_gifsave(self):
        # Animated GIF round trip
        x1 = pyvips.Image.new_from_file(GIF_ANIM_FILE, n=-1)
        b1 = x1.gifsave_buffer()
        x2 = pyvips.Image.new_from_buffer(b1, "", n=-1)
        assert x1.width == x2.width
        assert x1.height == x2.height
        assert x1.get("n-pages") == x2.get("n-pages")
        assert x1.get("delay") == x2.get("delay")
        assert x1.get("page-height") == x2.get("page-height")
        # FIXME ... this requires cgif0.3 or later for fixed loop support
        # assert x1.get("loop") == x2.get("loop")

        # Interlaced write
        x1 = pyvips.Image.new_from_file(GIF_FILE, n=-1)
        b1 = x1.gifsave_buffer(interlace=False)
        b2 = x1.gifsave_buffer(interlace=True)
        # Interlaced GIFs are usually larger in file size
        # FIXME ... cgif v0.3 or later required for interlaced write.
        # If interlaced write is not supported b2 and b1 are expected to be
        # of the same file size.
        assert len(b2) >= len(b1)

        # Reducing dither will typically reduce file size (and quality)
        little_dither = self.colour.gifsave_buffer(dither=0.1, effort=1)
        large_dither = self.colour.gifsave_buffer(dither=0.9, effort=1)
        assert len(little_dither) < len(large_dither)

        # Reducing effort will typically increase file size (and reduce quality)
        # quantizr does not yet implement effort, so use >=
        little_effort = self.colour.gifsave_buffer(effort=1)
        large_effort = self.colour.gifsave_buffer(effort=10)
        assert len(little_effort) >= len(large_effort)

        # Reducing bitdepth will typically reduce file size (and reduce quality)
        bitdepth8 = self.colour.gifsave_buffer(bitdepth=8,effort=1)
        bitdepth7 = self.colour.gifsave_buffer(bitdepth=7,effort=1)
        assert len(bitdepth8) > len(bitdepth7)

        if have("webpload"):
            # Animated WebP to GIF
            x1 = pyvips.Image.new_from_file(WEBP_ANIMATED_FILE, n=-1)
            b1 = x1.gifsave_buffer()
            x2 = pyvips.Image.new_from_buffer(b1, "", n=-1)
            assert x1.width == x2.width
            assert x1.height == x2.height
            assert x1.get("n-pages") == x2.get("n-pages")
            assert x1.get("delay") == x2.get("delay")
            assert x1.get("page-height") == x2.get("page-height")
            assert x1.get("loop") == x2.get("loop")

    def test_fail_on(self):
        # csvload should spot trunc correctly
        target = pyvips.Target.new_to_memory()
        self.mono.write_to_target(target, ".csv")
        buf = target.get("blob")

        source = pyvips.Source.new_from_memory(buf)
        im = pyvips.Image.csvload_source(source)
        assert im.avg() > 0

        # truncation should be OK by default
        buf_trunc = buf[:-100]
        source = pyvips.Source.new_from_memory(buf_trunc)
        im = pyvips.Image.csvload_source(source)
        assert im.avg() > 0

        # set trunc should make it fail
        with pytest.raises(Exception) as e_info:
            im = pyvips.Image.csvload_source(source, fail_on="truncated")
            # this will now force parsing of the whole file, which should
            # trigger an error
            im.avg() > 0

        # warn should fail too, since trunc implies warn
        with pytest.raises(Exception) as e_info:
            im = pyvips.Image.csvload_source(source, fail_on="warning")
            im.avg() > 0

if __name__ == '__main__':
    pytest.main()
