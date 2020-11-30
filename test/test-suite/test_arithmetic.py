# vim: set fileencoding=utf-8 :

import math
import pytest

import pyvips
from helpers import unsigned_formats, float_formats, noncomplex_formats, \
    all_formats, run_fn, run_image2, run_const, run_cmp, \
    assert_almost_equal_objects


class TestArithmetic:
    def run_arith(self, fn, fmt=all_formats):
        [run_image2('%s image %s %s %s' % (fn.__name__, x, y, z),
                    x.cast(y), x.cast(z), fn)
         for x in self.all_images for y in fmt for z in fmt]

    def run_arith_const(self, fn, fmt=all_formats):
        [run_const('%s scalar %s %s' % (fn.__name__, x, y), 
                   fn, x.cast(y), 2)
         for x in self.all_images for y in fmt]
        [run_const('%s vector %s' % (fn.__name__, y), 
                   fn, self.colour.cast(y), [1, 2, 3])
         for y in fmt]

    # run a function on an image,
    # 50,50 and 10,10 should have different values on the test image
    def run_imageunary(self, message, im, fn):
        run_cmp(message, im, 50, 50, lambda x: run_fn(fn, x))
        run_cmp(message, im, 10, 10, lambda x: run_fn(fn, x))

    def run_unary(self, images, fn, fmt=all_formats):
        [self.run_imageunary(fn.__name__ + ' image', x.cast(y), fn)
         for x in images for y in fmt]

    @classmethod
    def setup_class(cls):
        im = pyvips.Image.mask_ideal(100, 100, 0.5,
                                     reject=True, optical=True)
        cls.colour = im * [1, 2, 3] + [2, 3, 4]
        cls.mono = cls.colour.extract_band(1)
        cls.all_images = [cls.mono, cls.colour]

    @classmethod
    def teardown_class(cls):
        cls.colour = None
        cls.mono = None
        cls.all_images = None

    # test all operator overloads we define

    def test_add(self):
        def add(x, y):
            return x + y

        self.run_arith_const(add)
        self.run_arith(add)

    def test_sub(self):
        def sub(x, y):
            return x - y

        self.run_arith_const(sub)
        self.run_arith(sub)

    def test_mul(self):
        def mul(x, y):
            return x * y

        self.run_arith_const(mul)
        self.run_arith(mul)

    def test_div(self):
        def div(x, y):
            return x / y

        # (const / image) needs (image ** -1), which won't work for complex
        self.run_arith_const(div, fmt=noncomplex_formats)
        self.run_arith(div)

    def test_floordiv(self):
        def my_floordiv(x, y):
            return x // y

        # (const // image) needs (image ** -1), which won't work for complex
        self.run_arith_const(my_floordiv, fmt=noncomplex_formats)
        self.run_arith(my_floordiv, fmt=noncomplex_formats)

    def test_pow(self):
        def my_pow(x, y):
            return x ** y

        # (image ** x) won't work for complex images ... just test non-complex
        self.run_arith_const(my_pow, fmt=noncomplex_formats)
        self.run_arith(my_pow, fmt=noncomplex_formats)

    def test_and(self):
        def my_and(x, y):
            # python doesn't allow bools on float
            if isinstance(x, float):
                x = int(x)
            if isinstance(y, float):
                y = int(y)
            return x & y

        self.run_arith_const(my_and, fmt=noncomplex_formats)
        self.run_arith(my_and, fmt=noncomplex_formats)

    def test_or(self):
        def my_or(x, y):
            # python doesn't allow bools on float
            if isinstance(x, float):
                x = int(x)
            if isinstance(y, float):
                y = int(y)
            return x | y

        self.run_arith_const(my_or, fmt=noncomplex_formats)
        self.run_arith(my_or, fmt=noncomplex_formats)

    def test_xor(self):
        def my_xor(x, y):
            # python doesn't allow bools on float
            if isinstance(x, float):
                x = int(x)
            if isinstance(y, float):
                y = int(y)
            return x ^ y

        self.run_arith_const(my_xor, fmt=noncomplex_formats)
        self.run_arith(my_xor, fmt=noncomplex_formats)

    def test_more(self):
        def more(x, y):
            if isinstance(x, pyvips.Image) or isinstance(y, pyvips.Image):
                return x > y
            else:
                if x > y:
                    return 255
                else:
                    return 0

        self.run_arith_const(more)
        self.run_arith(more)

    def test_moreeq(self):
        def moreeq(x, y):
            if isinstance(x, pyvips.Image) or isinstance(y, pyvips.Image):
                return x >= y
            else:
                if x >= y:
                    return 255
                else:
                    return 0

        self.run_arith_const(moreeq)
        self.run_arith(moreeq)

    def test_less(self):
        def less(x, y):
            if isinstance(x, pyvips.Image) or isinstance(y, pyvips.Image):
                return x < y
            else:
                if x < y:
                    return 255
                else:
                    return 0

        self.run_arith_const(less)
        self.run_arith(less)

    def test_lesseq(self):
        def lesseq(x, y):
            if isinstance(x, pyvips.Image) or isinstance(y, pyvips.Image):
                return x <= y
            else:
                if x <= y:
                    return 255
                else:
                    return 0

        self.run_arith_const(lesseq)
        self.run_arith(lesseq)

    def test_equal(self):
        def equal(x, y):
            if isinstance(x, pyvips.Image) or isinstance(y, pyvips.Image):
                return x == y
            else:
                if x == y:
                    return 255
                else:
                    return 0

        self.run_arith_const(equal)
        self.run_arith(equal)

    def test_noteq(self):
        def noteq(x, y):
            if isinstance(x, pyvips.Image) or isinstance(y, pyvips.Image):
                return x != y
            else:
                if x != y:
                    return 255
                else:
                    return 0

        self.run_arith_const(noteq)
        self.run_arith(noteq)

        # comparisons against out of range values should always fail, and
        # comparisons to fractional values should always fail
        x = pyvips.Image.grey(256, 256, uchar=True)
        assert (x == 1000).max() == 0
        assert (x == 12).max() == 255
        assert (x == 12.5).max() == 0

    def test_abs(self):
        def my_abs(x):
            return abs(x)

        im = -self.colour
        self.run_unary([im], my_abs)

    def test_lshift(self):
        def my_lshift(x):
            # python doesn't allow float << int
            if isinstance(x, float):
                x = int(x)
            return x << 2

        # we don't support constant << image, treat as a unary
        self.run_unary(self.all_images, my_lshift, fmt=noncomplex_formats)

    def test_rshift(self):
        def my_rshift(x):
            # python doesn't allow float >> int
            if isinstance(x, float):
                x = int(x)
            return x >> 2

        # we don't support constant >> image, treat as a unary
        self.run_unary(self.all_images, my_rshift, fmt=noncomplex_formats)

    def test_mod(self):
        def my_mod(x):
            return x % 2

        # we don't support constant % image, treat as a unary
        self.run_unary(self.all_images, my_mod, fmt=noncomplex_formats)

    def test_pos(self):
        def my_pos(x):
            return +x

        self.run_unary(self.all_images, my_pos)

    def test_neg(self):
        def my_neg(x):
            return -x

        self.run_unary(self.all_images, my_neg)

    def test_invert(self):
        def my_invert(x):
            if isinstance(x, float):
                x = int(x)
            return ~x & 0xff

        # ~image is trimmed to image max so it's hard to test for all formats
        # just test uchar
        self.run_unary(self.all_images, my_invert,
                       fmt=[pyvips.BandFormat.UCHAR])

    # test the rest of VipsArithmetic

    def test_avg(self):
        im = pyvips.Image.black(50, 100)
        test = im.insert(im + 100, 50, 0, expand=True)

        for fmt in all_formats:
            assert pytest.approx(test.cast(fmt).avg()) == 50

    def test_deviate(self):
        im = pyvips.Image.black(50, 100)
        test = im.insert(im + 100, 50, 0, expand=True)

        for fmt in noncomplex_formats:
            assert pytest.approx(test.cast(fmt).deviate(), abs=0.01) == 50

    def test_polar(self):
        im = pyvips.Image.black(100, 100) + 100
        im = im.complexform(im)

        im = im.polar()

        assert pytest.approx(im.real().avg()) == 100 * 2 ** 0.5
        assert pytest.approx(im.imag().avg()) == 45

    def test_rect(self):
        im = pyvips.Image.black(100, 100)
        im = (im + 100 * 2 ** 0.5).complexform(im + 45)

        im = im.rect()

        assert pytest.approx(im.real().avg()) == 100
        assert pytest.approx(im.imag().avg()) == 100

    def test_conjugate(self):
        im = pyvips.Image.black(100, 100) + 100
        im = im.complexform(im)

        im = im.conj()

        assert pytest.approx(im.real().avg()) == 100
        assert pytest.approx(im.imag().avg()) == -100

    def test_histfind(self):
        im = pyvips.Image.black(50, 100)
        test = im.insert(im + 10, 50, 0, expand=True)

        for fmt in all_formats:
            hist = test.cast(fmt).hist_find()
            assert_almost_equal_objects(hist(0, 0), [5000])
            assert_almost_equal_objects(hist(10, 0), [5000])
            assert_almost_equal_objects(hist(5, 0), [0])

        test = test * [1, 2, 3]

        for fmt in all_formats:
            hist = test.cast(fmt).hist_find(band=0)
            assert_almost_equal_objects(hist(0, 0), [5000])
            assert_almost_equal_objects(hist(10, 0), [5000])
            assert_almost_equal_objects(hist(5, 0), [0])

            hist = test.cast(fmt).hist_find(band=1)
            assert_almost_equal_objects(hist(0, 0), [5000])
            assert_almost_equal_objects(hist(20, 0), [5000])
            assert_almost_equal_objects(hist(5, 0), [0])

    def test_histfind_indexed(self):
        im = pyvips.Image.black(50, 100)
        test = im.insert(im + 10, 50, 0, expand=True)
        index = test // 10

        for x in noncomplex_formats:
            for y in [pyvips.BandFormat.UCHAR, pyvips.BandFormat.USHORT]:
                a = test.cast(x)
                b = index.cast(y)
                hist = a.hist_find_indexed(b)

                assert_almost_equal_objects(hist(0, 0), [0])
                assert_almost_equal_objects(hist(1, 0), [50000])

    def test_histfind_ndim(self):
        im = pyvips.Image.black(100, 100) + [1, 2, 3]

        for fmt in noncomplex_formats:
            hist = im.cast(fmt).hist_find_ndim()

            assert_almost_equal_objects(hist(0, 0)[0], 10000)
            assert_almost_equal_objects(hist(5, 5)[5], 0)

            hist = im.cast(fmt).hist_find_ndim(bins=1)

            assert_almost_equal_objects(hist(0, 0)[0], 10000)
            assert hist.width == 1
            assert hist.height == 1
            assert hist.bands == 1

    def test_hough_circle(self):
        test = pyvips.Image.black(100, 100).draw_circle(100, 50, 50, 40)

        for fmt in all_formats:
            im = test.cast(fmt)
            hough = im.hough_circle(min_radius=35, max_radius=45)

            v, x, y = hough.maxpos()
            vec = hough(x, y)
            r = vec.index(v) + 35

            assert pytest.approx(x) == 50
            assert pytest.approx(y) == 50
            assert pytest.approx(r) == 40

    @pytest.mark.skipif(not pyvips.base.at_least_libvips(8, 7),
                        reason="requires libvips >= 8.7")
    def test_hough_line(self):
        # hough_line changed the way it codes parameter space in 8.7 ... don't
        # test earlier versions
        test = pyvips.Image.black(100, 100).draw_line(100, 10, 90, 90, 10)

        for fmt in all_formats:
            im = test.cast(fmt)
            hough = im.hough_line()

            v, x, y = hough.maxpos()

            angle = 180.0 * x // hough.width
            distance = test.height * y // hough.height

            assert pytest.approx(angle) == 45
            assert pytest.approx(distance) == 70

    def test_sin(self):
        def my_sin(x):
            if isinstance(x, pyvips.Image):
                return x.sin()
            else:
                return math.sin(math.radians(x))

        self.run_unary(self.all_images, my_sin, fmt=noncomplex_formats)

    def test_cos(self):
        def my_cos(x):
            if isinstance(x, pyvips.Image):
                return x.cos()
            else:
                return math.cos(math.radians(x))

        self.run_unary(self.all_images, my_cos, fmt=noncomplex_formats)

    def test_tan(self):
        def my_tan(x):
            if isinstance(x, pyvips.Image):
                return x.tan()
            else:
                return math.tan(math.radians(x))

        self.run_unary(self.all_images, my_tan, fmt=noncomplex_formats)

    def test_asin(self):
        def my_asin(x):
            if isinstance(x, pyvips.Image):
                return x.asin()
            else:
                return math.degrees(math.asin(x))

        im = (pyvips.Image.black(100, 100) + [1, 2, 3]) / 3.0
        self.run_unary([im], my_asin, fmt=noncomplex_formats)

    def test_acos(self):
        def my_acos(x):
            if isinstance(x, pyvips.Image):
                return x.acos()
            else:
                return math.degrees(math.acos(x))

        im = (pyvips.Image.black(100, 100) + [1, 2, 3]) / 3.0
        self.run_unary([im], my_acos, fmt=noncomplex_formats)

    def test_atan(self):
        def my_atan(x):
            if isinstance(x, pyvips.Image):
                return x.atan()
            else:
                return math.degrees(math.atan(x))

        im = (pyvips.Image.black(100, 100) + [1, 2, 3]) / 3.0
        self.run_unary([im], my_atan, fmt=noncomplex_formats)

    def test_log(self):
        def my_log(x):
            if isinstance(x, pyvips.Image):
                return x.log()
            else:
                return math.log(x)

        self.run_unary(self.all_images, my_log, fmt=noncomplex_formats)

    def test_log10(self):
        def my_log10(x):
            if isinstance(x, pyvips.Image):
                return x.log10()
            else:
                return math.log10(x)

        self.run_unary(self.all_images, my_log10, fmt=noncomplex_formats)

    def test_exp(self):
        def my_exp(x):
            if isinstance(x, pyvips.Image):
                return x.exp()
            else:
                return math.exp(x)

        self.run_unary(self.all_images, my_exp, fmt=noncomplex_formats)

    def test_exp10(self):
        def my_exp10(x):
            if isinstance(x, pyvips.Image):
                return x.exp10()
            else:
                return math.pow(10, x)

        self.run_unary(self.all_images, my_exp10, fmt=noncomplex_formats)

    def test_floor(self):
        def my_floor(x):
            if isinstance(x, pyvips.Image):
                return x.floor()
            else:
                return math.floor(x)

        self.run_unary(self.all_images, my_floor)

    def test_ceil(self):
        def my_ceil(x):
            if isinstance(x, pyvips.Image):
                return x.ceil()
            else:
                return math.ceil(x)

        self.run_unary(self.all_images, my_ceil)

    def test_rint(self):
        def my_rint(x):
            if isinstance(x, pyvips.Image):
                return x.rint()
            else:
                return round(x)

        self.run_unary(self.all_images, my_rint)

    def test_sign(self):
        def my_sign(x):
            if isinstance(x, pyvips.Image):
                return x.sign()
            else:
                if x > 0:
                    return 1
                elif x < 0:
                    return -1
                else:
                    return 0

        self.run_unary(self.all_images, my_sign)

    def test_max(self):
        test = pyvips.Image.black(100, 100).draw_rect(100, 40, 50, 1, 1)

        for fmt in all_formats:
            v = test.cast(fmt).max()

            assert pytest.approx(v) == 100
            v, x, y = test.cast(fmt).maxpos()
            assert pytest.approx(v) == 100
            assert pytest.approx(x) == 40
            assert pytest.approx(y) == 50

    def test_min(self):
        test = (pyvips.Image.black(100, 100) + 100).draw_rect(0, 40, 50, 1, 1)

        for fmt in all_formats:
            v = test.cast(fmt).min()

            assert pytest.approx(v) == 0
            v, x, y = test.cast(fmt).minpos()
            assert pytest.approx(v) == 0
            assert pytest.approx(x) == 40
            assert pytest.approx(y) == 50

    def test_measure(self):
        im = pyvips.Image.black(50, 50)
        test = im.insert(im + 10, 50, 0, expand=True)

        for x in noncomplex_formats:
            a = test.cast(x)
            matrix = a.measure(2, 1)
            [p1] = matrix(0, 0)
            [p2] = matrix(0, 1)

            assert pytest.approx(p1) == 0
            assert pytest.approx(p2) == 10

    def test_find_trim(self):
        if pyvips.type_find("VipsOperation", "find_trim") != 0:
            im = pyvips.Image.black(50, 60) + 100
            test = im.embed(10, 20, 200, 300, extend="white")

            for x in unsigned_formats + float_formats:
                a = test.cast(x)
                left, top, width, height = a.find_trim()

                assert left == 10
                assert top == 20
                assert width == 50
                assert height == 60

            test_rgb = test.bandjoin([test, test])
            left, top, width, height = test_rgb.find_trim(background=[255, 255,
                                                                      255])
            assert left == 10
            assert top == 20
            assert width == 50
            assert height == 60

    def test_profile(self):
        test = pyvips.Image.black(100, 100).draw_rect(100, 40, 50, 1, 1)

        for fmt in noncomplex_formats:
            columns, rows = test.cast(fmt).profile()

            v, x, y = columns.minpos()
            assert pytest.approx(v) == 50
            assert pytest.approx(x) == 40
            assert pytest.approx(y) == 0

            v, x, y = rows.minpos()
            assert pytest.approx(v) == 40
            assert pytest.approx(x) == 0
            assert pytest.approx(y) == 50

    def test_project(self):
        im = pyvips.Image.black(50, 50)
        test = im.insert(im + 10, 50, 0, expand=True)

        for fmt in noncomplex_formats:
            columns, rows = test.cast(fmt).project()

            assert_almost_equal_objects(columns(10, 0), [0])
            assert_almost_equal_objects(columns(70, 0), [50 * 10])

            assert_almost_equal_objects(rows(0, 10), [50 * 10])

    def test_stats(self):
        im = pyvips.Image.black(50, 50)
        test = im.insert(im + 10, 50, 0, expand=True)

        for x in noncomplex_formats:
            a = test.cast(x)
            matrix = a.stats()

            assert_almost_equal_objects(matrix(0, 0), [a.min()])
            assert_almost_equal_objects(matrix(1, 0), [a.max()])
            assert_almost_equal_objects(matrix(2, 0), [50 * 50 * 10])
            assert_almost_equal_objects(matrix(3, 0), [50 * 50 * 100])
            assert_almost_equal_objects(matrix(4, 0), [a.avg()])
            assert_almost_equal_objects(matrix(5, 0), [a.deviate()])

            assert_almost_equal_objects(matrix(0, 1), [a.min()])
            assert_almost_equal_objects(matrix(1, 1), [a.max()])
            assert_almost_equal_objects(matrix(2, 1), [50 * 50 * 10])
            assert_almost_equal_objects(matrix(3, 1), [50 * 50 * 100])
            assert_almost_equal_objects(matrix(4, 1), [a.avg()])
            assert_almost_equal_objects(matrix(5, 1), [a.deviate()])

    def test_sum(self):
        for fmt in all_formats:
            im = pyvips.Image.black(50, 50)
            im2 = [(im + x).cast(fmt) for x in range(0, 100, 10)]
            im3 = pyvips.Image.sum(im2)
            assert pytest.approx(im3.max()) == sum(range(0, 100, 10))


if __name__ == '__main__':
    pytest.main()
