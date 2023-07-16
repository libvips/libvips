/* Test +/-* overloads with every combination of vector, image and double.
 * This isn't a full test suite, look in the Python area for that.
 *
 * compile with:
 *
 *      g++ -g -Wall test_overloads.cpp `pkg-config vips-cpp --cflags --libs`
 *
 * run with:
 *
 * 	valgrind --leak-check=yes ./a.out ~/pics/k2.jpg ~/pics/shark.jpg
 *
 */

/*
#define VIPS_DEBUG
#define VIPS_DEBUG_VERBOSE
 */

#include <stdlib.h>

#include <vips/vips8>

using namespace vips;

bool
equal_vector(std::vector<double> a, std::vector<double> b)
{
	for (unsigned int i = 0; i < a.size(); i++)
		if (fabs(a[i] - b[i]) > 0.001) {
			printf("vectors differ at %u: should be [", i);
			for (unsigned int i = 0; i < a.size(); i++) {
				if (i > 0)
					printf(", ");
				printf("%g", a[i]);
			}
			printf("], is [");
			for (unsigned int i = 0; i < a.size(); i++) {
				if (i > 0)
					printf(", ");
				printf("%g", a[i]);
			}
			printf("]\n");

			return false;
		}

	return true;
}

bool
equal_double(double a, double b)
{
	if (fabs(a - b) > 0.001) {
		printf("doubles differ: should be %g, is %g\n", a, b);
		return false;
	}

	return true;
}

/* We can't do this with a template, I think we'd need partially-parameterised
 * template, which is C++11 only.
 */

/* Only test a few points and only test uchar: we are just testing the C++
 * overloads, we rely on the python test suite for testing the underlying
 * vips operators.
 */
#define TEST_BINARY(OPERATOR) \
	void \
		test_binary_##OPERATOR(VImage left, VImage right) \
	{ \
		for (int x = 10; x < 30; x += 10) { \
			std::vector<double> p_left = left.getpoint(x, x); \
			std::vector<double> p_right = right.getpoint(x, x); \
			std::vector<double> p_result = \
				OPERATOR<std::vector<double>, \
					std::vector<double>, \
					std::vector<double> >(p_left, p_right); \
\
			VImage im_result; \
			std::vector<double> p_im_result; \
\
			/* test: image = image OP image \
			 */ \
			im_result = OPERATOR<VImage, VImage, VImage>(left, right); \
			p_im_result = im_result.getpoint(x, x); \
\
			if (!equal_vector(p_result, p_im_result)) { \
				printf(#OPERATOR \
					"(VImage, VImage) failed at (%d, %d)\n", \
					x, x); \
				abort(); \
			} \
\
			/* test: image = image OP vec \
			 */ \
			im_result = \
				OPERATOR<VImage, \
					VImage, std::vector<double> >(left, p_right); \
			p_im_result = im_result.getpoint(x, x); \
\
			if (!equal_vector(p_result, p_im_result)) { \
				printf(#OPERATOR \
					"(VImage, vector) failed at (%d, %d)\n", \
					x, x); \
				abort(); \
			} \
\
			/* test: image = vec OP image \
			 */ \
			im_result = \
				OPERATOR<VImage, std::vector<double>, \
					VImage>(p_left, right); \
			p_im_result = im_result.getpoint(x, x); \
\
			if (!equal_vector(p_result, p_im_result)) { \
				printf(#OPERATOR \
					"(vector, VImage) failed at (%d, %d)\n", \
					x, x); \
				abort(); \
			} \
\
			/* test: image = image OP double \
			 */ \
			for (unsigned int i = 0; i < p_right.size(); i++) { \
				im_result = \
					OPERATOR<VImage, \
						VImage, double>(left, p_right[i]); \
				p_im_result = im_result.getpoint(x, x); \
\
				if (!equal_double(p_result[i], p_im_result[i])) { \
					printf(#OPERATOR \
						"(VImage, double) failed at " \
						"(%d, %d)\n", \
						x, x); \
					abort(); \
				} \
			} \
\
			/* test: image = double OP image \
			 */ \
			for (unsigned int i = 0; i < p_left.size(); i++) { \
				im_result = \
					OPERATOR<VImage, \
						double, VImage>(p_left[i], right); \
				p_im_result = im_result.getpoint(x, x); \
\
				if (!equal_double(p_result[i], p_im_result[i])) { \
					printf(#OPERATOR \
						"(double, VImage) failed at " \
						"(%d, %d)\n", \
						x, x); \
					abort(); \
				} \
			} \
		} \
	}

// eg. double = double + double
// or image = double + image
template <typename A, typename B, typename C>
A
test_add(B left, C right)
{
	return left + right;
}

template <typename T>
std::vector<T>
operator+(std::vector<T> &v1, const std::vector<T> &v2)
{
	std::vector<T> result(v1.size());

	for (unsigned int i = 0; i < v1.size(); i++)
		result[i] = v1[i] + v2[i];

	return result;
}

TEST_BINARY(test_add);

template <typename A, typename B, typename C>
A
test_subtract(B left, C right)
{
	return left - right;
}

template <typename T>
std::vector<T>
operator-(std::vector<T> &v1, const std::vector<T> &v2)
{
	std::vector<T> result(v1.size());

	for (unsigned int i = 0; i < v1.size(); i++)
		result[i] = v1[i] - v2[i];

	return result;
}

TEST_BINARY(test_subtract);

template <typename A, typename B, typename C>
A
test_multiply(B left, C right)
{
	return left * right;
}

template <typename T>
std::vector<T>
operator*(std::vector<T> &v1, const std::vector<T> &v2)
{
	std::vector<T> result(v1.size());

	for (unsigned int i = 0; i < v1.size(); i++)
		result[i] = v1[i] * v2[i];

	return result;
}

TEST_BINARY(test_multiply);

template <typename A, typename B, typename C>
A
test_divide(B left, C right)
{
	return left / right;
}

template <typename T>
std::vector<T>
operator/(std::vector<T> &v1, const std::vector<T> &v2)
{
	std::vector<T> result(v1.size());

	for (unsigned int i = 0; i < v1.size(); i++)
		result[i] = v1[i] / v2[i];

	return result;
}

TEST_BINARY(test_divide);

/* We can't test remainder easily, vips does not support constant % image.
 */

/* We'd need an int version to test the bool operators, C++ does not like
 * double & double.
 */

/* Only test a few points and only test uchar: we are just testing the C++
 * overloads, we rely on the python test suite for testing the underlying
 * vips operators.
 */
#define TEST_ASSIGNMENT(OPERATOR) \
	void \
		test_assignment_##OPERATOR(VImage left, VImage right) \
	{ \
		for (int x = 10; x < 30; x += 10) { \
			std::vector<double> p_left = left.getpoint(x, x); \
			std::vector<double> p_right = right.getpoint(x, x); \
			std::vector<double> p_result = p_left; \
			OPERATOR<std::vector<double>, \
				std::vector<double> >(p_result, p_right); \
\
			/* test: image OP= image \
			 */ \
			VImage im_result = left; \
			OPERATOR<VImage, VImage>(im_result, right); \
			std::vector<double> p_im_result = im_result.getpoint(x, x); \
\
			if (!equal_vector(p_result, p_im_result)) { \
				printf(#OPERATOR \
					"(VImage, VImage) failed at (%d, %d)\n", \
					x, x); \
				abort(); \
			} \
\
			/* test: image OP= vec \
			 */ \
			im_result = left; \
			OPERATOR<VImage, std::vector<double> >(im_result, p_right); \
			p_im_result = im_result.getpoint(x, x); \
\
			if (!equal_vector(p_result, p_im_result)) { \
				printf(#OPERATOR \
					"(VImage, vector) failed at (%d, %d)\n", \
					x, x); \
				abort(); \
			} \
\
			/* test: image OP= double \
			 */ \
			for (unsigned int i = 0; i < p_left.size(); i++) { \
				im_result = left; \
				OPERATOR<VImage, double>(im_result, p_right[i]); \
				p_im_result = im_result.getpoint(x, x); \
\
				if (!equal_double(p_result[i], p_im_result[i])) { \
					printf(#OPERATOR \
						"(VImage, double) failed at " \
						"(%d, %d)\n", \
						x, x); \
					abort(); \
				} \
			} \
		} \
	}

template <typename T>
std::vector<T> &
operator+=(std::vector<T> &a, std::vector<T> b)
{
	a = a + b;
	return a;
}

template <typename A, typename B>
void
test_plusequals(A &left, B right)
{
	left += right;
}

TEST_ASSIGNMENT(test_plusequals);

template <typename T>
std::vector<T> &
operator-=(std::vector<T> &a, std::vector<T> b)
{
	a = a - b;
	return a;
}

template <typename A, typename B>
void
test_minusequals(A &left, B right)
{
	left -= right;
}

TEST_ASSIGNMENT(test_minusequals);

template <typename T>
std::vector<T> &
operator*=(std::vector<T> &a, std::vector<T> b)
{
	a = a * b;
	return a;
}

template <typename A, typename B>
void
test_timesequals(A &left, B right)
{
	left *= right;
}

TEST_ASSIGNMENT(test_timesequals);

template <typename T>
std::vector<T> &
operator/=(std::vector<T> &a, std::vector<T> b)
{
	a = a / b;
	return a;
}

template <typename A, typename B>
void
test_divideequals(A &left, B right)
{
	left /= right;
}

TEST_ASSIGNMENT(test_divideequals);

/* We can't test remainder easily, vips does not support constant % image.
 */

/* We'd need an int version to test the bool operators.
 */

int
main(int argc, char **argv)
{
	if (VIPS_INIT(argv[0]))
		vips_error_exit(NULL);

	VImage left = VImage::new_from_file(argv[1]);
	VImage right = VImage::new_from_file(argv[2]);

	VImage band_one = left[1];
	std::vector<double> point = left(0, 0);

	test_binary_test_add(left, right);
	test_binary_test_subtract(left, right);
	test_binary_test_multiply(left, right);
	test_binary_test_divide(left, right);

	test_assignment_test_plusequals(left, right);
	test_assignment_test_minusequals(left, right);
	test_assignment_test_timesequals(left, right);
	test_assignment_test_divideequals(left, right);

	vips_shutdown();

	return 0;
}
