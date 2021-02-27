/* solve and invert matrices
 * 
 * 19/4/20 kleisauke
 *	- from im_matinv
 */

/*

    This file is part of VIPS.
    
    VIPS is free software; you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
    02110-1301  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

/*
#define DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include <vips/vips.h>

/* Our state.
 */
typedef struct _VipsMatrixinvert {
	VipsOperation parent_instance;

	VipsImage *in;
	VipsImage *out;

	/* .. and cast to a matrix.
	 */
	VipsImage *mat;

	/* The LU decomposed matrix.
	 */
	VipsImage *lu;
} VipsMatrixinvert;

typedef VipsOperationClass VipsMatrixinvertClass;

G_DEFINE_TYPE( VipsMatrixinvert, vips_matrixinvert, VIPS_TYPE_OPERATION );

static void
vips_matrixinvert_dispose( GObject *gobject )
{
	VipsMatrixinvert *matrix = (VipsMatrixinvert *) gobject;

	VIPS_UNREF( matrix->mat );
	VIPS_UNREF( matrix->lu );

	G_OBJECT_CLASS( vips_matrixinvert_parent_class )->dispose( gobject );
}

/* DBL_MIN is smallest *normalized* double precision float 
 */
#define TOO_SMALL (2.0 * DBL_MIN)

/* Save a bit of typing.
 */
#define ME( m, i, j ) (*VIPS_MATRIX( (m), (i), (j) ))

/**
 * lu_decomp:
 * @mat: matrix to decompose
 *
 * This function takes any square NxN #VipsImage.
 * It returns a #VipsImage which is (N+1)xN.
 *
 * It calculates the PLU decomposition, storing the upper and diagonal parts
 * of U, together with the lower parts of L, as an NxN matrix in the first
 * N rows of the new matrix.  The diagonal parts of L are all set to unity 
 * and are not stored.  
 *
 * The final row of the new #VipsImage has only integer entries, which 
 * represent the row-wise permutations made by the permutation matrix P.
 *
 * The scale and offset members of the input #VipsImage are ignored.
 *
 * See:
 *
 *   PRESS, W. et al, 1992.  Numerical Recipies in C; The Art of Scientific 
 *   Computing, 2nd ed.  Cambridge: Cambridge University Press, pp. 43-50.
 *
 * Returns: the decomposed matrix on success, or NULL on error.
 */
static VipsImage *
lu_decomp( VipsImage *mat )
{
	int i, j, k;
	double *row_scale;
	VipsImage *lu;
	
	if ( !(row_scale = VIPS_ARRAY( NULL, mat->Xsize, double )) ) {
		return( NULL );
	}

	if( !(lu = vips_image_new_matrix( mat->Xsize, mat->Xsize + 1 )) ) {
		g_free( row_scale );
		return( NULL );
	}

	/* copy all coefficients and then perform decomposition in-place */
	memcpy( VIPS_MATRIX( lu, 0, 0), VIPS_MATRIX( mat, 0, 0),
		mat->Xsize * mat->Xsize * sizeof( double ) );

	for( i = 0; i < mat->Xsize; ++i ) {
		row_scale[i] = 0.0;

		for( j = 0; j < mat->Xsize; ++j ) {
			double abs_val = fabs( ME( lu, i, j ) );

			/* find largest in each ROW */
			if( abs_val > row_scale[i] )
				row_scale[i] = abs_val;
		}

		if( !row_scale[i] ) {
			vips_error( "matrixinvert", "singular matrix" );
			g_object_unref( lu );
			g_free( row_scale );
			return( NULL );
		}

		/* fill array with scaling factors for each ROW */
		row_scale[i] = 1.0 / row_scale[i];
	}

	for( j = 0; j < mat->Xsize; ++j ) { /* loop over COLs */
		double max = -1.0;
		int i_of_max;

		/* not needed, but stops a compiler warning */
		i_of_max = 0;

		/* loop over ROWS in upper-half, except diagonal */
		for( i = 0; i < j; ++i )
			for( k = 0; k < i; ++k )
				ME( lu, i, j ) -= ME( lu, i, k ) * ME( lu, k, j );

		/* loop over ROWS in diagonal and lower-half */
		for( i = j; i < mat->Xsize; ++i ) {
			double abs_val;

			for( k = 0; k < j; ++k )
				ME( lu, i, j ) -= ME( lu, i, k ) * ME( lu, k, j );

			/* find largest element in each COLUMN scaled so that */
			/* largest in each ROW is 1.0 */
			abs_val = row_scale[i] * fabs( ME( lu, i, j ) );

			if( abs_val > max ) {
				max = abs_val;
				i_of_max = i;
			}
		}

		if( fabs( ME( lu, i_of_max, j ) ) < TOO_SMALL ) {
			/* divisor is near zero */
			vips_error( "matrixinvert", "singular or near-singular matrix" );
			g_object_unref( lu );
			g_free( row_scale );
			return( NULL );
		}

		if( i_of_max != j ) {
			/* swap ROWS */
			for( k = 0; k < mat->Xsize; ++k ) {
				double temp = ME( lu, j, k );
				ME( lu, j, k ) = ME( lu, i_of_max, k );
				ME( lu, i_of_max, k ) = temp;
			}

			row_scale[i_of_max] = row_scale[j];
			/* no need to copy this scale back up - we won't use it */
		}

		/* record permutation */
		ME( lu, j, mat->Xsize ) = i_of_max;

		/* divide by best (largest scaled) pivot found */
		for( i = j + 1; i < mat->Xsize; ++i )
			ME( lu, i, j ) /= ME( lu, j, j );
	}
	g_free( row_scale );

	return( lu );
}

/**
 * lu_solve:
 * @lu: matrix to solve
 * @vec: name for output matrix
 *
 * Solve the system of linear equations Ax=b, where matrix A has already
 * been decomposed into LU form in VipsImage *lu.  Input vector b is in
 * vec and is overwritten with vector x.
 *
 * See:
 *
 *   PRESS, W. et al, 1992.  Numerical Recipies in C; The Art of Scientific 
 *   Computing, 2nd ed.  Cambridge: Cambridge University Press, pp. 43-50.
 *
 * See also: vips__matrixtranspose(), vips__matrixmultiply().
 *
 * Returns: 0 on success, -1 on error
 */
static int
lu_solve( VipsImage *lu, double *vec )
{
	int i, j;

	if( lu->Xsize + 1 != lu->Ysize ) {
		vips_error( "matrixinvert", "not an LU decomposed matrix" );
		return( -1 );
	}

	for( i = 0; i < lu->Xsize; ++i ) {
		int i_perm = ME( lu, i, lu->Xsize );

		if( i_perm != i ) {
			double temp = vec[i];
			vec[i] = vec[i_perm];
			vec[i_perm] = temp;
		}
		for( j = 0; j < i; ++j )
			vec[i] -= ME( lu, i, j ) * vec[j];
	}

	for( i = lu->Xsize - 1; i >= 0; --i ) {

		for( j = i + 1; j < lu->Xsize; ++j )
			vec[i] -= ME( lu, i, j ) * vec[j];

		vec[i] /= ME( lu, i, i );
	}

	return( 0 );
}

static int
vips_matrixinvert_solve( VipsMatrixinvert *matrix )
{
	VipsImage *out = matrix->out;

	int i, j;
	double *vec;

	if( !(matrix->lu = lu_decomp( matrix->mat ) ) )
		return( -1 );

	if( !(vec = VIPS_ARRAY( matrix, matrix->lu->Xsize, double )) )
		return( -1 );

	for( j = 0; j < matrix->lu->Xsize; ++j ) {
		for( i = 0; i < matrix->lu->Xsize; ++i )
			vec[i] = 0.0;

		vec[j] = 1.0;

		if( lu_solve( matrix->lu, vec ) ) 
			return( -1 );

		for( i = 0; i < matrix->lu->Xsize; ++i )
			ME( out, i, j ) = vec[i];
	}

	return( 0 );
}

static int
vips_matrixinvert_direct( VipsMatrixinvert *matrix )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( matrix );
	VipsImage *in = matrix->mat;
	VipsImage *out = matrix->out;

	switch( matrix->mat->Xsize ) {
	case 1: 
{
		double det = ME( in, 0, 0 );

		if( fabs( det ) < TOO_SMALL ) {
			/* divisor is near zero */
			vips_error( class->nickname,
				"%s", _( "singular or near-singular matrix" ) );
			return( -1 );
		}

		ME( out, 0, 0 ) = 1.0 / det;
}
		break;

	case 2: 
{
		double det = ME( in, 0, 0 ) * ME( in, 1, 1 ) - 
			ME( in, 0, 1 ) * ME( in, 1, 0 );

		double tmp;

		if( fabs( det ) < TOO_SMALL ) {
			/* divisor is near zero */
			vips_error( class->nickname,
				"%s", _( "singular or near-singular matrix" ) );
			return( -1 );
		}

		tmp = 1.0 / det;
		ME( out, 0, 0 ) = tmp * ME( in, 1, 1 );
		ME( out, 0, 1 ) = -tmp * ME( in, 0, 1 );
		ME( out, 1, 0 ) = -tmp * ME( in, 1, 0 );
		ME( out, 1, 1 ) = tmp * ME( in,  0, 0 );
}
		break;

	case 3: 
{
		double det;
		double tmp;

		det = ME( in, 0, 0 ) * ( ME( in, 1, 1 ) * 
			ME( in, 2, 2 ) - ME( in, 1, 2 ) * ME( in, 2, 1 ) );
		det -= ME( in, 0, 1 ) * ( ME( in, 1, 0 ) * 
			ME( in, 2, 2 ) - ME( in, 1, 2 ) * ME( in, 2, 0) );
		det += ME( in, 0, 2)  *  ( ME( in, 1, 0 ) * 
			ME( in, 2, 1 ) - ME( in, 1, 1 ) * ME( in, 2, 0 ) );

		if( fabs( det ) < TOO_SMALL ) {
			/* divisor is near zero */
			vips_error( class->nickname,
				"%s", _( "singular or near-singular matrix" ) );
			return( -1 );
		}

		tmp = 1.0 / det;

		ME( out, 0, 0 ) = tmp * ( ME( in, 1, 1 ) * ME( in, 2, 2 ) -
			ME( in, 1, 2 ) * ME( in, 2, 1 ) );
		ME( out, 1, 0 ) = tmp * ( ME( in, 1, 2 ) * ME( in, 2, 0 ) -
			ME( in, 1, 0 ) * ME( in, 2, 2 ) );
		ME( out, 2, 0 ) = tmp * ( ME( in, 1, 0 ) * ME( in, 2, 1 ) -
			ME( in, 1, 1 ) * ME( in, 2, 0 ) );

		ME( out, 0, 1 ) = tmp * ( ME( in, 0, 2 ) * ME( in, 2, 1 ) -
			ME( in, 0, 1 ) * ME( in, 2, 2 ) );
		ME( out, 1, 1 ) = tmp * ( ME( in, 0, 0 ) * ME( in, 2, 2 ) -
			ME( in, 0, 2 ) * ME( in, 2, 0 ) );
		ME( out, 2, 1 ) = tmp * ( ME( in, 0, 1 ) * ME( in, 2, 0 ) -
			ME( in, 0, 0 ) * ME( in, 2, 1 ) );

		ME( out, 0, 2 ) = tmp * ( ME( in, 0, 1 ) * ME( in, 1, 2 ) -
			ME( in, 0, 2 ) * ME( in, 1, 1 ) );
		ME( out, 1, 2 ) = tmp * ( ME( in, 0, 2 ) * ME( in, 1, 0 ) -
			ME( in, 0, 0 ) * ME( in, 1, 2 ) );
		ME( out, 2, 2 ) = tmp * ( ME( in, 0, 0 ) * ME( in, 1, 1 ) -
			ME( in, 0, 1 ) * ME( in, 1, 0 ) );
}
		break;

	/* TODO(kleisauke):
	 * We sometimes use 4x4 matrices, could we also make a
	 * direct version for those? For e.g.:
	 * https://stackoverflow.com/a/1148405/10952119 */
	default:
		g_assert( 0 );
		return( -1 );
	}

	return( 0 );
}

static int
vips_matrixinvert_build( VipsObject *object )
{
	VipsObjectClass *class = VIPS_OBJECT_GET_CLASS( object );
	VipsMatrixinvert *matrix = (VipsMatrixinvert *) object;

	if( VIPS_OBJECT_CLASS( vips_matrixinvert_parent_class )->
		build( object ) )
		return( -1 );

	if( vips_check_matrix( class->nickname, matrix->in, &matrix->mat ) )
		return( -1 );

	if( matrix->mat->Xsize != matrix->mat->Ysize ) {
		vips_error( class->nickname, "%s", _( "non-square matrix" ) );
		return( -1 );
	}

	g_object_set( matrix, 
		"out", vips_image_new_matrix( matrix->mat->Xsize, 
			matrix->mat->Ysize ),
		NULL );

	/* Direct path for < 4x4 matrices 
	 */
	if( matrix->mat->Xsize >= 4 ) {
		if( vips_matrixinvert_solve( matrix ) )
			return( -1 );
	}
	else {
		if( vips_matrixinvert_direct( matrix ) )
			return( -1 );
	}

	return( 0 );
}

static void
vips_matrixinvert_class_init( VipsMatrixinvertClass *class )
{
	GObjectClass *gobject_class = G_OBJECT_CLASS( class );
	VipsObjectClass *vobject_class = VIPS_OBJECT_CLASS( class );

	gobject_class->dispose = vips_matrixinvert_dispose;
	gobject_class->set_property = vips_object_set_property;
	gobject_class->get_property = vips_object_get_property;

	vobject_class->nickname = "matrixinvert";
	vobject_class->description = _( "invert an matrix" );
	vobject_class->build = vips_matrixinvert_build;

	VIPS_ARG_IMAGE( class, "in", 0,
		_( "Input" ),
		_( "An square matrix" ),
		VIPS_ARGUMENT_REQUIRED_INPUT,
		G_STRUCT_OFFSET( VipsMatrixinvert, in ) );

	VIPS_ARG_IMAGE( class, "out", 1, 
		_( "Output" ), 
		_( "Output matrix" ),
		VIPS_ARGUMENT_REQUIRED_OUTPUT, 
		G_STRUCT_OFFSET( VipsMatrixinvert, out ) );
}

static void
vips_matrixinvert_init( VipsMatrixinvert *matrix )
{
}

/**
 * vips_matrixinvert: (method)
 * @m: matrix to invert
 * @out: (out): output matrix
 * @...: %NULL-terminated list of optional named arguments
 *
 * This operation calculates the inverse of the matrix represented in @m.
 * The scale and offset members of the input matrix are ignored.
 *
 * See also: vips_matrixload().
 *
 * Returns: 0 on success, -1 on error
 */
int
vips_matrixinvert( VipsImage *m, VipsImage **out, ... )
{
	va_list ap;
	int result;

	va_start( ap, out );
	result = vips_call_split( "matrixinvert", ap, m, out );
	va_end( ap );

	return( result );
}
