/* Define built-in VIPS types.
 *
 * J. Cupitt, 8/4/93.
 *
 * Modified:
 * 21/5/07
 *	- any length vector (Tom)
 * 23/8/10
 * 	- add IM_TYPE_RW flag for im__rw_image
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
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

 */

/*

    These files are distributed with VIPS - http://www.vips.ecs.soton.ac.uk

 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <vips/vips.h>
#include <vips/internal.h>

/* Max str we parse.
 */
#define IM_MAX_STR (4096)

/* String containing each of the characters which can be used within a 
 * single command line argument to separate the elements of a vector.
 */
#define VEC_SEPS " "

/* Init function for input displays.
 */
static int
input_display_init( im_object *obj, char *str )
{
	struct im_col_display *scr = im_col_display_name( str );

        if( !scr ) {
		int i;

		vips_error( "input_display", 
			_( "unknown display type \"%s\"" ), str );
		vips_error( "input_display", "%s", 
			_( "display should be one of:\n" ) );
                for( i = 0; (scr = im_col_displays( i )); i++ )
			vips_error( "input_display", 
				"  '%s'\n", scr->d_name );

		return( -1 );
        }

	*obj = scr;

	return( 0 );
}

/* Input display type.
 */
im_type_desc im__input_display = {
	IM_TYPE_DISPLAY,		/* It's a display */
	0, 				/* No storage needed */
	IM_TYPE_ARG,			/* It requires a command-line arg */
	input_display_init,		/* Init function */
	NULL				/* Destroy function */
};

/* Output display type.
 */
im_type_desc im__output_display = {
	IM_TYPE_DISPLAY,		/* It's a display */
	sizeof( struct im_col_display ),/* Memory to allocate */
	IM_TYPE_OUTPUT,			/* Output object */
	NULL,				/* Init function */
	NULL				/* Destroy function */
};

/* Init function for input images.
 */
static int
input_image_init( im_object *obj, char *str )
{
	IMAGE **im = (IMAGE **) obj;

	return( !(*im = vips__deprecated_open_read( str )) );
}

/* Input image type.
 */
im_type_desc im__input_image = {
	IM_TYPE_IMAGE,			/* It's an image */
	0, 				/* No storage needed */
	IM_TYPE_ARG,			/* It requires a command-line arg */
	(im_init_obj_fn) input_image_init,/* Init function */
	(im_dest_obj_fn) im_close	/* Destroy function */
};

/* Init function for output images.
 */
static int
output_image_init( im_object *obj, char *str )
{
	IMAGE **im = (IMAGE **) obj;

	return( !(*im = vips__deprecated_open_write( str )) );
}

/* Output image type.
 */
im_type_desc im__output_image = {
	IM_TYPE_IMAGE,			/* It's an image */
	0,				/* No storage to be allocated */
	IM_TYPE_OUTPUT | IM_TYPE_ARG,	/* Flags! */
	(im_init_obj_fn) output_image_init,/* Init function */
	(im_dest_obj_fn) im_close	/* Destroy function */
};

/* Init function for RW images.
 */
static int
rw_image_init( im_object *obj, char *str )
{
	IMAGE **im = (IMAGE **) obj;

	return( !(*im = im_open( str, "rw" )) );
}

/* RW image type.
 */
im_type_desc im__rw_image = {
	IM_TYPE_IMAGE,			/* It's an image */
	0,				/* No storage to be allocated */
	IM_TYPE_ARG | IM_TYPE_RW,	/* Read-write object, needs an arg */
	(im_init_obj_fn) rw_image_init,	/* Init function */
	(im_dest_obj_fn) im_close	/* Destroy function */
};

/* im_imagevec_object destroy function.
 */
static int
imagevec_dest( im_object obj )
{
	im_imagevec_object *iv = obj;

	if( iv->vec ) {
		int i;

		for( i = 0; i < iv->n; i++ )
			if( iv->vec[i] ) {
				im_close( iv->vec[i] );
				iv->vec[i] = NULL;
			}

		g_free( iv->vec );
		iv->vec = NULL;
		iv->n = 0;
	}

	return( 0 );
}

/* Init function for imagevec input.
 */
static int
input_imagevec_init( im_object *obj, char *str )
{
	im_imagevec_object *iv = *obj;
	char **strv;
	int nargs;
	int i;

	strv = g_strsplit( str, VEC_SEPS, -1 );
	nargs = g_strv_length( strv );

	if( !(iv->vec = VIPS_ARRAY( NULL, nargs, IMAGE * )) ) {
		g_strfreev( strv );
		return( -1 );
	}
	iv->n = nargs;

	/* Must NULL them out in case we fail halfway though opening them all.
	 */
	for( i = 0; i < nargs; i++ )
		iv->vec[i] = NULL;

	for( i = 0; i < nargs; i++ ) 
		if( !(iv->vec[i] = im_open( strv[i], "rd" )) ) {
			g_strfreev( strv );
			return( -1 );
		}

	g_strfreev( strv );

	return( 0 );
}

/* Input image vector type.
 */
im_type_desc im__input_imagevec = {
	IM_TYPE_IMAGEVEC,		/* It's an array of IMAGE */
	sizeof( im_imagevec_object ), 	/* Memory to allocate in vec build */
	IM_TYPE_ARG,			/* It requires a command-line arg */
	input_imagevec_init,		/* Init function */
	imagevec_dest			/* Destroy function */
};

/* Init function for masks. "str" can be NULL for output masks.
 */
static int
mask_init( im_object *obj, char *str )
{
	im_mask_object *mo = *obj;

	/* Install string, clear mask.
	 */
	if( str && !(mo->name = im_strdup( NULL, str )) ) 
		return( -1 );
	mo->mask = NULL;

	return( 0 );
}

/* Init function for input dmasks. As above, but read in the mask.
 */
static int
dmask_init( im_object *obj, char *str )
{
	im_mask_object *mo = *obj;

	if( mask_init( obj, str ) )
		return( -1 );
	if( !(mo->mask = im_read_dmask( str )) )
		return( -1 );

	return( 0 );
}

/* Init function for input imasks. 
 */
static int
imask_init( im_object *obj, char *str )
{
	im_mask_object *mo = *obj;

	if( mask_init( obj, str ) )
		return( -1 );
	if( !(mo->mask = im_read_imask( str )) )
		return( -1 );

	return( 0 );
}

/* DOUBLEMASK destroy function.
 */
static int
dmask_dest( im_object obj )
{
	im_mask_object *mo = obj;

	VIPS_FREE( mo->name );
	VIPS_FREEF( im_free_dmask, mo->mask );

	return( 0 );
}

/* INTMASK destroy function.
 */
static int
imask_dest( im_object obj )
{
	im_mask_object *mo = obj;

	VIPS_FREE( mo->name );
	VIPS_FREEF( im_free_imask, mo->mask );

	return( 0 );
}

/* As above, but save the mask first.
 */
static int
save_dmask_dest( im_object obj )
{
	im_mask_object *mo = obj;

	if( mo->mask && im_write_dmask( mo->mask ) )
		return( -1 );
	return( dmask_dest( obj ) );
}

/* As above, but save the mask first.
 */
static int
save_imask_dest( im_object obj )
{
	im_mask_object *mo = obj;

	if( mo->mask && im_write_imask( mo->mask ) )
		return( -1 );
	return( imask_dest( obj ) );
}

/* Output dmask type.
 */
im_type_desc im__output_dmask = {
	IM_TYPE_DMASK,			/* It's a mask */
	sizeof( im_mask_object ),	/* Storage for mask object */
	IM_TYPE_OUTPUT | IM_TYPE_ARG,	/* Flags */
	mask_init,			/* Init function */
	save_dmask_dest			/* Save and destroy function */
};

/* Input dmask type.
 */
im_type_desc im__input_dmask = {
	IM_TYPE_DMASK,			/* It's a mask */
	sizeof( im_mask_object ),	/* Storage for mask object */
	IM_TYPE_ARG,			/* It requires a command-line arg */
	dmask_init,			/* Init function */
	dmask_dest			/* Destroy function */
};

/* Output imask type.
 */
im_type_desc im__output_imask = {
	IM_TYPE_IMASK,			/* It's a mask */
	sizeof( im_mask_object ),	/* Storage for mask object */
	IM_TYPE_OUTPUT | IM_TYPE_ARG,	/* Flags */
	mask_init,			/* Init function */
	save_imask_dest			/* Save and destroy function */
};

/* Input imask type.
 */
im_type_desc im__input_imask = {
	IM_TYPE_IMASK,			/* It's a mask */
	sizeof( im_mask_object ),	/* Storage for mask object */
	IM_TYPE_ARG,			/* It requires a command-line arg */
	imask_init,			/* Init function */
	imask_dest			/* Destroy function */
};

/* Output dmask to screen type. Set a `print' function to get actual output.
 * Used for things like "stats".
 */
im_type_desc im__output_dmask_screen = {
	IM_TYPE_DMASK,			/* It's a mask */
	sizeof( im_mask_object ),	/* Storage for mask object */
	IM_TYPE_OUTPUT,			/* It's an output argument */
	mask_init,			/* Init function */
	dmask_dest			/* Destroy function */
};

/* Init function for double input.
 */
static int
input_double_init( im_object *obj, char *str )
{
	double *d = (double *) *obj;

	*d = g_ascii_strtod( str, NULL );

	return( 0 );
}

/* Input double type.
 */
im_type_desc im__input_double = {
	IM_TYPE_DOUBLE,			/* It's a double */
	sizeof( double ),		/* Memory to allocate */
	IM_TYPE_ARG,			/* It requires a command-line arg */
	input_double_init,		/* Init function */
	NULL				/* Destroy function */
};

/* im_doublevec_object destroy function.
 */
static int
doublevec_dest( im_object obj )
{
	im_doublevec_object *dv = obj;

	if( dv->vec ) {
		g_free( dv->vec );
		dv->vec = NULL;
		dv->n = 0;
	}

	return( 0 );
}

/* Init function for doublevec input.
 */
static int
input_doublevec_init( im_object *obj, char *str )
{
	im_doublevec_object *dv = *obj;
	char **strv;
	int nargs;
	int i;

	strv = g_strsplit( str, VEC_SEPS, -1 );
	nargs = g_strv_length( strv );

	if( !(dv->vec = VIPS_ARRAY( NULL, nargs, double )) ) {
		g_strfreev( strv );
		return( -1 );
	}
	dv->n = nargs;

	for( i = 0; i < nargs; i++ ) {
		dv->vec[i] = g_ascii_strtod( strv[i], NULL );
		if( errno ) {
			vips_error_system( errno, "input_doublevec_init", 
				_( "bad double \"%s\"" ), strv[i] );
			g_strfreev( strv );
			return( -1 );
		}
	}

	g_strfreev( strv );

	return( 0 );
}

/* Input double vector type.
 */
im_type_desc im__input_doublevec = {
	IM_TYPE_DOUBLEVEC,		/* It's an array of double */
	sizeof( im_doublevec_object ), 	/* Memory to allocate in vec build */
	IM_TYPE_ARG,			/* It requires a command-line arg */
	input_doublevec_init,		/* Init function */
	doublevec_dest			/* Destroy function */
};

/* Print function for doublevec output.
 */
int
im__dvprint( im_object obj )
{
	im_doublevec_object *dv = obj;
	int i;

	for( i = 0; i < dv->n; i++ ) 
		printf( "%G ", dv->vec[i] );
	printf( "\n" );

	return( 0 );
}

/* Output double vector type.
 */
im_type_desc im__output_doublevec = {
	IM_TYPE_DOUBLEVEC,		/* It's an array of double */
	sizeof( im_doublevec_object ), 	/* Memory to allocate in vec build */
	IM_TYPE_OUTPUT,			/* Output type */
	NULL,				/* Init function */
	doublevec_dest			/* Destroy function */
};

/* im_intvec_object destroy function.
 */
static int
intvec_dest( im_object obj )
{
	im_intvec_object *iv = obj;

	if( iv->vec ) {
		g_free( iv->vec );
		iv->vec = NULL;
		iv->n = 0;
	}

	return( 0 );
}

/* Init function for intvec input.
 */
static int
input_intvec_init( im_object *obj, char *str )
{
	im_intvec_object *iv = *obj;
	char **strv;
	int nargs;
	int i;

	strv = g_strsplit( str, VEC_SEPS, -1 );
	nargs = g_strv_length( strv );

	if( !(iv->vec = VIPS_ARRAY( NULL, nargs, int )) ) {
		g_strfreev( strv );
		return( -1 );
	}
	iv->n = nargs;

	for( i = 0; i < nargs; i++ ) {
                long int val= strtol( strv[i], NULL, 10 );

		if( errno ) {
			vips_error_system( errno, "input_intvec_init", 
				_( "bad integer \"%s\"" ), strv[i] );
			g_strfreev( strv );
			return( -1 );
		}
                if( INT_MAX < val || INT_MIN > val ) {
                        vips_error( "input_intvec_init", 
                                "%ld overflows integer type", val );
                }
		iv->vec[i] = (int) val;
	}

	g_strfreev( strv );

	return( 0 );
}

/* Input int vector type.
 */
im_type_desc im__input_intvec = {
	IM_TYPE_INTVEC,			/* It's an array of int */
	sizeof( im_intvec_object ), 	/* Memory to allocate in vec build */
	IM_TYPE_ARG,			/* It requires a command-line arg */
	input_intvec_init,		/* Init function */
	intvec_dest			/* Destroy function */
};

/* Print function for intvec output.
 */
int
im__ivprint( im_object obj )
{
	im_intvec_object *iv = obj;
	int i;

	for( i = 0; i < iv->n; i++ ) 
		printf( "%d ", iv->vec[i] );
	printf( "\n" );

	return( 0 );
}

/* Output int vector type.
 */
im_type_desc im__output_intvec = {
	IM_TYPE_INTVEC,			/* It's an array of int */
	sizeof( im_intvec_object ), 	/* Memory to allocate in vec build */
	IM_TYPE_OUTPUT,			/* Output arg */
	(im_init_obj_fn)NULL,		/* Init function */
	(im_dest_obj_fn)intvec_dest	/* Destroy function */
};

/* Init function for int input.
 */
static int
input_int_init( im_object *obj, char *str )
{
	int *i = (int *) *obj;

	if( sscanf( str, "%d", i ) != 1 ) {
		vips_error( "input_int", "%s", _( "bad format" ) );
		return( -1 );
	}

	return( 0 );
}

/* Input int type.
 */
im_type_desc im__input_int = {
	IM_TYPE_INT,			/* It's an int */
	sizeof( int ),			/* Memory to allocate */
	IM_TYPE_ARG,			/* It requires a command-line arg */
	input_int_init,			/* Init function */
	NULL				/* Destroy function */
};

/* Init function for string input.
 */
static int
input_string_init( im_object *obj, char *str )
{
	if( !(*obj = (im_object) im_strdup( NULL, str )) ) 
		return( -1 );

	return( 0 );
}

/* Input string type.
 */
im_type_desc im__input_string = {
	IM_TYPE_STRING,			/* It's a string */
	0, 				/* Memory to allocate */
	IM_TYPE_ARG,			/* It requires a command-line arg */
	input_string_init,		/* Init function */
	vips_free				/* Destroy function */
};

/* Output string type.
 */
im_type_desc im__output_string = {
	IM_TYPE_STRING,			/* It's a string */
	0,				/* Memory to allocate */
	IM_TYPE_OUTPUT,			/* It's an output argument */
	NULL,				/* Init function */
	vips_free				/* Destroy function */
};

/* Output double type.
 */
im_type_desc im__output_double = {
	IM_TYPE_DOUBLE,			/* It's a double */
	sizeof( double ),		/* Memory to allocate */
	IM_TYPE_OUTPUT,			/* It's an output argument */
	NULL,				/* Init function */
	NULL				/* Destroy function */
};

/* Output complex type.
 */
im_type_desc im__output_complex = {
	IM_TYPE_COMPLEX,		/* It's a complex */
	2 * sizeof( double ),		/* Memory to allocate */
	IM_TYPE_OUTPUT,			/* It's an output argument */
	NULL,				/* Init function */
	NULL				/* Destroy function */
};

/* Output int type.
 */
im_type_desc im__output_int = {
	IM_TYPE_INT,			/* It's an int */
	sizeof( int ),			/* Memory to allocate */
	IM_TYPE_OUTPUT,			/* It's an output argument */
	NULL,				/* Init function */
	NULL				/* Destroy function */
};

/* Print function for int output.
 */
int
im__iprint( im_object obj )
{
	int *i = (int *) obj;

	printf( "%d\n", *i );

	return( 0 );
}

/* Print function for string output.
 */
int
im__sprint( im_object obj )
{
	char *s = (char *) obj;

	printf( "%s\n", s );

	return( 0 );
}

/* Print function for double output.
 */
int
im__dprint( im_object obj )
{
	double *d = (double *) obj;

	printf( "%G\n", *d );

	return( 0 );
}

/* Print function for complex output.
 */
int
im__cprint( im_object obj )
{
	double *d = (double *) obj;

	printf( "%G %G\n", d[0], d[1] );

	return( 0 );
}

/* Statistics to stdout.
 */
int
im__dmsprint( im_object obj )
{
	DOUBLEMASK *mask = ((im_mask_object *) obj)->mask;
	double *row;
	int i, j;

	/* Print statistics band stats eg: 2 bands:b 0,1 
	 */
	printf( "band    minimum     maximum         sum       "
		"sum^2        mean   deviation\n" );
	for( j = 0; j < mask->ysize; j++ ) {
		row = mask->coeff + j * mask->xsize;
		if( j == 0 )
			printf( "all" );
		else
			printf( "%2d ", j );

		for( i = 0; i < 6; i++ )
			printf( "%12g", row[i] );
		printf( "\n" );
	}

	return( 0 );
}

static char *decode_dtype( enum im_col_disp_type type )
{
	switch( type ) {
	case DISP_BARCO: 
		return( "DISP_BARCO" );
	case DISP_DUMB: 
		return( "DISP_DUMB" );
	default:
		return( "<unknown display type>" );
	}
}

/* Print display stuff.
 */
int
im__displayprint( im_object obj )
{
	struct im_col_display *scr = (struct im_col_display *) obj;

	printf( "im_col_display:\n" );
	printf( "\td_name: %s\n", scr->d_name );
	printf( "\td_type: %s\n", decode_dtype( scr->d_type ) );
	printf( "\td_mat:\n" );
	printf( "\t\t %g %g %g\n", 
		scr->d_mat[0][0], scr->d_mat[0][1], scr->d_mat[0][2] );
	printf( "\t\t %g %g %g\n", 
		scr->d_mat[1][0], scr->d_mat[1][1], scr->d_mat[1][2] );
	printf( "\t\t %g %g %g\n", 
		scr->d_mat[2][0], scr->d_mat[2][1], scr->d_mat[2][2] );

	printf( "\td_YCW: %g\n", scr->d_YCW );
	printf( "\td_xCW: %g\n", scr->d_xCW );
	printf( "\td_yCW: %g\n", scr->d_yCW );

	printf( "\td_YCR: %g\n", scr->d_YCR );
	printf( "\td_YCG: %g\n", scr->d_YCG );
	printf( "\td_YCB: %g\n", scr->d_YCB );

	printf( "\td_Vrwr: %d\n", scr->d_Vrwr );
	printf( "\td_Vrwg: %d\n", scr->d_Vrwg );
	printf( "\td_Vrwb: %d\n", scr->d_Vrwb );

	printf( "\td_Y0R: %g\n", scr->d_Y0R );
	printf( "\td_Y0G: %g\n", scr->d_Y0G );
	printf( "\td_Y0B: %g\n", scr->d_Y0B );

	printf( "\td_gammaR: %g\n", scr->d_gammaR );
	printf( "\td_gammaG: %g\n", scr->d_gammaG );
	printf( "\td_gammaB: %g\n", scr->d_gammaB );

	printf( "\td_B: %g\n", scr->d_B );
	printf( "\td_P: %g\n", scr->d_P );

	return( 0 );
}

/* GValue
 */

/* Init function for input gvalue. Just make a string ... will get cast to
 * whatever later.
 */
static int
input_gvalue_init( im_object *obj, char *str )
{
	GValue *value = *obj;

	g_value_init( value, G_TYPE_STRING );
	g_value_set_string( value, str );

	return( 0 );
}

static int
gvalue_free( im_object obj )
{
	GValue *value = obj;

	g_value_unset( value );

	return( 0 );
}

/* Input GValue type.
 */
im_type_desc im__input_gvalue = {
	IM_TYPE_GVALUE,		
	sizeof( GValue ),		/* Need some storage */
	IM_TYPE_ARG,			/* It requires a command-line arg */
	(im_init_obj_fn) input_gvalue_init,	/* Init function */
	(im_dest_obj_fn) gvalue_free 	/* Destroy function */
};

int
im__gprint( im_object obj )
{
	GValue *value = obj;
	char *str_value;

	str_value = g_strdup_value_contents( value );
	printf( "%s\n", str_value );
	g_free( str_value );

	return( 0 );
}

/* Init function for output gvalue. Just init to zero.
 */
static int
output_gvalue_init( im_object *obj )
{
	GValue *value = *obj;

	memset( value, 0, sizeof( GValue ) );

	return( 0 );
}

im_type_desc im__output_gvalue = {
	IM_TYPE_GVALUE,	
	sizeof( GValue ),       	/* Need some storage */
	IM_TYPE_OUTPUT,			/* No arg needed (just print) */
	(im_init_obj_fn) output_gvalue_init,	/* Init function */
	(im_dest_obj_fn) gvalue_free 	/* Destroy function */
};

/* Init function for input interpolate.
 */
static int
input_interpolate_init( im_object *obj, char *str )
{
	GType type = g_type_from_name( "VipsInterpolate" );
	VipsObjectClass *class = VIPS_OBJECT_CLASS( g_type_class_ref( type ) );
	VipsObject *object;

	g_assert( class );

	if( !(object = vips_object_new_from_string( class, str )) )
		return( -1 );
	if( vips_object_build( object ) ) {
		g_object_unref( object );
		return( -1 );
	}
	*obj = object;

	return( 0 );
}

static int
input_interpolate_dest( im_object obj )
{
	g_object_unref( (GObject *) obj );

	return( 0 );
}

im_type_desc im__input_interpolate = {
	IM_TYPE_INTERPOLATE,	
	0,      			/* No storage required */
	IM_TYPE_ARG,			/* It requires a command-line arg */
	input_interpolate_init,		/* Init function */
	input_interpolate_dest		/* Destroy function */
};

