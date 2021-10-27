/* compat stuff for vips7
 * 
 * 4/3/11
 * 	- hacked up 
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
#define VIPS_DEBUG
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <vips/vips.h>
#include <vips/vips7compat.h>
#include <vips/internal.h>
#include <vips/debug.h>
#include <vips/vector.h>
#include <vips/transform.h>

/* Split filename into name / mode components. name and mode should both be
 * FILENAME_MAX chars.
 *
 * We look for the ':' splitting the name and mode by searching for the
 * rightmost occurrence of the regexp "\.[A-Za-z0-9]+:". The initial dot can
 * be missing if there's a dirsep or start of string, meaning this is a
 * filename without an extension.
 *
 * Examples:
 *
 * 	c:\silly:dir:name\fr:ed.tif:jpeg:95,,,,c:\icc\srgb.icc
 * 	  -> c:\silly:dir:name\fr:ed.tif  jpeg:95,,,,c:\icc\srgb.icc
 * 	I180:
 * 	  -> I180 ""
 * 	c:\silly:
 * 	  -> c:\silly ""
 * 	c:\silly
 * 	  -> c:\silly ""
 * 	C:\fixtures\2569067123_aca715a2ee_o.jpg
 * 	  -> C:\fixtures\2569067123_aca715a2ee_o.jpg ""
 *
 * vips8 handles this in a much better way :( 
 */
void
im_filename_split( const char *path, char *name, char *mode )
{
        char *p;
	size_t len;

        vips_strncpy( name, path, FILENAME_MAX );
	strcpy( mode, "" );

	if( (len = strlen( name )) == 0 ) 
	       return;	

	/* Search backwards towards start, stopping at each ':' char.
	 */
	for( p = name + len - 1; p > name; p -= 1 )
		if( *p == ':' ) {
			char *q;

			/* We are skipping back over the file extension,
			 * isalnum() is probably sufficient.
			 */
			for( q = p - 1; isalnum( *q ) && q > name; q -= 1 )
				;

			if( *q == '.' ) {
				break;
			}

			/* All the way back to the start? We probably have a
			 * filename with no extension, eg. "I180:"
			 */
			if( q == name )
				break;

			/* .. or we could hit a dirsep. Allow win or nix
			 * separators.
			 */
			if( *q == '/' || 
				*q == '\\' )
				break;
		}

	/* Ignore a ':' in column 1, it's probably a drive letter on a
	 * Windows path. 
	 */
	if( *p == ':' &&
		p - name != 1 ) {
                vips_strncpy( mode, p + 1, FILENAME_MAX );
                *p = '\0';
        }
}

/** 
 * vips_path_filename7:
 * @path: path to split
 *
 * Return the filename part of a vips7 path. For testing only.
 */
char *
vips_path_filename7( const char *path )
{
	char name[FILENAME_MAX];
	char mode[FILENAME_MAX];

	im_filename_split( path, name, mode );

	return( g_strdup( name ) );
}

/** 
 * vips_path_mode7:
 * @path: path to split
 *
 * Return the mode part of a vips7 path. For testing only.
 */
char *
vips_path_mode7( const char *path )
{
	char name[FILENAME_MAX];
	char mode[FILENAME_MAX];

	im_filename_split( path, name, mode );

	return( g_strdup( mode ) );
}

/* Skip any leading path stuff. Horrible: if this is a filename which came
 * from win32 and we're a *nix machine, it'll have '\\' not '/' as the
 * separator :-(
 *
 * Try to fudge this ... if the file doesn't contain any of our native
 * separators, look for the opposite one as well. If there are none of those
 * either, just return the filename.
 */
const char *
im_skip_dir( const char *path )
{
	char name[FILENAME_MAX];
	char mode[FILENAME_MAX];
        const char *p;
        const char *q;

	const char native_dir_sep = G_DIR_SEPARATOR;
	const char non_native_dir_sep = native_dir_sep == '/' ? '\\' : '/';

	/* Remove any trailing save modifiers: we don't want '/' or '\' in the
	 * modifier confusing us.
	 */
	im_filename_split( path, name, mode );

	/* The '\0' char at the end of the string.
	 */
	p = name + strlen( name );

	/* Search back for the first native dir sep, or failing that, the first
	 * non-native dir sep.
	 */
	for( q = p; q > name && q[-1] != native_dir_sep; q-- )
		;
	if( q == name )
		for( q = p; q > name && q[-1] != non_native_dir_sep; q-- )
			;

        return( path + (q - name) );
}

/* Extract suffix from filename, ignoring any mode string. Suffix should be
 * FILENAME_MAX chars. Include the "." character, if any.
 */
void
im_filename_suffix( const char *path, char *suffix )
{
	char name[FILENAME_MAX];
	char mode[FILENAME_MAX];
        char *p;

	im_filename_split( path, name, mode );
        if( (p = strrchr( name, '.' )) ) 
                strcpy( suffix, p );
        else
                strcpy( suffix, "" );
}

/* Does a filename have one of a set of suffixes. Ignore case.
 */
int
im_filename_suffix_match( const char *path, const char *suffixes[] )
{
	char suffix[FILENAME_MAX];
	const char **p;

	im_filename_suffix( path, suffix );
	for( p = suffixes; *p; p++ )
		if( g_ascii_strcasecmp( suffix, *p ) == 0 )
			return( 1 );

	return( 0 );
}

/* p points to the start of a buffer ... move it on through the buffer (ready
 * for the next call), and return the current option (or NULL for option
 * missing). ',' characters inside options can be escaped with a '\'.
 */
char *
im_getnextoption( char **in )
{
        char *p;
        char *q;

        p = *in;
        q = p;

        if( !p || !*p )
                return( NULL );

	/* Find the next ',' not prefixed with a '\'. If the first character
	 * of p is ',', there can't be a previous escape character.
	 */
	for(;;) {
		if( !(p = strchr( p, ',' )) )
			break;
		if( p == q )
			break;
		if( p[-1] != '\\' )
			break;

		p += 1;
	}

        if( p ) {
                /* Another option follows this one .. set up to pick that out
                 * next time.
                 */
                *p = '\0';
                *in = p + 1;
        }
        else {
                /* This is the last one.
                 */
                *in = NULL;
        }

        if( strlen( q ) > 0 )
                return( q );
        else
                return( NULL );
}

/* Get a suboption string, or NULL.
 */
char *
im_getsuboption( const char *buf )
{
        char *p, *q, *r;

        if( !(p = strchr( buf, ':' )) ) 
		/* No suboption.
		 */
		return( NULL );

	/* Step over the ':'.
	 */
	p += 1;

	/* Need to unescape any \, pairs. Shift stuff down one if we find one.
	 */
	for( q = p; *q; q++ ) 
		if( q[0] == '\\' && q[1] == ',' )
			for( r = q; *r; r++ )
				r[0] = r[1];

        return( p );
}

VipsImage *
im_open( const char *filename, const char *mode )
{
	VipsImage *image;

	vips_check_init(); 

	/* We have to go via the old VipsFormat system so we can support the
	 * "filename:option" syntax.
	 *
	 * Use "rs" to turn on seq mode.
	 */
	if( strcmp( mode, "r" ) == 0 ||
		strcmp( mode, "rd" ) == 0 ) {
		if( !(image = vips__deprecated_open_read( filename, FALSE )) )
			return( NULL );
	}
	else if( strcmp( mode, "rs" ) == 0 ) { 
		if( !(image = vips__deprecated_open_read( filename, TRUE )) )
			return( NULL );
	}
	else if( strcmp( mode, "w" ) == 0 ) {
		if( !(image = vips__deprecated_open_write( filename )) )
			return( NULL );
	}
	else {
		if( !(image = vips_image_new_mode( filename, mode )) )
			return( NULL );
	}

	return( image );
}

/* Just for compatibility. New code should use vips_object_local() directly.
 */
VipsImage *
im_open_local( VipsImage *parent, 
	const char *filename, const char *mode )
{
	VipsImage *image;

	if( !(image = im_open( filename, mode )) )
		return( NULL );
	vips_object_local( parent, image );

	return( image );
}

/* Just for compatibility. New code should use vips_object_local_array().
 */
int
im_open_local_array( VipsImage *parent, 
	VipsImage **images, int n,
	const char *filename, const char *mode )
{
	int i;

	for( i = 0; i < n; i++ )
		if( !(images[i] = im_open_local( parent, filename, mode )) )
			return( -1 );

	return( 0 );
}

typedef struct {
	im_callback_fn fn;
	void *a;
	void *b;
} Callback;

static void
im_add_callback_cb( VipsImage *im, Callback *callback )
{
	if( callback->fn( callback->a, callback->b ) )
		vips_image_set_kill( im, TRUE );
}

int 
im_add_callback( VipsImage *im, 
	const char *name, im_callback_fn fn, void *a, void *b )
{
	Callback *callback;

	callback = VIPS_NEW( VIPS_OBJECT( im ), Callback );
	callback->fn = fn;
	callback->a = a;
	callback->b = b;
	g_signal_connect( im, name,
		G_CALLBACK( im_add_callback_cb ), callback );

	return( 0 );
}

static void
im_add_callback_cb1( VipsImage *im, void *x, Callback *callback )
{
	if( callback->fn( callback->a, callback->b ) )
		vips_image_set_kill( im, TRUE );
}

int 
im_add_callback1( VipsImage *im, 
	const char *name, im_callback_fn fn, void *a, void *b )
{
	Callback *callback;

	callback = VIPS_NEW( VIPS_OBJECT( im ), Callback );
	callback->fn = fn;
	callback->a = a;
	callback->b = b;
	g_signal_connect( im, name,
		G_CALLBACK( im_add_callback_cb1 ), callback );

	return( 0 );
}

/* Make something local to an image descriptor ... pass in a constructor
 * and a destructor, plus three args.
 */
void *
im_local( IMAGE *im, 
	im_construct_fn cons, im_callback_fn dest, void *a, void *b, void *c )
{
	void *obj;

	if( !im ) {
		im_error( "im_local", "%s", _( "NULL image descriptor" ) );
		return( NULL );
	}

        if( !(obj = cons( a, b, c )) )
                return( NULL );
        if( im_add_close_callback( im, (im_callback_fn) dest, obj, a ) ) {
                dest( obj, a );
                return( NULL );
        }
 
        return( obj );
}

/* Make an array of things local to a descriptor ... eg. make 6 local temp
 * images.
 */
int
im_local_array( IMAGE *im, void **out, int n,
	im_construct_fn cons, im_callback_fn dest, void *a, void *b, void *c )
{
	int i;

	for( i = 0; i < n; i++ )
		if( !(out[i] = im_local( im, cons, dest, a, b, c )) )
			return( -1 );

	return( 0 );
}

int
im_close( VipsImage *im )
{
	g_object_unref( im );

	return( 0 );
}

/* edvips.c needs this
 */
VipsImage *
im_init( const char *filename )
{
	VipsImage *image;

	image = vips_image_new();
	IM_SETSTR( image->filename, filename );

	return( image );
}

/* We can't do this with a rename macro since the C++ interface needs
 * this entrypoint, see VImage.h.
 *
 * As a result our fancy ABI check will not work with the vips7 interface.
 */
int
im_init_world( const char *argv0 )
{
	return( vips_init( argv0 ) );
}

/* Prettyprint various header fields. Just for vips7 compat, use
 * vips_enum_value() instead.
 */
const char *im_Type2char( VipsInterpretation type ) 
	{ return( vips_enum_string( VIPS_TYPE_INTERPRETATION, type ) ); }
const char *im_BandFmt2char( VipsBandFormat format ) 
	{ return( vips_enum_string( VIPS_TYPE_BAND_FORMAT, format ) ); }
const char *im_Coding2char( VipsCoding coding ) 
	{ return( vips_enum_string( VIPS_TYPE_CODING, coding ) ); }
const char *im_dtype2char( VipsImageType n ) 
	{ return( vips_enum_string( VIPS_TYPE_IMAGE_TYPE, n ) ); }
const char *im_dhint2char( VipsDemandStyle style ) 
	{ return( vips_enum_string( VIPS_TYPE_DEMAND_STYLE, style ) ); }

/* Old names for enums, for compat.
 */
static const char *im_Type[] = {
	"IM_TYPE_MULTIBAND", 		/* 0 */
	"IM_TYPE_B_W", 			/* 1 */
	"LUMINACE", 			/* 2 */
	"XRAY", 			/* 3 */
	"IR", 				/* 4 */
	"YUV", 				/* 5 */
	"RED_ONLY", 			/* 6 */
	"GREEN_ONLY", 			/* 7 */
	"BLUE_ONLY", 			/* 8 */
	"POWER_SPECTRUM", 		/* 9 */
	"IM_TYPE_HISTOGRAM", 		/* 10 */
	"LUT", 				/* 11 */
	"IM_TYPE_XYZ",			/* 12 */
	"IM_TYPE_LAB", 			/* 13 */
	"CMC", 				/* 14 */
	"IM_TYPE_CMYK", 		/* 15 */
	"IM_TYPE_LABQ", 		/* 15 */
	"IM_TYPE_RGB", 			/* 17 */
	"IM_TYPE_UCS", 			/* 18 */
	"IM_TYPE_LCH", 			/* 19 */
	"IM_TYPE_LABS",			/* 20 */
	"<unknown>", 			/* 21 */
	"IM_TYPE_sRGB", 		/* 22 */
	"IM_TYPE_YXY", 			/* 23 */
	"IM_TYPE_FOURIER",		/* 24 */
	"IM_TYPE_RGB16",		/* 25 */
	"IM_TYPE_GREY16",		/* 26 */
	NULL
};

static const char *im_BandFmt[] = {
	"IM_BANDFMT_UCHAR", 
	"IM_BANDFMT_CHAR", 
	"IM_BANDFMT_USHORT", 
	"IM_BANDFMT_SHORT", 
	"IM_BANDFMT_UINT", 
	"IM_BANDFMT_INT", 
	"IM_BANDFMT_FLOAT", 
	"IM_BANDFMT_COMPLEX", 
	"IM_BANDFMT_DOUBLE", 
	"IM_BANDFMT_DPCOMPLEX",
	NULL
};

static const char *im_Coding[] = {
	"IM_CODING_NONE", 
	"COLQUANT8", 
	"IM_CODING_LABQ", 
	"IM_CODING_LABQ_COMPRESSED",
	"RGB_COMPRESSED",
	"LUM_COMPRESSED",
	"IM_CODING_RAD",
	NULL
};

static const char *im_dtype[] = {
	"IM_NONE", 
	"IM_SETBUF", 
	"IM_SETBUF_FOREIGN", 
	"IM_OPENIN", 
	"IM_MMAPIN", 
	"IM_MMAPINRW", 
	"IM_OPENOUT", 
	"IM_PARTIAL",
	NULL
};

static const char *im_dhint[] = {
	"IM_SMALLTILE", 
	"IM_FATSTRIP", 
	"IM_THINSTRIP", 
	"IM_ANY",
	NULL
};

/* enum string to int, try the GEnum first, then use a compat *char[] for old
 * names.
 */
static int
lookup_enum( GType type, const char *names[], const char *name )
{
	GEnumClass *class;
	GEnumValue *value;
	int i;

	class = g_type_class_ref( type );
	if( (value = g_enum_get_value_by_nick( class, name )) )
		return( value->value );
	if( (value = g_enum_get_value_by_name( class, name )) )
		return( value->value );

	for( i = 0; names[i]; i++ )
		if( g_ascii_strcasecmp( names[i], name ) == 0 )
			return( i );

	return( -1 );
}

VipsInterpretation im_char2Type( const char *str ) 
	{ return( lookup_enum( VIPS_TYPE_INTERPRETATION, im_Type, str ) ); }
VipsBandFormat im_char2BandFmt( const char *str ) 
	{ return( lookup_enum( VIPS_TYPE_BAND_FORMAT, im_BandFmt, str ) ); }
VipsCoding im_char2Coding( const char *str ) 
	{ return( lookup_enum( VIPS_TYPE_CODING, im_Coding, str ) ); }
VipsImageType im_char2dtype( const char *str ) 
	{ return( lookup_enum( VIPS_TYPE_IMAGE_TYPE, im_dtype, str ) ); }
VipsDemandStyle im_char2dhint( const char *str ) 
	{ return( lookup_enum( VIPS_TYPE_DEMAND_STYLE, im_dhint, str ) ); }

/* Totally useless now.
 */
const char *im_Compression2char( int n ) { return( "NONE" ); }
int im_char2Compression( const char *str ) { return( -1 ); }

/* Wrap one / many is being replaced by a class thing.
 */

typedef struct {
	im_wrapmany_fn fn;	/* Function we call */ 
	void *a, *b;		/* User values for function */
} Bundle;

/* Maximum number of input images -- why not?
 */
#define MAX_INPUT_IMAGES (64)

/* Convert a VipsRegion.
 */
static int
process_region( VipsRegion *or, void *seq, void *a, void *b )
{
	VipsRegion **ir = (VipsRegion **) seq;
	Bundle *bun = (Bundle *) b;

	PEL *p[MAX_INPUT_IMAGES], *q;
	int i, y;

	/* Prepare all input regions and make buffer pointers.
	 */
	if( vips_reorder_prepare_many( or->im, ir, &or->valid ) ) 
		return( -1 );
	for( i = 0; ir[i]; i++ ) 
		p[i] = (PEL *) VIPS_REGION_ADDR( ir[i], 
			or->valid.left, or->valid.top );
	p[i] = NULL;
	q = (PEL *) VIPS_REGION_ADDR( or, or->valid.left, or->valid.top );

	/* Convert linewise.
	 */
	for( y = 0; y < or->valid.height; y++ ) {
		PEL *p1[MAX_INPUT_IMAGES];

		/* Make a copy of p[] which the buffer function can mess up if
		 * it wants.
		 */
		for( i = 0; ir[i]; i++ )
			p1[i] = p[i];

		/* Bizarre double-cast stops a bogus gcc 4.1 compiler warning.
		 */
		bun->fn( (void **) ((void *)p1), q, 
			or->valid.width, bun->a, bun->b );

		/* Move pointers on.
		 */
		for( i = 0; ir[i]; i++ )
			p[i] += VIPS_REGION_LSKIP( ir[i] );
		q += VIPS_REGION_LSKIP( or );
	}

	return( 0 );
}

/* Make a copy of an array of input images.
 */
static IMAGE **
dupims( IMAGE *out, IMAGE **in )
{
	IMAGE **new;
	int i, n;

	for( n = 0; in[n]; n++ )
		;
	new = VIPS_ARRAY( VIPS_OBJECT( out ), n + 1, IMAGE * );
	for( i = 0; i < n; i++ )
		new[i] = in[i];
	new[n] = NULL;

	return( new );
}

int
im_wrapmany( IMAGE **in, IMAGE *out, im_wrapmany_fn fn, void *a, void *b )
{
	Bundle *bun;
	int i, n;

	/* Count input images.
	 */
	for( n = 0; in[n]; n++ )
		;
	if( n >= MAX_INPUT_IMAGES - 1 ) {
		vips_error( "im_wrapmany", "%s", _( "too many input images" ) );
		return( -1 );
	}

	/* Save args.
	 */
	bun = VIPS_NEW( VIPS_OBJECT( out ), Bundle );
	if( !(in = dupims( out, in )) )
		return( -1 );
	bun->fn = fn;
	bun->a = a;
	bun->b = b;

	/* Check descriptors --- make sure that our caller has done this
	 * correctly.
	 */
	for( i = 0; i < n; i++ ) {
		if( in[i]->Xsize != out->Xsize || in[i]->Ysize != out->Ysize ) {
			vips_error( "im_wrapmany", 
				"%s", _( "descriptors differ in size" ) );
			return( -1 );
		}

		/* Check io style.
		 */
		if( vips_image_pio_input( in[i] ) )
			return( -1 );
	}

	/* Don't call vips_image_pipeline_array(), we don't want to copy
	 * fields.
	 */
	vips__demand_hint_array( out, VIPS_DEMAND_STYLE_THINSTRIP, in );
	if( vips__reorder_set_input( out, in ) )
		return( -1 ); 

	/* Generate!
	 */
	if( vips_image_generate( out,
		vips_start_many, (VipsGenerateFn) process_region, 
		vips_stop_many, in, bun ) )
		return( -1 );

	return( 0 );
}

static void
wrapone_gen( void **ins, void *out, int width, Bundle *bun, void *dummy )
{
	((im_wrapone_fn) (bun->fn)) (ins[0], out, width, bun->a, bun->b );
}

int
im_wrapone( IMAGE *in, IMAGE *out, im_wrapone_fn fn, void *a, void *b )
{
	Bundle *bun;
	IMAGE *invec[2];

	/* Heh, yuk. We cast back above.
	 */
	bun = VIPS_NEW( VIPS_OBJECT( out ), Bundle );
	bun->fn = (im_wrapmany_fn) fn;
	bun->a = a;
	bun->b = b;
	invec[0] = in; invec[1] = NULL;

	return( im_wrapmany( invec, out, 
		(im_wrapmany_fn) wrapone_gen, bun, NULL ) );
}

static void
wraptwo_gen( void **ins, void *out, int width, Bundle *bun, void *dummy )
{
	((im_wraptwo_fn) (bun->fn)) (ins[0], ins[1], out, 
		width, bun->a, bun->b );
}

int
im_wraptwo( IMAGE *in1, IMAGE *in2, IMAGE *out, 
	im_wraptwo_fn fn, void *a, void *b )
{
	Bundle *bun;
	IMAGE *invec[3];

	bun = VIPS_NEW( VIPS_OBJECT( out ), Bundle );
	bun->fn = (im_wrapmany_fn) fn;
	bun->a = a;
	bun->b = b;
	invec[0] = in1; invec[1] = in2; invec[2] = NULL;

	return( im_wrapmany( invec, out, 
		(im_wrapmany_fn) wraptwo_gen, bun, NULL ) );
}

/* Save a bit of typing.
 */
#define UC IM_BANDFMT_UCHAR
#define C IM_BANDFMT_CHAR
#define US IM_BANDFMT_USHORT
#define S IM_BANDFMT_SHORT
#define UI IM_BANDFMT_UINT
#define I IM_BANDFMT_INT
#define F IM_BANDFMT_FLOAT
#define X IM_BANDFMT_COMPLEX
#define D IM_BANDFMT_DOUBLE
#define DX IM_BANDFMT_DPCOMPLEX

/* For two integer types, the "largest", ie. one which can represent the
 * full range of both.
 */
static int bandfmt_largest[6][6] = {
        /* UC  C   US  S   UI  I */
/* UC */ { UC, S,  US, S,  UI, I },
/* C */  { S,  C,  I,  S,  I,  I },
/* US */ { US, I,  US, I,  UI, I },
/* S */  { S,  S,  I,  S,  I,  I },
/* UI */ { UI, I,  UI, I,  UI, I },
/* I */  { I,  I,  I,  I,  I,  I }
};

/* For two formats, find one which can represent the full range of both.
 */
static VipsBandFmt
im__format_common( VipsBandFmt in1, VipsBandFmt in2 )
{
	if( vips_band_format_iscomplex( in1 ) || 
		vips_band_format_iscomplex( in2 ) ) {
		/* What kind of complex?
		 */
		if( in1 == IM_BANDFMT_DPCOMPLEX || in2 == IM_BANDFMT_DPCOMPLEX )
			/* Output will be DPCOMPLEX. 
			 */
			return( IM_BANDFMT_DPCOMPLEX );
		else
			return( IM_BANDFMT_COMPLEX );

	}
	else if( vips_bandfmt_isfloat( in1 ) || 
		vips_bandfmt_isfloat( in2 ) ) {
		/* What kind of float?
		 */
		if( in1 == IM_BANDFMT_DOUBLE || in2 == IM_BANDFMT_DOUBLE )
			return( IM_BANDFMT_DOUBLE );
		else
			return( IM_BANDFMT_FLOAT );
	}
	else 
		/* Must be int+int -> int.
		 */
		return( bandfmt_largest[in1][in2] );
}

int
im__formatalike_vec( IMAGE **in, IMAGE **out, int n )
{
	int i;
	VipsBandFmt fmt;

	g_assert( n >= 1 );

	fmt = in[0]->BandFmt;
	for( i = 1; i < n; i++ )
		fmt = im__format_common( fmt, in[i]->BandFmt );

	for( i = 0; i < n; i++ )
		if( im_clip2fmt( in[i], out[i], fmt ) )
			return( -1 );

	return( 0 );
}

int
im__formatalike( IMAGE *in1, IMAGE *in2, IMAGE *out1, IMAGE *out2 )
{
	IMAGE *in[2];
	IMAGE *out[2];

	in[0] = in1;
	in[1] = in2;
	out[0] = out1;
	out[1] = out2;

	return( im__formatalike_vec( in, out, 2 ) );
}

/* Make an n-band image. Input 1 or n bands.
 */
int
im__bandup( const char *domain, IMAGE *in, IMAGE *out, int n )
{
	IMAGE *bands[256];
	int i;

	if( in->Bands == n ) 
		return( vips_image_write( in, out ) );
	if( in->Bands != 1 ) {
		im_error( domain, _( "not one band or %d bands" ), n );
		return( -1 );
	}
	if( n > 256 || n < 1 ) {
		im_error( domain, "%s", _( "bad bands" ) );
		return( -1 );
	}

	for( i = 0; i < n; i++ )
		bands[i] = in;

	return( im_gbandjoin( bands, out, n ) );
}

int
im__bandalike_vec( const char *domain, IMAGE **in, IMAGE **out, int n )
{
	int i;
	int max_bands;

	g_assert( n >= 1 );

	max_bands = in[0]->Bands;
	for( i = 1; i < n; i++ )
		max_bands = IM_MAX( max_bands, in[i]->Bands );
	for( i = 0; i < n; i++ )
		if( im__bandup( domain, in[i], out[i], max_bands ) )
			return( -1 );

	return( 0 );
}

int
im__bandalike( const char *domain, 
	IMAGE *in1, IMAGE *in2, IMAGE *out1, IMAGE *out2 )
{
	IMAGE *in[2];
	IMAGE *out[2];

	in[0] = in1;
	in[1] = in2;
	out[0] = out1;
	out[1] = out2;
	if( im__bandalike_vec( domain, in, out, 2 ) )
		return( -1 );

	return( 0 );
}

VipsVector *
im__init_program( VipsVector *vectors[IM_BANDFMT_LAST], 
	VipsBandFmt format_table[IM_BANDFMT_LAST], VipsBandFmt fmt )
{
	int isize = im__sizeof_bandfmt[fmt];
	int osize = im__sizeof_bandfmt[format_table[fmt]];

	VipsVector *v;

	v = vips_vector_new( "binary arith", osize );

	vips_vector_source_name( v, "s1", isize );
	vips_vector_source_name( v, "s2", isize );
	vips_vector_temporary( v, "t1", osize );
	vips_vector_temporary( v, "t2", osize );

	vectors[fmt] = v;

	return( v );
}

void
im__compile_programs( VipsVector *vectors[IM_BANDFMT_LAST] )
{
	int fmt;

	for( fmt = 0; fmt < IM_BANDFMT_LAST; fmt++ ) {
		if( vectors[fmt] &&
			!vips_vector_compile( vectors[fmt] ) )
			IM_FREEF( vips_vector_free, vectors[fmt] );
	}

#ifdef DEBUG
	printf( "im__compile_programs: " );
	for( fmt = 0; fmt < IM_BANDFMT_LAST; fmt++ ) 
		if( vectors[fmt] )
			printf( "%s ", im_BandFmt2char( fmt ) );
	printf( "\n" );
#endif /*DEBUG*/
}

int 
im_add( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	VipsImage *x;

	if( vips_call( "add", in1, in2, &x, NULL ) )
		return( -1 );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_subtract( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	VipsImage *x;

	if( vips_call( "subtract", in1, in2, &x, NULL ) )
		return( -1 );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_multiply( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	VipsImage *x;

	if( vips_call( "multiply", in1, in2, &x, NULL ) )
		return( -1 );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_divide( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	VipsImage *x;

	if( vips_call( "divide", in1, in2, &x, NULL ) )
		return( -1 );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int
im_avg( IMAGE *in, double *out )
{
	return( vips_avg( in, out, NULL ) ); 
}

int
im_deviate( IMAGE *in, double *out )
{
	return( vips_deviate( in, out, NULL ) ); 
}

int im_generate( VipsImage *im,
	im_start_fn start, im_generate_fn generate, im_stop_fn stop,
	void *a, void *b )
{
	return( vips_image_generate( im, 
		start, (VipsGenerateFn) generate, stop, a, b ) );
}

int
im_minpos( IMAGE *in, int *xpos, int *ypos, double *out )
{
	return( vips_min( in, out, "x", xpos, "y", ypos, NULL ) );
}

int
im_min( IMAGE *in, double *out )
{
	return( im_minpos( in, NULL, NULL, out ) );
}

int
im_maxpos( IMAGE *in, int *xpos, int *ypos, double *out )
{
	return( vips_max( in, out, "x", xpos, "y", ypos, NULL ) );
}

int
im_max( IMAGE *in, double *out )
{
	return( im_maxpos( in, NULL, NULL, out ) );
}

#define MAX_IMAGES 100
int
im_demand_hint (IMAGE * im, VipsDemandStyle hint, ...)
{
  va_list ap;
  int i;
  IMAGE *ar[MAX_IMAGES];

  va_start (ap, hint);
  for (i = 0; i < MAX_IMAGES && (ar[i] = va_arg (ap, IMAGE *)); i++)
    ;
  va_end (ap);
  if (i == MAX_IMAGES)
    {
      im_error ("im_demand_hint", "%s", _("too many images"));
      return (-1);
    }

  vips__demand_hint_array (im, hint, ar);

  return (0);
}

int
im_cp_descv (IMAGE * im, ...)
{
  va_list ap;
  int i;
  IMAGE *ar[MAX_IMAGES];

  va_start (ap, im);
  for (i = 0; i < MAX_IMAGES && (ar[i] = va_arg (ap, IMAGE *)); i++)
    ;
  va_end (ap);
  if (i == MAX_IMAGES)
    {
      im_error ("im_cp_descv", "%s", _("too many images"));
      return (-1);
    }

  return (vips__image_copy_fields_array (im, ar));
}

int
im_cp_desc(IMAGE *out, IMAGE *in )
{
	return( im_cp_descv( out, in, NULL)); 
}

int 
im_copy_set( IMAGE *in, IMAGE *out, 
	VipsType type, float xres, float yres, int xoffset, int yoffset )
{
	VipsImage *x;

	if( vips_copy( in, &x, 
		"interpretation", type, 
		"xres", xres, 
		"yres", yres, 
		"xoffset", xoffset, 
		"yoffset", yoffset, 
		NULL ) )
		return( -1 );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_copy_morph( IMAGE *in, IMAGE *out, 
	int bands, VipsBandFmt bandfmt, VipsCoding coding )
{
	VipsImage *x;

	if( vips_copy( in, &x, 
		"bands", bands, 
		"format", bandfmt, 
		"coding", coding, 
		NULL ) )
		return( -1 );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int
im_copy( IMAGE *in, IMAGE *out )
{
	return( vips_image_write( in, out ) ); 
}

int
im_copy_swap( IMAGE *in, IMAGE *out )
{
	VipsImage *x;

	if( vips_byteswap( in, &x, NULL ) )
		return( -1 );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int
im_copy_set_meta( IMAGE *in, IMAGE *out, const char *field, GValue *value )
{
	if( vips_image_write( in, out ) )
		return( -1 );
	(void) im_meta_set( out, field, value );

	return( 0 );
}

int
im_copy_native( IMAGE *in, IMAGE *out, gboolean is_msb_first )
{
	if( is_msb_first != im_amiMSBfirst() )
		return( im_copy_swap( in, out ) );
	else
		return( vips_image_write( in, out ) );
}

int
im_embed( IMAGE *in, IMAGE *out, int type, int x, int y, int width, int height )
{
	VipsImage *t;

	if( vips_embed( in, &t, x, y, width, height,
		"extend", type, 
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_fliphor( IMAGE *in, IMAGE *out )
{
	VipsImage *t;

	if( vips_flip( in, &t, VIPS_DIRECTION_HORIZONTAL, NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_rot90( IMAGE *in, IMAGE *out )
{
	VipsImage *t;

	if( vips_rot( in, &t, VIPS_ANGLE_D90, NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_rot180( IMAGE *in, IMAGE *out )
{
	VipsImage *t;

	if( vips_rot( in, &t, VIPS_ANGLE_D180, NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_rot270( IMAGE *in, IMAGE *out )
{
	VipsImage *t;

	if( vips_rot( in, &t, VIPS_ANGLE_D270, NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_flipver( IMAGE *in, IMAGE *out )
{
	VipsImage *t;

	if( vips_flip( in, &t, VIPS_DIRECTION_VERTICAL, NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_insert( IMAGE *main, IMAGE *sub, IMAGE *out, int x, int y )
{
	VipsImage *t;

	if( vips_insert( main, sub, &t, x, y, 
		"expand", TRUE, 
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_insert_noexpand( IMAGE *main, IMAGE *sub, IMAGE *out, int x, int y )
{
	VipsImage *t;

	if( vips_insert( main, sub, &t, x, y, NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_lrjoin( IMAGE *left, IMAGE *right, IMAGE *out )
{
	VipsImage *t;

	if( vips_join( left, right, &t, VIPS_DIRECTION_HORIZONTAL,
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_tbjoin( IMAGE *left, IMAGE *right, IMAGE *out )
{
	VipsImage *t;

	if( vips_join( left, right, &t, VIPS_DIRECTION_VERTICAL,
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int
im_extract_area( IMAGE *in, IMAGE *out, 
	int left, int top, int width, int height )
{
	VipsImage *t;

	if( vips_extract_area( in, &t, left, top, width, height,
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_extract_bands( IMAGE *in, IMAGE *out, int band, int nbands )
{
	VipsImage *t;

	if( vips_extract_band( in, &t, band,
		"n", nbands,
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_extract_band( IMAGE *in, IMAGE *out, int band )
{
	return( im_extract_bands( in, out, band, 1 ) ); 
}

int
im_extract_areabands( IMAGE *in, IMAGE *out, 
	int left, int top, int width, int height, int band, int nbands )
{
	VipsImage *t1, *t2;

	if( vips_extract_area( in, &t1, left, top, width, height,
		NULL ) )
		return( -1 );

	if( vips_extract_band( t1, &t2, band,
		"n", nbands,
		NULL ) ) {
		g_object_unref( t1 );
		return( -1 );
	}
	g_object_unref( t1 );

	if( vips_image_write( t2, out ) ) {
		g_object_unref( t2 );
		return( -1 );
	}
	g_object_unref( t2 );

	return( 0 );
}

int 
im_replicate( IMAGE *in, IMAGE *out, int across, int down )
{
	VipsImage *t;

	if( vips_replicate( in, &t, across, down,
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_clip2fmt( IMAGE *in, IMAGE *out, VipsBandFmt fmt ) 
{
	VipsImage *t;

	if( vips_cast( in, &t, fmt,
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

size_t 
im_ref_string_get_length( const GValue *value )
{
	size_t length;

	(void) vips_value_get_ref_string( value, &length );

	return( length );
}

int 
im_bandjoin( VipsImage *in1, VipsImage *in2, VipsImage *out )
{
	VipsImage *t;

	if( vips_bandjoin2( in1, in2, &t, 
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_gbandjoin( VipsImage **in, VipsImage *out, int n )
{
	VipsImage *t;

	if( vips_bandjoin( in, &t, n,
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int
im_rank_image( VipsImage **in, VipsImage *out, int n, int index )
{
	VipsImage *t;

	if( vips_bandrank( in, &t, n,
		"index", index,
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int
im_maxvalue( IMAGE **in, IMAGE *out, int n )
{
	return( im_rank_image( in, out, n, n - 1 ) );
}

int 
im_invert( IMAGE *in, IMAGE *out )
{
	VipsImage *t;

	if( vips_invert( in, &t, 
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_sign( IMAGE *in, IMAGE *out )
{
	VipsImage *t;

	if( vips_sign( in, &t, 
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_abs( IMAGE *in, IMAGE *out )
{
	VipsImage *t;

	if( vips_abs( in, &t, 
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_bandmean( IMAGE *in, IMAGE *out )
{
	VipsImage *t;

	if( vips_bandmean( in, &t, 
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_lintra( double a, IMAGE *in, double b, IMAGE *out )
{
	VipsImage *t;

	if( vips_linear1( in, &t, a, b,
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_lintra_vec( int n, double *a, IMAGE *in, double *b, IMAGE *out )
{
	VipsImage *t;

	if( vips_linear( in, &t, a, b, n,
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_black( IMAGE *out, int x, int y, int bands )
{
	VipsImage *t;

	if( vips_black( &t, x, y,
		"bands", bands,
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_identity_ushort( VipsImage *lut, int bands, int sz )
{
	VipsImage *t;

	if( vips_identity( &t, 
		"bands", bands,
		"ushort", TRUE,
		"size", sz,
		NULL ) )
		return( -1 );
	if( vips_image_write( t, lut ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_identity( VipsImage *lut, int bands )
{
	VipsImage *t;

	if( vips_identity( &t, 
		"bands", bands,
		NULL ) )
		return( -1 );
	if( vips_image_write( t, lut ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_gaussnoise( VipsImage *out, int x, int y, double mean, double sigma )
{
	VipsImage *t;

	if( vips_gaussnoise( &t, x, y,
		"mean", mean,
		"sigma", sigma,
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_grid( VipsImage *in, VipsImage *out, int tile_height, int across, int down )
{
	VipsImage *t;

	if( vips_grid( in, &t, tile_height, across, down, NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_scale( VipsImage *in, VipsImage *out )
{
	VipsImage *t;

	if( vips_scale( in, &t, NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_msb( VipsImage *in, VipsImage *out )
{
	VipsImage *t;

	if( vips_msb( in, &t, NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_msb_band( VipsImage *in, VipsImage *out, int band )
{
	VipsImage *t;

	if( vips_msb( in, &t, "band", band, NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int
im_make_xy( IMAGE *out, const int xsize, const int ysize )
{
	VipsImage *t;

	if( vips_xyz( &t, xsize, ysize, NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int
im_zone( IMAGE *out, int size )
{
	VipsImage *t;

	if( vips_zone( &t, size, size, 
		"uchar", TRUE,
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int
im_fzone( IMAGE *out, int size )
{
	VipsImage *t;

	if( vips_zone( &t, size, size, NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_sines( IMAGE *out, int xsize, int ysize, double horfreq, double verfreq )
{
	VipsImage *t;

	if( vips_sines( &t, xsize, ysize, 
		"hfreq", horfreq, 
		"vfreq", verfreq, 
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_text( IMAGE *out, const char *text, const char *font, 
	int width, int align, int dpi )
{
	VipsImage *t;

	if( vips_text( &t, text,
		"font", font, 
		"width", width, 
		"align", align, 
		"dpi", dpi, 
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_system( VipsImage *im, const char *cmd, char **out )
{
	VipsArea *area;
	VipsImage **array;
	char *str;

	area = vips_area_new_array_object( 1 );
	array = (VipsImage **) area->data;
	array[0] = im;

	if( vips_system( cmd, 
		"in", area,
		"in_format", "%s.v",
		"log", &str,
		NULL ) ) {
		vips_area_unref( area );
		return( -1 );
	}

	vips_area_unref( area );

	if( out )
		*out = str;

	return( 0 );
}

VipsImage *
im_system_image( VipsImage *im,
	const char *in_format, const char *out_format, const char *cmd_format,
	char **log )
{
	VipsArrayImage *array;
	char *str;
	VipsImage *out; 

	array = vips_array_image_newv( 1, im );

	/* im will be unreffed when area is unreffed.
	 */
	g_object_ref( im ); 

	if( vips_system( cmd_format, 
		"in", array,
		"out", &out,
		"in_format", in_format,
		"out_format", out_format,
		"log", &str,
		NULL ) ) {
		vips_area_unref( VIPS_AREA( array ) );
		return( NULL );
	}

	vips_area_unref( VIPS_AREA( array ) );

	if( log )
		*log = str;
	else
		g_free( str ); 

	return( out );
}

int
im_wrap( IMAGE *in, IMAGE *out, int x, int y )
{
	VipsImage *t;

	if( vips_wrap( in, &t, "x", x, "y", y, NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int
im_rotquad( IMAGE *in, IMAGE *out )
{
	return( im_wrap( in, out, in->Xsize / 2, in->Ysize / 2 ) );
}

int 
im_scaleps( VipsImage *in, VipsImage *out )
{
	VipsImage *t;

	if( vips_scale( in, &t, "log", TRUE, NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_zoom( VipsImage *in, VipsImage *out, int xfac, int yfac )
{
	VipsImage *t;

	if( vips_zoom( in, &t, xfac, yfac, NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_subsample( VipsImage *in, VipsImage *out, int xfac, int yfac )
{
	VipsImage *t;

	if( vips_subsample( in, &t, xfac, yfac, NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

static int
vips__math( VipsImage *in, VipsImage *out, VipsOperationMath math )
{
	VipsImage *t;

	if( vips_math( in, &t, math,
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_sintra( IMAGE *in, IMAGE *out )
{
	return( vips__math( in, out, VIPS_OPERATION_MATH_SIN ) );
}

int 
im_costra( IMAGE *in, IMAGE *out )
{
	return( vips__math( in, out, VIPS_OPERATION_MATH_COS ) );
}

int 
im_tantra( IMAGE *in, IMAGE *out )
{
	return( vips__math( in, out, VIPS_OPERATION_MATH_TAN ) );
}

int 
im_asintra( IMAGE *in, IMAGE *out )
{
	return( vips__math( in, out, VIPS_OPERATION_MATH_ASIN ) );
}

int 
im_acostra( IMAGE *in, IMAGE *out )
{
	return( vips__math( in, out, VIPS_OPERATION_MATH_ACOS ) );
}

int 
im_atantra( IMAGE *in, IMAGE *out )
{
	return( vips__math( in, out, VIPS_OPERATION_MATH_ATAN ) );
}

int 
im_logtra( IMAGE *in, IMAGE *out )
{
	return( vips__math( in, out, VIPS_OPERATION_MATH_LOG ) );
}

int 
im_log10tra( IMAGE *in, IMAGE *out )
{
	return( vips__math( in, out, VIPS_OPERATION_MATH_LOG10 ) );
}

int 
im_exptra( IMAGE *in, IMAGE *out )
{
	return( vips__math( in, out, VIPS_OPERATION_MATH_EXP ) );
}

int 
im_exp10tra( IMAGE *in, IMAGE *out )
{
	return( vips__math( in, out, VIPS_OPERATION_MATH_EXP10 ) );
}

DOUBLEMASK *
im_stats( VipsImage *in )
{
	VipsImage *t;
	DOUBLEMASK *msk;

	if( vips_stats( in, &t,
		NULL ) )
		return( NULL );
	if( !(msk = im_vips2mask( t, "im_stats" )) ) {
		g_object_unref( t );
		return( NULL );
	}
	g_object_unref( t );

	return( msk );
}

DOUBLEMASK *
im_gauss_dmask( const char *filename, double sigma, double min_ampl )
{
	VipsImage *t;
	DOUBLEMASK *msk;

	if( vips_gaussmat( &t, sigma, min_ampl,
		"precision", VIPS_PRECISION_FLOAT,
		NULL ) )
		return( NULL );
	if( !(msk = im_vips2mask( t, filename )) ) {
		g_object_unref( t );
		return( NULL );
	}
	g_object_unref( t );

	return( msk );
}

DOUBLEMASK *
im_gauss_dmask_sep( const char *filename, double sigma, double min_ampl )
{
	VipsImage *t;
	DOUBLEMASK *msk;

	if( vips_gaussmat( &t, sigma, min_ampl,
		"precision", VIPS_PRECISION_FLOAT,
		"separable", TRUE,
		NULL ) )
		return( NULL );
	if( !(msk = im_vips2mask( t, filename )) ) {
		g_object_unref( t );
		return( NULL );
	}
	g_object_unref( t );

	return( msk );
}

INTMASK *
im_gauss_imask( const char *filename, double sigma, double min_ampl )
{
	VipsImage *t;
	INTMASK *msk;

	if( vips_gaussmat( &t, sigma, min_ampl, NULL ) )
		return( NULL );
	if( !(msk = im_vips2imask( t, filename )) ) {
		g_object_unref( t );
		return( NULL );
	}
	g_object_unref( t );

	return( msk );
}

INTMASK *
im_gauss_imask_sep( const char *filename, double sigma, double min_ampl )
{
	VipsImage *t;
	INTMASK *msk;

	if( vips_gaussmat( &t, sigma, min_ampl,
		"separable", TRUE,
		NULL ) )
		return( NULL );
	if( !(msk = im_vips2imask( t, filename )) ) {
		g_object_unref( t );
		return( NULL );
	}
	g_object_unref( t );

	return( msk );
}

INTMASK *
im_log_imask( const char *filename, double sigma, double min_ampl )
{
	VipsImage *t;
	INTMASK *msk;

	if( vips_logmat( &t, sigma, min_ampl, NULL ) )
		return( NULL );
	if( !(msk = im_vips2imask( t, filename )) ) {
		g_object_unref( t );
		return( NULL );
	}
	g_object_unref( t );

	return( msk );
}

DOUBLEMASK *
im_log_dmask( const char *filename, double sigma, double min_ampl )
{
	VipsImage *t;
	DOUBLEMASK *msk;

	if( vips_logmat( &t, sigma, min_ampl,
		"precision", VIPS_PRECISION_FLOAT,
		NULL ) )
		return( NULL );
	if( !(msk = im_vips2mask( t, filename )) ) {
		g_object_unref( t );
		return( NULL );
	}
	g_object_unref( t );

	return( msk );
}

int 
im_recomb( IMAGE *in, IMAGE *out, DOUBLEMASK *recomb )
{
	VipsImage *t1, *t2;

	if( !(t1 = vips_image_new()) ||
		im_mask2vips( recomb, t1 ) )
		return( -1 );
	if( vips_recomb( in, &t2, t1, 
		NULL ) ) {
		g_object_unref( t1 );
		return( -1 );
	}
	g_object_unref( t1 );
	if( vips_image_write( t2, out ) ) {
		g_object_unref( t2 );
		return( -1 );
	}
	g_object_unref( t2 );

	return( 0 );
}

int 
im_compass( VipsImage *in, VipsImage *out, INTMASK *mask )
{
	VipsImage *t1, *t2;

	if( !(t1 = vips_image_new()) ||
		im_imask2vips( mask, t1 ) )
		return( -1 );
	if( vips_compass( in, &t2, t1, 
		"times", 8, 
		"angle", VIPS_ANGLE45_D45, 
		"precision", VIPS_PRECISION_INTEGER,
		NULL ) ) {
		g_object_unref( t1 );
		return( -1 );
	}
	g_object_unref( t1 );
	if( vips_image_write( t2, out ) ) {
		g_object_unref( t2 );
		return( -1 );
	}
	g_object_unref( t2 );

	return( 0 );
}

int 
im_lindetect( IMAGE *in, IMAGE *out, INTMASK *mask )
{
	VipsImage *t1, *t2;

	if( !(t1 = vips_image_new()) ||
		im_imask2vips( mask, t1 ) )
		return( -1 );
	if( vips_compass( in, &t2, t1, 
		"times", 4, 
		"angle", VIPS_ANGLE45_D45, 
		"precision", VIPS_PRECISION_INTEGER,
		NULL ) ) {
		g_object_unref( t1 );
		return( -1 );
	}
	g_object_unref( t1 );
	if( vips_image_write( t2, out ) ) {
		g_object_unref( t2 );
		return( -1 );
	}
	g_object_unref( t2 );

	return( 0 );
}

int
im_gradient( IMAGE *in, IMAGE *out, INTMASK *mask )
{
	VipsImage *t1, *t2;

	if( !(t1 = vips_image_new()) ||
		im_imask2vips( mask, t1 ) )
		return( -1 );
	if( vips_compass( in, &t2, t1, 
		"times", 2, 
		"angle", VIPS_ANGLE45_D90, 
		"combine", VIPS_COMBINE_SUM, 
		"precision", VIPS_PRECISION_INTEGER,
		NULL ) ) {
		g_object_unref( t1 );
		return( -1 );
	}
	g_object_unref( t1 );
	if( vips_image_write( t2, out ) ) {
		g_object_unref( t2 );
		return( -1 );
	}
	g_object_unref( t2 );

	return( 0 );
}

int
im_convsep_raw( IMAGE *in, IMAGE *out, INTMASK *mask )
{
	im_error( "im_convsep_raw", "no compat function" );
	return( -1 );
}

int 
im_convsep( IMAGE *in, IMAGE *out, INTMASK *mask )
{
	VipsImage *t1, *t2;

	if( !(t1 = vips_image_new()) ||
		im_imask2vips( mask, t1 ) )
		return( -1 );
	if( vips_convsep( in, &t2, t1, 
		"precision", VIPS_PRECISION_INTEGER,
		NULL ) ) {
		g_object_unref( t1 );
		return( -1 );
	}
	g_object_unref( t1 );
	if( vips_image_write( t2, out ) ) {
		g_object_unref( t2 );
		return( -1 );
	}
	g_object_unref( t2 );

	return( 0 );
}

int
im_convsep_f_raw( IMAGE *in, IMAGE *out, DOUBLEMASK *mask )
{
	im_error( "im_convsep_raw", "no compat function" );
	return( -1 );
}

int 
im_convsep_f( IMAGE *in, IMAGE *out, DOUBLEMASK *mask )
{
	VipsImage *t1, *t2;

	if( !(t1 = vips_image_new()) ||
		im_mask2vips( mask, t1 ) )
		return( -1 );
	if( vips_convsep( in, &t2, t1, NULL ) ) {
		g_object_unref( t1 );
		return( -1 );
	}
	g_object_unref( t1 );
	if( vips_image_write( t2, out ) ) {
		g_object_unref( t2 );
		return( -1 );
	}
	g_object_unref( t2 );

	return( 0 );
}

int 
im_conv( VipsImage *in, VipsImage *out, INTMASK *mask )
{
	VipsImage *t1, *t2;

	if( !(t1 = vips_image_new()) ||
		im_imask2vips( mask, t1 ) )
		return( -1 );
	if( vips_convi( in, &t2, t1, 
		NULL ) ) {
		g_object_unref( t1 );
		return( -1 );
	}
	g_object_unref( t1 );
	if( vips_image_write( t2, out ) ) {
		g_object_unref( t2 );
		return( -1 );
	}
	g_object_unref( t2 );

	return( 0 );
}

int
im_conv_raw( VipsImage *in, VipsImage *out, INTMASK *mask )
{
	im_error( "im_conv_raw", "no compat function" );
	return( -1 );
}

int 
im_conv_f( VipsImage *in, VipsImage *out, DOUBLEMASK *mask )
{
	VipsImage *t1, *t2;

	if( !(t1 = vips_image_new()) ||
		im_mask2vips( mask, t1 ) )
		return( -1 );
	if( vips_convf( in, &t2, t1, 
		NULL ) ) {
		g_object_unref( t1 );
		return( -1 );
	}
	g_object_unref( t1 );
	if( vips_image_write( t2, out ) ) {
		g_object_unref( t2 );
		return( -1 );
	}
	g_object_unref( t2 );

	return( 0 );
}

int 
im_aconvsep( VipsImage *in, VipsImage *out, DOUBLEMASK *mask, int n_layers )
{
	VipsImage *t1, *t2;

	if( !(t1 = vips_image_new()) ||
		im_mask2vips( mask, t1 ) )
		return( -1 );
	if( vips_convasep( in, &t2, t1, 
		"layers", n_layers,
		NULL ) ) {
		g_object_unref( t1 );
		return( -1 );
	}
	g_object_unref( t1 );
	if( vips_image_write( t2, out ) ) {
		g_object_unref( t2 );
		return( -1 );
	}
	g_object_unref( t2 );

	return( 0 );
}

int 
im_aconv( VipsImage *in, VipsImage *out, 
	DOUBLEMASK *mask, int n_layers, int cluster )
{
	VipsImage *t1, *t2;

	if( !(t1 = vips_image_new()) ||
		im_mask2vips( mask, t1 ) )
		return( -1 );
	if( vips_conva( in, &t2, t1, 
		"layers", n_layers,
		"cluster", cluster,
		NULL ) ) {
		g_object_unref( t1 );
		return( -1 );
	}
	g_object_unref( t1 );
	if( vips_image_write( t2, out ) ) {
		g_object_unref( t2 );
		return( -1 );
	}
	g_object_unref( t2 );

	return( 0 );
}

int
im_conv_f_raw( VipsImage *in, VipsImage *out, DOUBLEMASK *mask )
{
	im_error( "im_conv_f_raw", "no compat function" );
	return( -1 );
}

int
im_addgnoise( IMAGE *in, IMAGE *out, double sigma )
{
	IMAGE *t;

	if( !(t = im_open_local( out, "im_addgnoise", "p" )) ||
		im_gaussnoise( t, in->Xsize, in->Ysize, 0, sigma ) ||
		im_add( in, t, out ) )
		return( -1 );

	return( 0 );
}

int
im_contrast_surface_raw( IMAGE *in, IMAGE *out, int half_win_size, int spacing )
{
	im_error( "im_contrast_surface_raw", "no compat function" );
	return( -1 );
}

/* This replaces some custom code in 7.36 and earlier. The hand-made one was
 * slower for spacing == 1, though faster for large values of spacing. 
 *
 * Not worth maintaining a special operator for. 
 */
int
im_contrast_surface( IMAGE *in, IMAGE *out, int half_win_size, int spacing )
{
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( VIPS_OBJECT( out ), 10 );
	int size = half_win_size * 2; 

	int x, y;

	t[0] = vips_image_new_matrixv( 1, 2, -1.0, 1.0 );
	t[1] = vips_image_new_matrixv( 2, 1, -1.0, 1.0 );
	t[8] = vips_image_new_matrix( size, size ); 

	for( y = 0; y < size; y++ )
		for( x = 0; x < size; x++ )
			*VIPS_MATRIX( t[8], x, y ) = 1.0;

	if( vips_conv( in, &t[2], t[0], 
			"precision", VIPS_PRECISION_INTEGER,
			NULL ) ||
		vips_conv( in, &t[3], t[1], 
			"precision", VIPS_PRECISION_INTEGER,
			NULL ) ||
		vips_abs( t[2], &t[4], NULL ) ||
		vips_abs( t[3], &t[5], NULL ) ||
		vips_add( t[4], t[5], &t[6], NULL ) ||
		vips_conv( t[6], &t[7], t[8], 
			"precision", VIPS_PRECISION_INTEGER,
			NULL ) ||
		vips_subsample( t[7], &t[9], spacing, spacing, NULL ) ||
		vips_image_write( t[9], out ) )
		return( -1 ); 

	return( 0 );
}

int
im_spcor_raw( IMAGE *in, IMAGE *ref, IMAGE *out )
{
	im_error( "im_spcor_raw", "no compat function" );
	return( -1 );
}

int
im_spcor( IMAGE *in, IMAGE *ref, IMAGE *out )
{
	VipsImage *x;

	if( vips_call( "spcor", in, ref, &x, NULL ) )
		return( -1 );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int
im_fastcor_raw( IMAGE *in, IMAGE *ref, IMAGE *out )
{
	im_error( "im_fastcor_raw", "no compat function" );
	return( -1 );
}

int
im_fastcor( IMAGE *in, IMAGE *ref, IMAGE *out )
{
	VipsImage *x;

	if( vips_call( "fastcor", in, ref, &x, NULL ) )
		return( -1 );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int
im_sharpen( IMAGE *in, IMAGE *out, 
	int mask_size, 
	double x1, double y2, double y3, 
	double m1, double m2 )
{
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( VIPS_OBJECT( out ), 2 );

	/* im_sharpen() always recoded as labq and im_benchmark() depends
	 * upon this behaviour. 
	 */
	if( vips_call( "sharpen", in, &t[0], 
		"sigma", mask_size / 4.0,
		"x1", x1,
		"y2", y2,
		"y3", y3,
		"m1", m1,
		"m2", m2,
		NULL ) ||
		vips_colourspace( t[0], &t[1], 
			VIPS_INTERPRETATION_LABQ, NULL ) ||
		vips_image_write( t[1], out ) ) 
		return( -1 );

	return( 0 );
}

static int
vips__round( VipsImage *in, VipsImage *out, VipsOperationRound round )
{
	VipsImage *t;

	if( vips_round( in, &t, round,
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_rint( IMAGE *in, IMAGE *out )
{
	return( vips__round( in, out, VIPS_OPERATION_ROUND_RINT ) );
}

int 
im_floor( IMAGE *in, IMAGE *out )
{
	return( vips__round( in, out, VIPS_OPERATION_ROUND_FLOOR ) );
}

int 
im_ceil( IMAGE *in, IMAGE *out )
{
	return( vips__round( in, out, VIPS_OPERATION_ROUND_CEIL ) );
}

static int 
vips__relational( IMAGE *in1, IMAGE *in2, IMAGE *out, 
	VipsOperationRelational relational )
{
	VipsImage *t;

	if( vips_relational( in1, in2, &t, relational,
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_equal( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	return( vips__relational( in1, in2, out, 
		VIPS_OPERATION_RELATIONAL_EQUAL ) );
}

int 
im_notequal( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	return( vips__relational( in1, in2, out, 
		VIPS_OPERATION_RELATIONAL_NOTEQ ) );
}

int 
im_less( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	return( vips__relational( in1, in2, out, 
		VIPS_OPERATION_RELATIONAL_LESS ) );
}

int 
im_lesseq( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	return( vips__relational( in1, in2, out, 
		VIPS_OPERATION_RELATIONAL_LESSEQ ) );
}

int 
im_more( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	return( vips__relational( in1, in2, out, 
		VIPS_OPERATION_RELATIONAL_MORE ) );
}

int 
im_moreeq( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	return( vips__relational( in1, in2, out, 
		VIPS_OPERATION_RELATIONAL_MOREEQ ) );
}

static int 
vips__relational_vec( IMAGE *in, IMAGE *out, 
	VipsOperationRelational relational, double *c, int n )
{
	VipsImage *t;

	if( vips_relational_const( in, &t, relational, c, n, 
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_equal_vec( VipsImage *in, VipsImage *out, int n, double *c )
{
	return( vips__relational_vec( in, out, 
		VIPS_OPERATION_RELATIONAL_EQUAL, c, n ) );
}

int 
im_notequal_vec( VipsImage *in, VipsImage *out, int n, double *c )
{
	return( vips__relational_vec( in, out, 
		VIPS_OPERATION_RELATIONAL_NOTEQ, c, n ) );
}

int 
im_less_vec( VipsImage *in, VipsImage *out, int n, double *c )
{
	return( vips__relational_vec( in, out, 
		VIPS_OPERATION_RELATIONAL_LESS, c, n ) );
}

int 
im_lesseq_vec( VipsImage *in, VipsImage *out, int n, double *c )
{
	return( vips__relational_vec( in, out, 
		VIPS_OPERATION_RELATIONAL_LESSEQ, c, n ) );
}

int 
im_more_vec( VipsImage *in, VipsImage *out, int n, double *c )
{
	return( vips__relational_vec( in, out, 
		VIPS_OPERATION_RELATIONAL_MORE, c, n ) );
}

int 
im_moreeq_vec( VipsImage *in, VipsImage *out, int n, double *c )
{
	return( vips__relational_vec( in, out, 
		VIPS_OPERATION_RELATIONAL_MOREEQ, c, n ) );
}

int 
im_equalconst( IMAGE *in, IMAGE *out, double c )
{
	return( im_equal_vec( in, out, 1, &c ) );
}

int
im_notequalconst( IMAGE *in, IMAGE *out, double c )
{
	return( im_notequal_vec( in, out, 1, &c ) );
}

int
im_lessconst( IMAGE *in, IMAGE *out, double c )
{
	return( im_less_vec( in, out, 1, &c ) );
}

int
im_lesseqconst( IMAGE *in, IMAGE *out, double c )
{
	return( im_lesseq_vec( in, out, 1, &c ) );
}

int
im_moreconst( IMAGE *in, IMAGE *out, double c )
{
	return( im_more_vec( in, out, 1, &c ) );
}

int
im_moreeqconst( IMAGE *in, IMAGE *out, double c )
{
	return( im_moreeq_vec( in, out, 1, &c ) );
}

int 
im_remainder( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	VipsImage *t;

	if( vips_remainder( in1, in2, &t, 
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_remainder_vec( IMAGE *in, IMAGE *out, int n, double *c )
{
	VipsImage *t;

	if( vips_remainder_const( in, &t, c, n,
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_remainderconst( IMAGE *in, IMAGE *out, double c )
{
	return( im_remainder_vec( in, out, 1, &c ) );
}

static int 
vips__boolean( IMAGE *in1, IMAGE *in2, IMAGE *out, 
	VipsOperationBoolean boolean )
{
	VipsImage *t;

	if( vips_boolean( in1, in2, &t, boolean,
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_andimage( VipsImage *in1, VipsImage *in2, VipsImage *out )
{
	return( vips__boolean( in1, in2, out, VIPS_OPERATION_BOOLEAN_AND ) );
}

int 
im_orimage( VipsImage *in1, VipsImage *in2, VipsImage *out )
{
	return( vips__boolean( in1, in2, out, VIPS_OPERATION_BOOLEAN_OR ) );
}

int 
im_eorimage( VipsImage *in1, VipsImage *in2, VipsImage *out )
{
	return( vips__boolean( in1, in2, out, VIPS_OPERATION_BOOLEAN_EOR ) );
}

static int 
vips__boolean_vec( IMAGE *in, IMAGE *out, 
	VipsOperationBoolean boolean, double *c, int n )
{
	VipsImage *t;

	if( vips_boolean_const( in, &t, boolean, c, n, 
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_andimage_vec( VipsImage *in, VipsImage *out, int n, double *c )
{
	return( vips__boolean_vec( in, out, 
		VIPS_OPERATION_BOOLEAN_AND, c, n ) );
}

int 
im_orimage_vec( VipsImage *in, VipsImage *out, int n, double *c )
{
	return( vips__boolean_vec( in, out, 
		VIPS_OPERATION_BOOLEAN_OR, c, n ) );
}

int 
im_eorimage_vec( VipsImage *in, VipsImage *out, int n, double *c )
{
	return( vips__boolean_vec( in, out, 
		VIPS_OPERATION_BOOLEAN_EOR, c, n ) );
}

int 
im_shiftleft_vec( IMAGE *in, IMAGE *out, int n, double *c )
{
	return( vips__boolean_vec( in, out, 
		VIPS_OPERATION_BOOLEAN_LSHIFT, c, n ) );
}

int 
im_shiftright_vec( IMAGE *in, IMAGE *out, int n, double *c )
{
	return( vips__boolean_vec( in, out, 
		VIPS_OPERATION_BOOLEAN_RSHIFT, c, n ) );
}

int 
im_andimageconst( IMAGE *in, IMAGE *out, double c )
{
	return( im_andimage_vec( in, out, 1, &c ) ); 
}

int 
im_orimageconst( IMAGE *in, IMAGE *out, double c )
{
	return( im_orimage_vec( in, out, 1, &c ) );
}

int 
im_eorimageconst( IMAGE *in, IMAGE *out, double c )
{
	return( im_eorimage_vec( in, out, 1, &c ) );
}

int 
im_shiftleft( IMAGE *in, IMAGE *out, int n )
{
	double c = n;

	return( im_shiftleft_vec( in, out, 1, &c ) );
}

int 
im_shiftright( IMAGE *in, IMAGE *out, int n )
{
	double c = n;

	return( im_shiftright_vec( in, out, 1, &c ) );
}

static int 
vips__math2_vec( IMAGE *in, IMAGE *out, 
	VipsOperationMath2 math2, double *c, int n )
{
	VipsImage *t;

	if( vips_math2_const( in, &t, math2, c, n, 
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_powtra_vec( VipsImage *in, VipsImage *out, int n, double *c )
{
	return( vips__math2_vec( in, out, VIPS_OPERATION_MATH2_POW, c, n ) );
}

int 
im_powtra( IMAGE *in, IMAGE *out, double c )
{
	return( im_powtra_vec( in, out, 1, &c ) );
}

int 
im_expntra_vec( IMAGE *in, IMAGE *out, int n, double *c )
{
	return( vips__math2_vec( in, out, VIPS_OPERATION_MATH2_WOP, c, n ) );
}

int 
im_expntra( IMAGE *in, IMAGE *out, double c )
{
	return( im_expntra_vec( in, out, 1, &c ) );
}

int 
im_ifthenelse( VipsImage *c, VipsImage *a, VipsImage *b, VipsImage *out )
{
	VipsImage *t;

	if( vips_ifthenelse( c, a, b, &t, 
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_blend( VipsImage *c, VipsImage *a, VipsImage *b, VipsImage *out )
{
	VipsImage *t;

	if( vips_ifthenelse( c, a, b, &t, 
		"blend", TRUE,
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

static int
vips__complex( VipsImage *in, VipsImage *out, VipsOperationComplex cmplx )
{
	VipsImage *t;

	if( vips_complex( in, &t, cmplx,
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_c2amph( IMAGE *in, IMAGE *out )
{
	return( vips__complex( in, out, VIPS_OPERATION_COMPLEX_POLAR ) );
}

int 
im_c2rect( IMAGE *in, IMAGE *out )
{
	return( vips__complex( in, out, VIPS_OPERATION_COMPLEX_RECT ) );
}

static int
vips__complexget( VipsImage *in, VipsImage *out, VipsOperationComplexget get )
{
	VipsImage *t;

	if( vips_complexget( in, &t, get,
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_c2real( IMAGE *in, IMAGE *out )
{
	return( vips__complexget( in, out, VIPS_OPERATION_COMPLEXGET_REAL ) );
}

int 
im_c2imag( IMAGE *in, IMAGE *out )
{
	return( vips__complexget( in, out, VIPS_OPERATION_COMPLEXGET_IMAG ) );
}

int 
im_ri2c( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	VipsImage *x;

	if( vips_call( "complexform", in1, in2, &x, NULL ) )
		return( -1 );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int
im_cache( VipsImage *in, VipsImage *out, 
	int width, int height, int max )
{
	return( vips_sink_screen( in, out, NULL, 
		width, height, max, 0, NULL, NULL ) );
}

int
im_argb2rgba( VipsImage *in, VipsImage *out )
{
	/* No longer exists, just a null op.
	 */
	return( vips_image_write( in, out ) );
}

int
im_shrink( VipsImage *in, VipsImage *out, double xshrink, double yshrink )
{
	VipsImage *x;

	if( vips_shrink( in, &x, xshrink, yshrink, NULL ) )
		return( -1 );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int
im_eye( IMAGE *out, const int xsize, const int ysize, const double factor )
{
	VipsImage *x;

	if( vips_eye( &x, xsize, ysize, 
		"factor", factor,
		"uchar", TRUE,
		NULL ) )
		return( -1 );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int
im_feye( IMAGE *out, const int xsize, const int ysize, const double factor )
{
	VipsImage *x;

	if( vips_eye( &x, xsize, ysize, 
		"factor", factor,
		NULL ) )
		return( -1 );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int
im_grey( IMAGE *out, const int xsize, const int ysize )
{
	VipsImage *x;

	if( vips_grey( &x, xsize, ysize, 
		"uchar", TRUE,
		NULL ) )
		return( -1 );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int
im_fgrey( IMAGE *out, const int xsize, const int ysize )
{
	VipsImage *x;

	if( vips_grey( &x, xsize, ysize, 
		NULL ) )
		return( -1 );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int
im_buildlut( DOUBLEMASK *input, VipsImage *out )
{
	VipsImage *mat;
	VipsImage *x;

	mat = vips_image_new();
	if( im_mask2vips( input, mat ) )
		return( -1 );
	if( vips_buildlut( mat, &x, 
		NULL ) ) {
		g_object_unref( mat );
		return( -1 );
	}
	g_object_unref( mat );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int
im_invertlut( DOUBLEMASK *input, VipsImage *out, int size )
{
	VipsImage *mat;
	VipsImage *x;

	mat = vips_image_new();
	if( im_mask2vips( input, mat ) )
		return( -1 );
	if( vips_invertlut( mat, &x, 
		"size", size, 
		NULL ) ) {
		g_object_unref( mat );
		return( -1 );
	}
	g_object_unref( mat );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_tone_build_range( IMAGE *out, 
	int in_max, int out_max,
	double Lb, double Lw,
	double Ps, double Pm, double Ph, 
	double S, double M, double H )
{
	VipsImage *t;

	if( vips_tonelut( &t, 
		"in_max", in_max,
		"out_max", out_max,
		"Lb", Lb,
		"Lw", Lw,
		"Ps", Ps,
		"Pm", Pm,
		"Ph", Ph,
		"S", S,
		"M", M,
		"H", H,
		NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_tone_build( IMAGE *out, 
	double Lb, double Lw,
	double Ps, double Pm, double Ph, 
	double S, double M, double H )
{
	IMAGE *t1;

	if( !(t1 = im_open_local( out, "im_tone_build", "p" )) ||
		im_tone_build_range( t1, 32767, 32767,
			Lb, Lw, Ps, Pm, Ph, S, M, H ) ||
		im_clip2fmt( t1, out, IM_BANDFMT_SHORT ) )
		return( -1 );

	return( 0 );
}

int
im_rightshift_size( IMAGE *in, IMAGE *out, 
	int xshift, int yshift, int band_fmt )
{
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( VIPS_OBJECT( out ), 2 );

	if( vips_shrink( in, &t[0], 1 << xshift, 1 << yshift, NULL ) ||
		vips_cast( t[0], &t[1], band_fmt, NULL ) ||
		vips_image_write( t[1], out ) ) 
		return( -1 );

	return( 0 );
}

int 
im_Lab2XYZ_temp( IMAGE *in, IMAGE *out, double X0, double Y0, double Z0 )
{
	VipsArea *temp;
	VipsImage *x;

	temp = VIPS_AREA( vips_array_double_newv( 3, X0, Y0, Z0 ) );
	if( vips_Lab2XYZ( in, &x, "temp", temp, NULL ) ) {
		vips_area_unref( temp );
		return( -1 );
	}
	vips_area_unref( temp );

	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_Lab2XYZ( IMAGE *in, IMAGE *out )
{
	VipsImage *x;

	if( vips_Lab2XYZ( in, &x, NULL ) )
		return( -1 );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_XYZ2Lab_temp( IMAGE *in, IMAGE *out, double X0, double Y0, double Z0 )
{
	double ary[3];
	VipsArea *temp;
	VipsImage *x;

	ary[0] = X0;
	ary[1] = Y0;
	ary[2] = Z0;
	temp = VIPS_AREA( vips_array_double_new( ary, 3 ) ); 
	if( vips_XYZ2Lab( in, &x, "temp", temp, NULL ) ) {
		vips_area_unref( temp );
		return( -1 );
	}
	vips_area_unref( temp );

	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_XYZ2Lab( IMAGE *in, IMAGE *out )
{
	VipsImage *x;

	if( vips_XYZ2Lab( in, &x, NULL ) )
		return( -1 );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_Lab2LCh( IMAGE *in, IMAGE *out )
{
	VipsImage *x;

	if( vips_Lab2LCh( in, &x, NULL ) )
		return( -1 );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_LCh2Lab( IMAGE *in, IMAGE *out )
{
	VipsImage *x;

	if( vips_LCh2Lab( in, &x, NULL ) )
		return( -1 );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_LCh2UCS( IMAGE *in, IMAGE *out )
{
	VipsImage *x;

	if( vips_LCh2CMC( in, &x, NULL ) )
		return( -1 );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_UCS2LCh( IMAGE *in, IMAGE *out )
{
	VipsImage *x;

	if( vips_CMC2LCh( in, &x, NULL ) )
		return( -1 );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_XYZ2Yxy( IMAGE *in, IMAGE *out )
{
	VipsImage *x;

	if( vips_XYZ2Yxy( in, &x, NULL ) )
		return( -1 );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_Yxy2XYZ( IMAGE *in, IMAGE *out )
{
	VipsImage *x;

	if( vips_Yxy2XYZ( in, &x, NULL ) )
		return( -1 );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_float2rad( IMAGE *in, IMAGE *out )
{
	VipsImage *x;

	if( vips_float2rad( in, &x, NULL ) )
		return( -1 );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_rad2float( IMAGE *in, IMAGE *out )
{
	VipsImage *x;

	if( vips_rad2float( in, &x, NULL ) )
		return( -1 );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_Lab2LabQ( IMAGE *in, IMAGE *out )
{
	VipsImage *x;

	if( vips_Lab2LabQ( in, &x, NULL ) )
		return( -1 );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_LabQ2Lab( IMAGE *in, IMAGE *out )
{
	VipsImage *x;

	if( vips_LabQ2Lab( in, &x, NULL ) )
		return( -1 );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_Lab2LabS( IMAGE *in, IMAGE *out )
{
	VipsImage *x;

	if( vips_Lab2LabS( in, &x, NULL ) )
		return( -1 );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_LabS2Lab( IMAGE *in, IMAGE *out )
{
	VipsImage *x;

	if( vips_LabS2Lab( in, &x, NULL ) )
		return( -1 );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_LabQ2LabS( IMAGE *in, IMAGE *out )
{
	VipsImage *x;

	if( vips_LabQ2LabS( in, &x, NULL ) )
		return( -1 );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_LabS2LabQ( IMAGE *in, IMAGE *out )
{
	VipsImage *x;

	if( vips_LabS2LabQ( in, &x, NULL ) )
		return( -1 );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_Lab2disp( IMAGE *in, IMAGE *out, struct im_col_display *disp )
{	
	IMAGE *t[1];

	if( im_open_local_array( out, t, 1, "im_Lab2disp:1", "p" ) ||
		im_Lab2XYZ( in, t[0] ) ||
		im_XYZ2disp( t[0], out, disp ) )
		return( -1 );

	return( 0 );
}

int 
im_dECMC_fromdisp( IMAGE *im1, IMAGE *im2, 
	IMAGE *out, struct im_col_display *d )
{	
	IMAGE *t[4];

	if( im_open_local_array( out, t, 4, "im_dECMC_fromdisp:1", "p" ) ||
		im_disp2XYZ( im1, t[0], d ) ||
		im_XYZ2Lab( t[0], t[1] ) ||
		im_disp2XYZ( im2, t[2], d ) ||
		im_XYZ2Lab( t[2], t[3] ) ||
		im_dECMC_fromLab( t[1], t[3], out ) )
		return( -1 );

	return( 0 );
}

int 
im_dE_fromdisp( IMAGE *im1, IMAGE *im2, IMAGE *out, struct im_col_display *d )
{
	IMAGE *t[2];

	if( im_open_local_array( out, t, 2, "im_dE_fromdisp:1", "p" ) ||
		im_disp2XYZ( im1, t[0], d ) ||
		im_disp2XYZ( im2, t[1], d ) ||
		im_dE_fromXYZ( t[0], t[1], out ) )
		return( -1 );

	return( 0 );
}

int 
im_disp2Lab( IMAGE *in, IMAGE *out, struct im_col_display *d )
{
	VipsImage *t[1];

	if( im_open_local_array( out, t, 1, "im_disp2Lab:1", "p" ) ||
		im_disp2XYZ( in, t[0], d ) ||
		im_XYZ2Lab( t[0], out ) )
		return( -1 );
	
	return( 0 );
}

int 
im_sRGB2XYZ( IMAGE *in, IMAGE *out )
{
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( (VipsObject *) out, 2 );

	if( vips_sRGB2scRGB( in, &t[0], NULL ) ||
		vips_scRGB2XYZ( t[0], &t[1], NULL ) ||
		vips_image_write( t[1], out ) ) 
		return( -1 );

	return( 0 );
}

int 
im_XYZ2sRGB( IMAGE *in, IMAGE *out )
{
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( (VipsObject *) out, 2 );

	if( vips_XYZ2scRGB( in, &t[0], NULL ) ||
		vips_scRGB2sRGB( t[0], &t[1], NULL ) ||
		vips_image_write( t[1], out ) ) 
		return( -1 );

	return( 0 );
}

int 
im_LabQ2sRGB( IMAGE *in, IMAGE *out )
{
	VipsImage *x;

	if( vips_LabQ2sRGB( in, &x, NULL ) )
		return( -1 );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_icc_transform( VipsImage *in, VipsImage *out, 
	const char *input_profile_filename,
	const char *output_profile_filename,
	VipsIntent intent )
{
	VipsImage *x;

	if( vips_icc_transform( in, &x, output_profile_filename,
		"input_profile", input_profile_filename,
		"intent", intent,
		NULL ) )
		return( -1 );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_icc_import( VipsImage *in, VipsImage *out, 
	const char *input_profile_filename, VipsIntent intent )
{
	VipsImage *x;

	if( vips_icc_import( in, &x, 
		"input_profile", input_profile_filename,
		"intent", intent,
		NULL ) )
		return( -1 );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_icc_import_embedded( VipsImage *in, VipsImage *out, VipsIntent intent )
{
	VipsImage *x;

	if( vips_icc_import( in, &x, 
		"embedded", TRUE,
		"intent", intent,
		NULL ) )
		return( -1 );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_icc_export_depth( VipsImage *in, VipsImage *out, int depth,
	const char *output_profile_filename, VipsIntent intent )
{
	VipsImage *x;

	if( vips_icc_export( in, &x, 
		"output_profile", output_profile_filename,
		"depth", depth,
		"intent", intent,
		NULL ) )
		return( -1 );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

/**
 * im_LabQ2XYZ:
 * @in: input image
 * @out: output image
 *
 * Convert an image from LabQ (Coding == IM_CODING_LABQ) to XYZ.
 *
 * Returns: 0 on success, -1 on error.
 */
int 
im_LabQ2XYZ( IMAGE *in, IMAGE *out )
{	
	IMAGE *t[1];

	if( im_open_local_array( out, t, 1, "im_LabQ2XYZ:1", "p" ) ||
		im_LabQ2Lab( in, t[0] ) ||
		im_Lab2XYZ( t[0], out ) )
		return( -1 );

	return( 0 );
}

int 
im_Lab2UCS( IMAGE *in, IMAGE *out )
{	
	IMAGE *t[1];

	if( im_open_local_array( out, t, 1, "im_Lab2UCS:1", "p" ) ||
		im_Lab2LCh( in, t[0] ) ||
		im_LCh2UCS( t[0], out ) )
		return( -1 );

	return( 0 );
}

int 
im_UCS2Lab( IMAGE *in, IMAGE *out )
{	
	IMAGE *t[1];

	if( im_open_local_array( out, t, 1, "im_UCS2Lab:1", "p" ) ||
		im_UCS2LCh( in, t[0] ) ||
		im_LCh2Lab( t[0], out ) )
		return( -1 );

	return( 0 );
}

int 
im_UCS2XYZ( IMAGE *in, IMAGE *out )
{
	IMAGE *t[1];

	if( im_open_local_array( out, t, 1, "im_UCS2XYZ:1", "p" ) ||
		im_UCS2Lab( in, t[0] ) ||
		im_Lab2XYZ( t[0], out ) )
		return( -1 );

	return( 0 );
}

int 
im_XYZ2UCS( IMAGE *in, IMAGE *out )
{	
	IMAGE *t[1];

	if( im_open_local_array( out, t, 1, "im_XYZ2UCS:1", "p" ) ||
		im_XYZ2Lab( in, t[0] ) ||
		im_Lab2UCS( t[0], out ) )
		return( -1 );

	return( 0 );
}

int 
im_dE_fromXYZ( IMAGE *in1, IMAGE *in2, IMAGE *out )
{	
	IMAGE *t[2];

	if( im_open_local_array( out, t, 2, "im_dE_fromXYZ:1", "p" ) ||
		im_XYZ2Lab( in1, t[0] ) ||
		im_XYZ2Lab( in2, t[1] ) ||
		im_dE_fromLab( t[0], t[1], out ) )
		return( -1 );

	return( 0 );
}

int 
im_dE_fromLab( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	VipsImage *x;

	if( vips_dE76( in1, in2, &x, 
		NULL ) )
		return( -1 );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_dECMC_fromLab( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	VipsImage *x;

	if( vips_dECMC( in1, in2, &x, 
		NULL ) )
		return( -1 );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_dE00_fromLab( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	VipsImage *x;

	if( vips_dE00( in1, in2, &x, 
		NULL ) )
		return( -1 );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int
im_icc_ac2rc( VipsImage *in, VipsImage *out, const char *profile_filename )
{
	VipsImage *x;

	if( vips_icc_ac2rc( in, &x, profile_filename ) )
		return( -1 );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_quadratic( IMAGE *in, IMAGE *out, IMAGE *coeff )
{
	VipsImage *x;

	if( vips_quadratic( in, &x, coeff, 
		NULL ) )
		return( -1 );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_maxpos_vec( VipsImage *im, int *xpos, int *ypos, double *maxima, int n )
{
	double max;
	VipsArrayDouble *out_array;
	VipsArrayInt *x_array;
	VipsArrayInt *y_array;

	if( vips_max( im, &max, 
		"size", n,
		"out_array", &out_array, 
		"x_array", &x_array, 
		"y_array", &y_array, 
		NULL ) )
		return( -1 );

	memcpy( xpos, VIPS_ARRAY_ADDR( x_array, 0 ), n * sizeof( int ) );
	memcpy( ypos, VIPS_ARRAY_ADDR( y_array, 0 ), n * sizeof( int ) );
	memcpy( maxima, VIPS_ARRAY_ADDR( out_array, 0 ), n * sizeof( double ) );

	vips_area_unref( VIPS_AREA( out_array ) );
	vips_area_unref( VIPS_AREA( x_array ) );
	vips_area_unref( VIPS_AREA( y_array ) );

	return( 0 );
}

int 
im_minpos_vec( VipsImage *im, int *xpos, int *ypos, double *minima, int n )
{
	double min;
	VipsArrayDouble *out_array;
	VipsArrayInt *x_array;
	VipsArrayInt *y_array;

	if( vips_min( im, &min, 
		"size", n,
		"out_array", &out_array, 
		"x_array", &x_array, 
		"y_array", &y_array, 
		NULL ) )
		return( -1 );

	memcpy( xpos, VIPS_ARRAY_ADDR( x_array, 0 ), n * sizeof( int ) );
	memcpy( ypos, VIPS_ARRAY_ADDR( y_array, 0 ), n * sizeof( int ) );
	memcpy( minima, VIPS_ARRAY_ADDR( out_array, 0 ), n * sizeof( double ) );

	vips_area_unref( VIPS_AREA( out_array ) );
	vips_area_unref( VIPS_AREA( x_array ) );
	vips_area_unref( VIPS_AREA( y_array ) );

	return( 0 );
}

int 
im_cross_phase( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	VipsImage *x;

	if( vips_call( "cross_phase", in1, in2, &x, NULL ) )
		return( -1 );

	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_maplut( IMAGE *in, IMAGE *out, IMAGE *lut )
{
	VipsImage *x;

	if( vips_maplut( in, &x, lut, NULL ) )
		return( -1 );

	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int
im_ismonotonic( IMAGE *lut, int *out )
{
	gboolean monotonic;

	if( vips_hist_ismonotonic( lut, &monotonic, NULL ) )
		return( -1 );

	*out = monotonic ? 255 : 0; 

	return( 0 );
}

int 
im_histcum( IMAGE *in, IMAGE *out )
{
	VipsImage *x;

	if( vips_hist_cum( in, &x, NULL ) )
		return( -1 );

	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_histnorm( IMAGE *in, IMAGE *out )
{
	VipsImage *x;

	if( vips_hist_norm( in, &x, NULL ) )
		return( -1 );

	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_histeq( IMAGE *in, IMAGE *out )
{
	IMAGE *t1;

	if( !(t1 = im_open_local( out, "im_histeq", "p" )) ||
		im_histcum( in, t1 ) || 
		im_histnorm( t1, out ) )
		return( -1 );

	return( 0 );
}

int 
im_heq( VipsImage *in, VipsImage *out, int bandno )
{
	VipsImage *x;

	if( vips_hist_equal( in, &x, "band", bandno, NULL ) )
		return( -1 );

	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 ); 
}

int 
im_hist( IMAGE *in, IMAGE *out, int bandno )
{
	IMAGE *hist;

	if( !(hist = im_open_local( out, "im_hist", "p" )) ||
		im_histgr( in, hist, bandno ) ||
		im_histplot( hist, out ) )
		return( -1 );

	return( 0 );
}

int 
im_histgr( IMAGE *in, IMAGE *out, int bandno )
{
	VipsImage *x;

	if( vips_hist_find( in, &x, 
		"band", bandno,
		NULL ) )
		return( -1 );

	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_stdif( IMAGE *in, IMAGE *out, 
	double a, double m0, double b, double s0, 
	int width, int height )
{
	VipsImage *x;

	if( vips_stdif( in, &x, width, height, 
		"a", a,
		"b", b,
		"m0", m0,
		"s0", s0,
		NULL ) )
		return( -1 );

	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_lhisteq( VipsImage *in, VipsImage *out, int width, int height )
{
	VipsImage *x;

	if( vips_hist_local( in, &x, width, height, NULL ) )
		return( -1 );

	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_histnD( VipsImage *in, VipsImage *out, int bins )
{
	VipsImage *x;

	if( vips_hist_find_ndim( in, &x, 
		"bins", bins,
		NULL ) )
		return( -1 );

	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_hist_indexed( VipsImage *index, VipsImage *value, VipsImage *out )
{
	VipsImage *x;

	if( vips_hist_find_indexed( value, index, &x, NULL ) )
		return( -1 );

	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_project( IMAGE *in, IMAGE *hout, IMAGE *vout )
{
	VipsImage *x, *y;

	if( vips_project( in, &x, &y, NULL ) )
		return( -1 );

	if( vips_image_write( x, hout ) ) {
		g_object_unref( x );
		g_object_unref( y );
		return( -1 );
	}
	g_object_unref( x );

	if( vips_image_write( y, vout ) ) {
		g_object_unref( y );
		return( -1 );
	}
	g_object_unref( y );

	return( 0 );
}

int 
im_profile( IMAGE *in, IMAGE *out, int dir )
{
	VipsImage *columns, *rows;
	VipsImage *t1, *t2;

	if( vips_profile( in, &columns, &rows, NULL ) )
		return( -1 );
	if( dir == 0 ) {
		t1 = columns;
		g_object_unref( rows );
	}
	else {
		t1 = rows;
		g_object_unref( columns );
	}

	if( vips_cast( t1, &t2, VIPS_FORMAT_USHORT, NULL ) ) {
		g_object_unref( t1 );
		return( -1 );
	}
	g_object_unref( t1 );

	if( vips_image_write( t2, out ) ) {
		g_object_unref( t2 );
		return( -1 );
	}
	g_object_unref( t2 );

	return( 0 ); 
}

int
im_erode( IMAGE *in, IMAGE *out, INTMASK *mask )
{
	VipsImage *t1, *t2;

	if( !(t1 = vips_image_new()) ||
		im_imask2vips( mask, t1 ) )
		return( -1 );

	if( vips_morph( in, &t2, t1, VIPS_OPERATION_MORPHOLOGY_ERODE,
		NULL ) ) {
		g_object_unref( t1 );
		return( -1 );
	}
	g_object_unref( t1 );

	if( vips_image_write( t2, out ) ) {
		g_object_unref( t2 );
		return( -1 );
	}
	g_object_unref( t2 );

	return( 0 );
}

int
im_erode_raw( IMAGE *in, IMAGE *out, INTMASK *m )
{
	return( im_erode( in, out, m ) );
}

int
im_dilate( IMAGE *in, IMAGE *out, INTMASK *mask )
{
	VipsImage *t1, *t2;

	if( !(t1 = vips_image_new()) ||
		im_imask2vips( mask, t1 ) )
		return( -1 );

	if( vips_morph( in, &t2, t1, VIPS_OPERATION_MORPHOLOGY_DILATE,
		NULL ) ) {
		g_object_unref( t1 );
		return( -1 );
	}
	g_object_unref( t1 );

	if( vips_image_write( t2, out ) ) {
		g_object_unref( t2 );
		return( -1 );
	}
	g_object_unref( t2 );

	return( 0 );
}

int
im_dilate_raw( IMAGE *in, IMAGE *out, INTMASK *m )
{
	return( im_dilate( in, out, m ) );
}

int
im_mpercent( IMAGE *in, double percent, int *out )
{
	if( vips_percent( in, percent * 100.0, out, NULL ) )
		return( -1 ); 

	return( 0 );
}

int
im_mpercent_hist( IMAGE *in, double percent, int *out )
{
	/* Hard to do this in a wrapper.
	 */
	vips_error( "im_mpercent_hist", "%s", _( "no compat implemented" ) ); 

	return( -1 ); 
}

int 
im_hsp( IMAGE *in, IMAGE *ref, IMAGE *out )
{
	IMAGE *t[3];

	if( im_open_local_array( out, t, 3, "im_hsp", "p" ) ||
		im_histgr( in, t[0], -1 ) || 
		im_histgr( ref, t[1], -1 ) ||
		im_histspec( t[0], t[1], t[2] ) ||
		im_maplut( in, out, t[2] ) )
		return( -1 );

	return( 0 );
}

static int
match( VipsImage *in, VipsImage *ref, VipsImage *out )
{
	VipsImage *x;

	if( vips_hist_match( in, ref, &x, NULL ) )
		return( -1 );

	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_histspec( IMAGE *in, IMAGE *ref, IMAGE *out )
{
	IMAGE *t[5];
	guint64 px;
	int fmt;

	if( im_check_uint( "im_histspec", in ) ||
		im_check_uint( "im_histspec", ref ) )
		return( -1 );

	if( im_open_local_array( out, t, 5, "im_histspec", "p" ) ||
		im_histeq( in, t[0] ) || 
		im_histeq( ref, t[2] ) ||
		match( t[0], t[2], t[4] ) )
		return( -1 );

	px = VIPS_IMAGE_N_PELS( t[4] );
	if( px <= 256 ) 
		fmt = IM_BANDFMT_UCHAR;
	else if( px <= 65536 ) 
		fmt = IM_BANDFMT_USHORT;
	else 
		fmt = IM_BANDFMT_UINT;

	if( im_clip2fmt( t[4], out, fmt ) )
		return( -1 );

        return( 0 );
}

int 
im_falsecolour( IMAGE *in, IMAGE *out )
{
	VipsImage *x;

	if( vips_falsecolour( in, &x, NULL ) )
		return( -1 );

	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_gammacorrect( IMAGE *in, IMAGE *out, double exponent )
{
	VipsImage *x;

	if( vips_gamma( in, &x, 
		"exponent", 1.0 / exponent,
		NULL ) )
		return( -1 );

	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

/* This is used by the carrierwave shrinker to cache the
 * output of shrink before doing the final affine.
 *
 * We use the vips8 threaded tilecache to avoid a deadlock: suppose thread1,
 * evaluating the top block of the output is delayed, and thread2, evaluating
 * the second block gets here first (this can happen on a heavily-loaded
 * system). 
 *
 * With an unthreaded tilecache (as we had before), thread2 will get
 * the cache lock and start evaling the second block of the shrink. When it
 * reaches the png reader it will stall until the first block has been used ...
 * but it never will, since thread1 will block on this cache lock. 
 *
 * This function is only used in this place (I think), so it's OK to
 * hard-wire this to be a sequential threaded cache. 
 */
int
im_tile_cache( IMAGE *in, IMAGE *out,
	int tile_width, int tile_height, int max_tiles )
{
	VipsImage *x;

	if( vips_tilecache( in, &x, 
		"tile_width", tile_width, 
		"tile_height", tile_height, 
		"max_tiles", max_tiles, 
		"access", VIPS_ACCESS_SEQUENTIAL,
		"threaded", TRUE, 
		NULL ) )
		return( -1 );

	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

/* This is the one used by nip2's menu for caching images. Random access and
 * persistent. 
 */
int
im_tile_cache_random( IMAGE *in, IMAGE *out,
	int tile_width, int tile_height, int max_tiles )
{
	VipsImage *x;

	if( vips_tilecache( in, &x, 
		"tile_width", tile_width, 
		"tile_height", tile_height, 
		"max_tiles", max_tiles, 
		"access", VIPS_ACCESS_RANDOM,
		"persistent", TRUE,
		"threaded", TRUE, 
		NULL ) )
		return( -1 );

	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

static int 
im__affinei( VipsImage *in, VipsImage *out, 
	VipsInterpolate *interpolate, VipsTransformation *trn )
{
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( VIPS_OBJECT( out ), 2 );

	VipsArea *oarea;
	gboolean repack;

	oarea = VIPS_AREA( vips_array_int_newv( 4, 
		trn->oarea.left, trn->oarea.top,
		trn->oarea.width, trn->oarea.height ) );

	/* vips7 affine would repack labq and im_benchmark() depends upon
	 * this.
	 */
	repack = in->Coding == IM_CODING_LABQ;

	if( vips_affine( in, &t[0], 
		trn->a, trn->b, trn->c, trn->d,
		"interpolate", interpolate,
		"oarea", oarea,
		"odx", trn->odx,
		"ody", trn->ody,
		NULL ) ) {
		vips_area_unref( oarea );
		return( -1 );
	}
	vips_area_unref( oarea );
	in = t[0];

	if( repack ) {
		if( vips_colourspace( in, &t[1], 
			VIPS_INTERPRETATION_LABQ, NULL ) )
			return( -1 );
		in = t[1];
	}

	if( vips_image_write( in, out ) ) 
		return( -1 );

	return( 0 );
}

int 
im_affinei( VipsImage *in, VipsImage *out, VipsInterpolate *interpolate,
	double a, double b, double c, double d, double odx, double ody, 
	int ox, int oy, int ow, int oh )
{
	VipsTransformation trn;

	trn.iarea.left = 0;
	trn.iarea.top = 0;
	trn.iarea.width = in->Xsize;
	trn.iarea.height = in->Ysize;

	trn.oarea.left = ox;
	trn.oarea.top = oy;
	trn.oarea.width = ow;
	trn.oarea.height = oh;

	trn.a = a;
	trn.b = b;
	trn.c = c;
	trn.d = d;
	trn.idx = 0;
	trn.idy = 0;
	trn.odx = odx;
	trn.ody = ody;

	return( im__affinei( in, out, interpolate, &trn ) );
}

int 
im_affinei_all( VipsImage *in, VipsImage *out, VipsInterpolate *interpolate,
	double a, double b, double c, double d, double odx, double ody ) 
{
	VipsTransformation trn;

	trn.iarea.left = 0;
	trn.iarea.top = 0;
	trn.iarea.width = in->Xsize;
	trn.iarea.height = in->Ysize;
	trn.a = a;
	trn.b = b;
	trn.c = c;
	trn.d = d;
	trn.idx = 0;
	trn.idy = 0;
	trn.odx = odx;
	trn.ody = ody;

	vips__transform_set_area( &trn );

	return( im__affinei( in, out, interpolate, &trn ) );
}

/* Still needed by some parts of mosaic.
 */
int 
vips__affine( VipsImage *in, VipsImage *out, VipsTransformation *trn )
{
	return( im__affinei( in, out, 
		vips_interpolate_bilinear_static(), trn ) );
}

int
im_copy_file( IMAGE *in, IMAGE *out )
{
	VipsImage *x;

	if( vips_copy_file( in, &x, NULL ) )
		return( -1 );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int
im_video_v4l1( IMAGE *im, const char *device,
	int channel, int brightness, int colour, int contrast, int hue, 
	int ngrabs )
{
	im_error( "im_video_v4l1", 
		"%s", _( "compiled without im_video_v4l1 support" ) );
	return( -1 );
}

int 
im_fwfft( IMAGE *in, IMAGE *out )
{
	VipsImage *x;

	if( vips_fwfft( in, &x, NULL ) )
		return( -1 );

	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_invfft( IMAGE *in, IMAGE *out )
{
	VipsImage *x;

	if( vips_invfft( in, &x, NULL ) )
		return( -1 );

	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_invfftr( IMAGE *in, IMAGE *out )
{
	VipsImage *x;

	if( vips_invfft( in, &x, 
		"real", TRUE,
		NULL ) )
		return( -1 );

	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_freqflt( IMAGE *in, IMAGE *mask, IMAGE *out )
{
	VipsImage *x;

	if( vips_freqmult( in, mask, &x, NULL ) )
		return( -1 );

	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_disp_ps( IMAGE *in, IMAGE *out )
{
	VipsImage *t;

	if( vips_spectrum( in, &t, NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_fractsurf( IMAGE *out, int size, double frd )
{
	VipsImage *t;

	if( vips_fractsurf( &t, size, size, frd, NULL ) )
		return( -1 );
	if( vips_image_write( t, out ) ) {
		g_object_unref( t );
		return( -1 );
	}
	g_object_unref( t );

	return( 0 );
}

int 
im_phasecor_fft( IMAGE *in1, IMAGE *in2, IMAGE *out )
{
	VipsImage *x;

	if( vips_phasecor( in1, in2, &x, NULL ) )
		return( -1 );

	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_cntlines( VipsImage *im, double *nolines, int flag )
{
	return( vips_countlines( im, nolines, 
		flag == 0 ? 
			VIPS_DIRECTION_HORIZONTAL : VIPS_DIRECTION_VERTICAL,
		NULL ) );
}

int
im_label_regions( IMAGE *test, IMAGE *mask, int *segments )
{
	VipsImage *x;

	if( vips_labelregions( test, &x, "segments", segments, NULL ) )
		return( -1 );

	if( vips_image_write( x, mask ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_rank( IMAGE *in, IMAGE *out, int width, int height, int index )
{
	VipsImage *x;

	if( vips_rank( in, &x, width, height, index, NULL ) )
		return( -1 );

	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int
im_rank_raw( IMAGE *in, IMAGE *out, int width, int height, int index )
{
	im_error( "im_rank_raw", "no compat function" );
	return( -1 );
}

int
im_draw_circle( VipsImage *image, 
	int x, int y, int radius, gboolean fill, VipsPel *ink )
{
	double *vec;
	int n;

	if( !(vec = vips__ink_to_vector( "im_draw_circle", image, ink, &n )) )
		return( -1 ); 

	return( vips_draw_circle( image, vec, n, x, y, radius,
		"fill", fill,
		NULL ) ); 
}

int 
im_draw_line( VipsImage *image, int x1, int y1, int x2, int y2, VipsPel *ink )
{
	double *vec;
	int n;

	if( !(vec = vips__ink_to_vector( "im_draw_line", image, ink, &n )) )
		return( -1 ); 

	return( vips_draw_line( image, vec, n, x1, y1, x2, y2, NULL ) ); 
}

typedef struct _Line {
	VipsPlotFn plot;
	void *a;
	void *b;
	void *c;
} Line;

static void
draw_line_wrapper( VipsImage *image, int x, int y, void *client )
{
	Line *line = (Line *) client;

	line->plot( image, x, y, line->a, line->b, line->c ); 
}

int 
im_draw_line_user( VipsImage *image, 
	int x1, int y1, int x2, int y2, 
	VipsPlotFn plot, void *a, void *b, void *c )
{
	Line line;

	line.plot = plot;
	line.a = a;
	line.b = b;
	line.c = c;

	vips__draw_line_direct( image, x1, y1, x2, y2, 
		draw_line_wrapper, &line ); 
	
	return( 0 );
}

int
im_draw_mask( VipsImage *image, VipsImage *mask, int x, int y, VipsPel *ink )
{
	/* Direct call, since this has to be very quick.
	 */
	return( vips__draw_mask_direct( image, mask, ink, x, y ) ); 
}

int
im_draw_image( VipsImage *image, VipsImage *sub, int x, int y )
{
	return( vips_draw_image( image, sub, x, y, NULL ) ); 
}

int
im_draw_rect( IMAGE *image, 
	int left, int top, int width, int height, int fill, VipsPel *ink )
{
	double *vec;
	int n;

	if( !(vec = vips__ink_to_vector( "im_draw_rect", image, ink, &n )) )
		return( -1 ); 

	return( vips_draw_rect( image, vec, n, left, top, width, height,
		"fill", fill, 
		NULL ) ); 
}

int
im_draw_point( VipsImage *image, int x, int y, VipsPel *ink )
{
	double *vec;
	int n;

	if( !(vec = vips__ink_to_vector( "im_draw_rect", image, ink, &n )) )
		return( -1 ); 

	return( vips_draw_point( image, vec, n, x, y, NULL ) ); 
}

int
im_draw_smudge( VipsImage *im, int left, int top, int width, int height )
{
	return( vips_draw_smudge( im, left, top, width, height, NULL ) ); 
}

int
im_read_point( VipsImage *image, int x, int y, VipsPel *ink )
{
	double *vector;
	int n;
	VipsPel *pixel_vector;

	if( vips_getpoint( image, &vector, &n, x, y, NULL ) )
		return( -1 );

	if( !(pixel_vector = vips__vector_to_ink( "im_read_point", 
		image, vector, NULL, n )) ) {
		g_free( vector );
		return( -1 );
	}

	memcpy( ink, pixel_vector, VIPS_IMAGE_SIZEOF_PEL( image ) ); 

	g_free( vector );

	return( 0 );
}

int
im_draw_flood( IMAGE *image, int x, int y, VipsPel *ink, Rect *dout )
{
	double *vec;
	int n;
	int left;
	int top;
	int width;
	int height;

	if( !(vec = vips__ink_to_vector( "im_draw_flood", image, ink, &n )) )
		return( -1 ); 

	if( vips_draw_flood( image, vec, n, x, y,
		"left", &left,
		"top", &top,
		"width", &width,
		"height", &height,
		NULL ) )
		return( -1 ); 

	if( dout ) { 
		dout->left = left; 
		dout->top = top; 
		dout->width = width; 
		dout->height = height; 
	}

	return( 0 ); 
}

int
im_draw_flood_blob( IMAGE *image, int x, int y, VipsPel *ink, Rect *dout )
{
	double *vec;
	int n;
	int left;
	int top;
	int width;
	int height;

	if( !(vec = vips__ink_to_vector( "im_draw_flood", image, ink, &n )) )
		return( -1 ); 

	if( vips_draw_flood( image, vec, n, x, y,
		"equal", TRUE,
		"left", &left,
		"top", &top,
		"width", &width,
		"height", &height,
		NULL ) )
		return( -1 ); 

	if( dout ) { 
		dout->left = left; 
		dout->top = top; 
		dout->width = width; 
		dout->height = height; 
	}

	return( 0 ); 
}

int
im_draw_flood_other( IMAGE *image, 
	IMAGE *test, int x, int y, int serial, Rect *dout )
{
	int left;
	int top;
	int width;
	int height;

	if( vips_draw_flood1( image, serial, x, y,
		"test", test,
		"equal", TRUE,
		"left", &left,
		"top", &top,
		"width", &width,
		"height", &height,
		NULL ) )
		return( -1 ); 

	if( dout ) { 
		dout->left = left; 
		dout->top = top; 
		dout->width = width; 
		dout->height = height; 
	} 

	return( 0 ); 
}

int
im_lineset( IMAGE *in, IMAGE *out, IMAGE *mask, IMAGE *ink,
	int n, int *x1v, int *y1v, int *x2v, int *y2v )
{
	Rect mask_rect;
	int i;

	if( mask->Bands != 1 || mask->BandFmt != IM_BANDFMT_UCHAR ||
		mask->Coding != IM_CODING_NONE ) {
		im_error( "im_lineset", 
			"%s", _( "mask image not 1 band 8 bit uncoded" ) );
		return( -1 );
	}
	if( ink->Bands != in->Bands || ink->BandFmt != in->BandFmt ||
		ink->Coding != in->Coding ) {
		im_error( "im_lineset", 
			"%s", _( "ink image does not match in image" ) );
		return( -1 );
	}
	if( ink->Xsize != 1 || ink->Ysize != 1 ) {
		im_error( "im_lineset", "%s", _( "ink image not 1x1 pixels" ) );
		return( -1 );
	}

	/* Copy the image then fastline to it ... this will render to a "t"
	 * usually.
	 */
	if( vips_image_write( in, out ) )
		return( -1 );

	mask_rect.left = mask->Xsize / 2;
	mask_rect.top = mask->Ysize / 2;
	mask_rect.width = mask->Xsize;
	mask_rect.height = mask->Ysize;

	if( im_incheck( ink ) ||
		im_incheck( mask ) )
		return( -1 );

	for( i = 0; i < n; i++ ) {
		if( im_fastlineuser( out, x1v[i], y1v[i], x2v[i], y2v[i], 
			(VipsPlotFn) im_plotmask, ink->data, mask->data, &mask_rect ) )
			return( -1 );
	}

	return( 0 );
}

int
im_match_linear_search( IMAGE *ref, IMAGE *sec, IMAGE *out,
	int xr1, int yr1, int xs1, int ys1, 
	int xr2, int yr2, int xs2, int ys2,
	int hwindowsize, int hsearchsize )
{
	VipsImage *x;

	if( vips_match( ref, sec, &x,
		xr1, yr1, xs1, ys1, xr2, yr2, xs2, ys2,
		"search", TRUE,
		"hwindow", hwindowsize,
		"harea", hsearchsize,
		NULL ) )
		return( -1 );

	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int
im_match_linear( IMAGE *ref, IMAGE *sec, IMAGE *out,
	int xr1, int yr1, int xs1, int ys1, 
	int xr2, int yr2, int xs2, int ys2 )
{ 
	VipsImage *x;

	if( vips_match( ref, sec, &x,
		xr1, yr1, xs1, ys1, xr2, yr2, xs2, ys2,
		NULL ) )
		return( -1 );

	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int
im_global_balance( IMAGE *in, IMAGE *out, double gamma )
{
	VipsImage *x;

	if( vips_globalbalance( in, &x,
		"gamma", gamma,
		"int_output", TRUE,
		NULL ) )
		return( -1 );

	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int 
im_histplot( IMAGE *in, IMAGE *out )
{
	VipsImage *x;

	if( vips_hist_plot( in, &x, NULL ) )
		return( -1 );

	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int
im_global_balancef( IMAGE *in, IMAGE *out, double gamma )
{
	VipsImage *x;

	if( vips_globalbalance( in, &x,
		"gamma", gamma,
		NULL ) )
		return( -1 );

	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int
im_remosaic( IMAGE *in, IMAGE *out, const char *old_str, const char *new_str )
{
	VipsImage *x;

	if( vips_remosaic( in, &x, old_str, new_str, NULL ) ) 
		return( -1 );

	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int
im_lrmosaic( IMAGE *ref, IMAGE *sec, IMAGE *out,
	int bandno,
	int xref, int yref, int xsec, int ysec,
 	int hwindowsize, int hsearchsize,
	int balancetype,
	int mwidth )
{
	VipsImage *x;

	if( vips_mosaic( ref, sec, &x, VIPS_DIRECTION_HORIZONTAL,
		xref, yref, xsec, ysec,
		"hwindow", hwindowsize,
		"harea", hsearchsize,
		"mblend", mwidth,
		NULL ) ) 
		return( -1 );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int
im_lrmosaic1( IMAGE *ref, IMAGE *sec, IMAGE *out, 
	int bandno,
	int xr1, int yr1, int xs1, int ys1, 
	int xr2, int yr2, int xs2, int ys2,
	int hwindowsize, int hsearchsize,
	int balancetype,
	int mwidth )
{ 
	VipsImage *x;

	if( vips_mosaic1( ref, sec, &x, VIPS_DIRECTION_HORIZONTAL,
		xr1, yr1, xs1, ys1, xr2, yr2, xs2, ys2,
		"search", TRUE,
		"bandno", bandno,
		"hwindow", hwindowsize,
		"harea", hsearchsize,
		"mblend", mwidth,
		NULL ) ) 
		return( -1 );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int
im_tbmosaic( IMAGE *ref, IMAGE *sec, IMAGE *out,
	int bandno,
	int xref, int yref, int xsec, int ysec,
 	int hwindowsize, int hsearchsize,
	int balancetype,
	int mwidth )
{
	VipsImage *x;

	if( vips_mosaic( ref, sec, &x, VIPS_DIRECTION_VERTICAL,
		xref, yref, xsec, ysec,
		"hwindow", hwindowsize,
		"harea", hsearchsize,
		"mblend", mwidth,
		NULL ) ) 
		return( -1 );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int
im_tbmosaic1( IMAGE *ref, IMAGE *sec, IMAGE *out,
	int bandno,
	int xr1, int yr1, int xs1, int ys1, 
	int xr2, int yr2, int xs2, int ys2,
	int hwindowsize, int hsearchsize,
	int balancetype,
	int mwidth )
{ 
	VipsImage *x;

	if( vips_mosaic1( ref, sec, &x, VIPS_DIRECTION_VERTICAL,
		xr1, yr1, xs1, ys1, xr2, yr2, xs2, ys2,
		"search", TRUE,
		"bandno", bandno,
		"hwindow", hwindowsize,
		"harea", hsearchsize,
		"mblend", mwidth,
		NULL ) ) 
		return( -1 );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int
im_correl( VipsImage *ref, VipsImage *sec,
	int xref, int yref, int xsec, int ysec,
	int hwindowsize, int hsearchsize,
	double *correlation, int *x, int *y )
{
	return( vips__correl( ref, sec, xref, yref, xsec, ysec,
		hwindowsize, hsearchsize, correlation, x, y ) );
}

int
im_lrmerge( IMAGE *ref, IMAGE *sec, IMAGE *out,
	int dx, int dy, int mwidth )
{
	VipsImage *x;

	if( vips_merge( ref, sec, &x, VIPS_DIRECTION_HORIZONTAL, dx, dy,
		"mblend", mwidth,
		NULL ) ) 
		return( -1 );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int
im_lrmerge1( IMAGE *ref, IMAGE *sec, IMAGE *out,
	int xr1, int yr1, int xs1, int ys1, 
	int xr2, int yr2, int xs2, int ys2,
	int mwidth )
{
	VipsImage *x;

	if( vips_mosaic1( ref, sec, &x, VIPS_DIRECTION_HORIZONTAL,
		xr1, yr1, xs1, ys1, xr2, yr2, xs2, ys2,
		"mblend", mwidth,
		NULL ) ) 
		return( -1 );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int
im_tbmerge( IMAGE *ref, IMAGE *sec, IMAGE *out,
	int dx, int dy, int mwidth )
{
	VipsImage *x;

	if( vips_merge( ref, sec, &x, VIPS_DIRECTION_VERTICAL, dx, dy,
		"mblend", mwidth,
		NULL ) ) 
		return( -1 );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

int
im_tbmerge1( IMAGE *ref, IMAGE *sec, IMAGE *out,
	int xr1, int yr1, int xs1, int ys1, 
	int xr2, int yr2, int xs2, int ys2,
	int mwidth )
{
	VipsImage *x;

	if( vips_mosaic1( ref, sec, &x, VIPS_DIRECTION_VERTICAL,
		xr1, yr1, xs1, ys1, xr2, yr2, xs2, ys2,
		"mblend", mwidth,
		NULL ) ) 
		return( -1 );
	if( vips_image_write( x, out ) ) {
		g_object_unref( x );
		return( -1 );
	}
	g_object_unref( x );

	return( 0 );
}

/* The common part of most binary conversion
 * operators. We:
 *
 * - check in and out
 * - cast in1 and in2 up to a common format
 * - equalise bands 
 * - make an input array
 * - return the matched images in vec[0] and vec[1]
 *
 * A left-over, remove soon.
 */
IMAGE **
im__insert_base( const char *domain, 
	IMAGE *in1, IMAGE *in2, IMAGE *out ) 
{
	IMAGE *t[4];
	IMAGE **vec;

	if( im_piocheck( in1, out ) || 
		im_pincheck( in2 ) ||
		im_check_bands_1orn( domain, in1, in2 ) ||
		im_check_coding_known( domain, in1 ) ||
		im_check_coding_same( domain, in1, in2 ) )
		return( NULL );

	/* Cast our input images up to a common format and bands.
	 */
	if( im_open_local_array( out, t, 4, domain, "p" ) ||
		im__formatalike( in1, in2, t[0], t[1] ) ||
		im__bandalike( domain, t[0], t[1], t[2], t[3] ) ||
		!(vec = im_allocate_input_array( out, t[2], t[3], NULL )) )
		return( NULL );

	/* Generate the output.
	 */
	if( im_cp_descv( out, vec[0], vec[1], NULL ) ||
		im_demand_hint_array( out, IM_SMALLTILE, vec ) )
		return( NULL );

	return( vec );
}

/**
 * im_insertset:
 * @main: big image
 * @sub: small image
 * @out: output image
 * @n: number of positions
 * @x: left positions of @sub
 * @y: top positions of @sub
 *
 * Insert @sub repeatedly into @main at the positions listed in the arrays @x,
 * @y of length @n. @out is the same
 * size as @main. @sub is clipped against the edges of @main. 
 *
 * This operation is fast for large @n, but will use a memory buffer the size
 * of @out. It's useful for things like making scatter plots.
 *
 * If the number of bands differs, one of the images 
 * must have one band. In this case, an n-band image is formed from the 
 * one-band image by joining n copies of the one-band image together, and then
 * the two n-band images are operated upon.
 *
 * The two input images are cast up to the smallest common type (see table 
 * Smallest common format in 
 * <link linkend="VIPS-arithmetic">arithmetic</link>).
 *
 * See also: im_insert(), im_lrjoin().
 *
 * Returns: 0 on success, -1 on error
 */
int
im_insertset( IMAGE *main, IMAGE *sub, IMAGE *out, int n, int *x, int *y )
{
	IMAGE **vec;
	IMAGE *t;
	int i;

	if( !(vec = im__insert_base( "im_insert", main, sub, out )) )
		return( -1 );

	/* Copy to a memory image, zap that, then copy to out.
	 */
	if( !(t = im_open_local( out, "im_insertset", "t" )) ||
		im_copy( vec[0], t ) )
		return( -1 );

	for( i = 0; i < n; i++ ) 
		if( im_insertplace( t, vec[1], x[i], y[i] ) )
			return( -1 );

	if( im_copy( t, out ) )
		return( -1 );

	return( 0 );
}

/* We had this entry point in earlier libvipses, hilariously.
 */
int
vips__init( const char *argv0 )
{
	return( vips_init( argv0 ) );
}

int
im_greyc_mask( IMAGE *in, IMAGE *out, IMAGE *mask,
	int iterations,
	float amplitude, float sharpness, float anisotropy,
	float alpha, float sigma,
	float dl, float da, float gauss_prec,
	int interpolation, int fast_approx )
{
	vips_error( "im_greyc_mask", 
		"This function is no longer in the core library" ); 

	return( -1 ); 
}

int
vips_check_imask( const char *domain, INTMASK *mask )
{
	if( !mask || 
		mask->xsize > 1000 || 
		mask->ysize > 1000 || 
		mask->xsize <= 0 || 
		mask->ysize <= 0 || 
		mask->scale == 0 || 
		!mask->coeff ) {
		vips_error( domain, "%s", _( "nonsense mask parameters" ) );
		return( -1 );
	}

	return( 0 );
}

int
vips_check_dmask( const char *domain, DOUBLEMASK *mask )
{
	if( !mask || 
		mask->xsize > 1000 || 
		mask->ysize > 1000 || 
		mask->xsize <= 0 || 
		mask->ysize <= 0 || 
		mask->scale == 0 || 
		!mask->coeff ) {
		vips_error( domain, "%s", _( "nonsense mask parameters" ) );
		return( -1 );
	}

	return( 0 );
}

int
vips_check_dmask_1d( const char *domain, DOUBLEMASK *mask )
{
	if( vips_check_dmask( domain, mask ) )
		return( -1 );
	if( mask->xsize != 1 &&
		mask->ysize != 1 ) {
		vips_error( domain, "%s", _( "mask must be 1D" ) );
		return( -1 );
	}

	return( 0 );
}

GOptionGroup *
vips_get_option_group( void )
{
	static GOptionGroup *option_group = NULL;

	if( !option_group ) {
		option_group = g_option_group_new( "vips", 
				_( "VIPS Options" ), _( "Show VIPS options" ),
				NULL, NULL );
		vips_add_option_entries( option_group ); 
	}

	return( option_group );
}

/* We used to use this for system() back in the day. But it's awkward to make
 * it work properly on win32, so this is now deprecated.
 */
FILE *
vips_popenf( const char *fmt, const char *mode, ... )
{
        vips_error( "popenf", "%s", _( "deprecated" ) );
        return( NULL );
}

/* We used to use this for getpoint(), but since it was the only caller in
 * vips8 it's now deprecated.
 */
double *
vips__ink_to_vector( const char *domain, VipsImage *im, VipsPel *ink, int *n )
{
	VipsImage **t = (VipsImage **) 
		vips_object_local_array( VIPS_OBJECT( im ), 6 );

	double *result;

#ifdef VIPS_DEBUG
	printf( "vips__ink_to_vector: starting\n" );
#endif /*VIPS_DEBUG*/

	/* Wrap a VipsImage around ink.
	 */
	t[0] = vips_image_new_from_memory( ink, VIPS_IMAGE_SIZEOF_PEL( im ),
		1, 1, VIPS_IMAGE_SIZEOF_PEL( im ), VIPS_FORMAT_UCHAR );
	if( vips_copy( t[0], &t[1], 
		"bands", im->Bands, 
		"format", im->BandFmt, 
		"coding", im->Coding, 
		"interpretation", im->Type, 
		NULL ) )
		return( NULL ); 

	/* The image may be coded .. unpack to double.
	 */
	if( vips_image_decode( t[1], &t[2] ) ||
		vips_cast( t[2], &t[3], VIPS_FORMAT_DOUBLE, NULL ) )
		return( NULL );

	/* To a mem buffer, then copy to out. 
	 */
	if( !(t[4] = vips_image_new_memory()) ||
		vips_image_write( t[3], t[4] ) )
		return( NULL ); 

	if( !(result = VIPS_ARRAY( im, t[4]->Bands, double )) )
		return( NULL ); 
	memcpy( result, t[4]->data, VIPS_IMAGE_SIZEOF_PEL( t[4] ) ); 
	*n = t[4]->Bands; 

#ifdef VIPS_DEBUG
{
	int i;

	printf( "vips__ink_to_vector:\n" );
	printf( "\tink = " ); 
	for( i = 0; i < n; i++ )
		printf( "%d ", ink[i] );
	printf( "\n" ); 

	printf( "\tvec = " ); 
	for( i = 0; i < *n; i++ )
		printf( "%g ", result[i] );
	printf( "\n" ); 
}
#endif /*VIPS_DEBUG*/

	return( result ); 
}

