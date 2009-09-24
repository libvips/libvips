/* @(#)  display VIPS IMAGE descriptor for debugging
 * @(#)  a valid IMAGE descriptor is needed
 * @(#) HANDLESIMAGE
 * @(#)  Static strings must be modified if header files are changed
 * @(#) void im_printdesc(image)
 * @(#) IMAGE *image;
 *
 * Copyright: Nicos Dessipris
 * Written on: 15/01/1990
 * Modified on : 3/6/92 Kirk Martinez
 * 15/4/93 JC
 *	- partial regions dumped too
 *	- resolution bug fixed
 * 11/5/93 JC
 *	- formatting changed for ctags
 * 1/7/93 JC
 *	- adapted for partial v2
 * 15/11/94 JC
 *	- new Coding types added
 *	- new Type values added
 *	- new Compression type added
 * 2/3/98 JC
 *	- IM_ANY added
 * 5/11/98 JC
 *	- prints byte-order too
 * 1/8/05
 * 	- prints meta header fields too
 * 9/9/05
 * 	- oops, shouldn't print filename ourselves
 * 4/1/07
 * 	- use new im_history_get() thing
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

#include <stdio.h>
#include <string.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

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
	"IM_TYPE_GREY16"		/* 26 */
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
	"IM_BANDFMT_DPCOMPLEX"
};

static const char *im_Coding[] = {
	"IM_CODING_NONE", 
	"COLQUANT8", 
	"IM_CODING_LABQ", 
	"IM_CODING_LABQ_COMPRESSED",
	"RGB_COMPRESSED",
	"LUM_COMPRESSED",
	"IM_CODING_RAD"
};

static const char *im_Compression[] = {
	"NO_COMPRESSION", 
	"TCSF_COMPRESSION", 
	"JPEG_COMPRESSION"
};

static const char *im_dtype[] = {
	"IM_NONE", 
	"IM_SETBUF", 
	"IM_SETBUF_FOREIGN", 
	"IM_OPENIN", 
	"IM_MMAPIN", 
	"IM_MMAPINRW", 
	"IM_OPENOUT", 
	"IM_PARTIAL"
};

static const char *im_dhint[] = {
	"IM_SMALLTILE", 
	"IM_FATSTRIP", 
	"IM_THINSTRIP", 
	"IM_ANY"
};

/* Stuff to decode an enum.
 */
typedef struct _EnumTable {
	const char *error;	/* eg. "<bad Coding>" */
	const char **names;	/* eg. {"IM_CODING_NONE",..} */
	int nnames;
} EnumTable;

static EnumTable enumType = {
	N_( "<bad Type>" ),
	im_Type,
	IM_NUMBER( im_Type )
};

static EnumTable enumBandFmt = {
	N_( "<bad BandFmt>" ),
	im_BandFmt,
	IM_NUMBER( im_BandFmt )
};

static EnumTable enumCoding = {
	N_( "<bad Coding>" ),
	im_Coding,
	IM_NUMBER( im_Coding )
};

static EnumTable enumCompression = {
	N_( "<bad Compression>" ),
	im_Compression,
	IM_NUMBER( im_Compression )
};

static EnumTable enumdtype = {
	N_( "<bad dtype>" ),
	im_dtype,
	IM_NUMBER( im_dtype )
};

static EnumTable enumdhint = {
	N_( "<bad dhint>" ),
	im_dhint,
	IM_NUMBER( im_dhint )
};

static const char *
enum2char( EnumTable *etable, int n )
{
	if( n < 0 || n > etable->nnames ) 
		return( _( etable->error ) );
	else
		return( etable->names[n] );
}

static int
char2enum( EnumTable *etable, const char *name )
{
	int i;

	for( i = 0; i < etable->nnames; i++ )
		if( g_ascii_strcasecmp( etable->names[i], name ) == 0 )
			return( i );

	im_error( "char2enum", "%s", _( etable->error ) );

	return( -1 );
}


/* Prettyprint various header fields.
 */
const char *im_Type2char( VipsType type ) 
	{ return( enum2char( &enumType, type ) ); }
const char *im_BandFmt2char( VipsBandFmt fmt ) 
	{ return( enum2char( &enumBandFmt, fmt ) ); }
const char *im_Coding2char( VipsCoding coding ) 
	{ return( enum2char( &enumCoding, coding ) ); }
const char *im_Compression2char( int n ) 
	{ return( enum2char( &enumCompression, n ) ); }
const char *im_dtype2char( im_desc_type n ) 
	{ return( enum2char( &enumdtype, n ) ); }
const char *im_dhint2char( VipsDemandStyle style ) 
	{ return( enum2char( &enumdhint, style ) ); }

int im_char2Type( const char *str ) 
	{ return( char2enum( &enumType, str ) ); }
int im_char2BandFmt( const char *str ) 
	{ return( char2enum( &enumBandFmt, str ) ); }
int im_char2Coding( const char *str ) 
	{ return( char2enum( &enumCoding, str ) ); }
int im_char2Compression( const char *str ) 
	{ return( char2enum( &enumCompression, str ) ); }
im_desc_type im_char2dtype( const char *str ) 
	{ return( char2enum( &enumdtype, str ) ); }
im_demand_type im_char2dhint( const char *str ) 
	{ return( char2enum( &enumdhint, str ) ); }

static void *
print_field_fn( IMAGE *im, const char *field, GValue *value )
{
	const char *extra;
	char *str_value;

	str_value = g_strdup_value_contents( value );
	printf( "%s: %s", field, str_value );
	g_free( str_value );

	/* Replace NULL static strings with "(null)".
	 */
#define NN( X ) ((X) ? (X) : "(null)")

	/* Look for known enums and decode them.
	 */
	extra = NULL;
	if( strcmp( field, "Coding" ) == 0 )
		extra = NN( im_Coding2char( g_value_get_int( value ) ) );
	else if( strcmp( field, "BandFmt" ) == 0 )
		extra = NN( im_BandFmt2char( g_value_get_int( value ) ) );
	else if( strcmp( field, "Type" ) == 0 )
		extra = NN( im_Type2char( g_value_get_int( value ) ) );
	else if( strcmp( field, "Compression" ) == 0 )
		extra = NN( im_Compression2char( g_value_get_int( value ) ) );

	if( extra )
		printf( " - %s", extra );

	printf( "\n" );

	return( NULL );
}

static void *
print_region( REGION *reg, void *a, void *b )
{	
	printf( "Region defined for area at %dx%d size %dx%d\n",
		reg->valid.left, reg->valid.top,
		reg->valid.width, reg->valid.height );
	if( reg->seq )
		printf( "sequence in progress on region\n" );
	if( reg->buffer )
		printf( "local memory allocated\n" );

	return( NULL );
}

void 
im_printdesc( IMAGE *image )
{	
	if( !image ) {
		printf( "NULL descriptor\n" );
		return;
	}

	printf( "IMAGE* %p\n", image );

	if( im_isMSBfirst( image ) )
		printf( "SPARC (MSB first) " );
	else
		printf( "Intel (LSB first) " );
	printf( "byte order image, on a " );
	if( im_amiMSBfirst() )
		printf( "SPARC (MSB first) " );
	else
		printf( "Intel (LSB first) " );
	printf( "byte order machine\n" );
 
	(void) im_header_map( image, (im_header_map_fn) print_field_fn, NULL );

	printf( "Hist: %s", im_history_get( image ) );

	/* Print other (non-header) fields.
	 */
	if( image->generate )
		printf( "generate function attached\n" );
	if( image->closefns )
		printf( "close callbacks attached\n" );
	if( image->evalfns )
		printf( "eval callbacks attached\n" );
	if( image->evalendfns )
		printf( "evalend callbacks attached\n" );
	if( image->evalstartfns )
		printf( "evalstart callbacks attached\n" );
	if( image->preclosefns )
		printf( "preclose callbacks attached\n" );
	if( image->invalidatefns )
		printf( "invalidate callbacks attached\n" );
	if( image->regions ) {
		printf( "%d regions present\n", 
			g_slist_length( image->regions ) );
		im_slist_map2( image->regions, 
			(VSListMap2Fn) print_region, NULL, NULL );
	}
	if( image->kill )
		printf( "kill flag set\n" );
	if( image->closing )
		printf( "closing flag set\n" );
	if( image->close_pending )
		printf( "close_pending flag set\n" );

#ifdef DEBUG
	/* Can't get these with im_header_get(), so only show for debugging.
	 */
	printf( "dhint: %s\n", im_dhint2char( image->dhint ) );
	printf( "dtype: %s\n", im_dtype2char( image->dtype ) );
#endif /*DEBUG*/
}
