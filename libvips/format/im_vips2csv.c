/* Write a csv file.
 * 
 * 9/6/06
 *	- hacked from im_debugim
 * 23/10/06
 * 	- allow separator to be specified (default "\t", <tab>)
 * 17/11/06
 * 	- oops, was broken
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
#include <assert.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

#define PRINT_INT( TYPE ) fprintf( fp, "%d", *((TYPE*)p) );
#define PRINT_FLOAT( TYPE ) fprintf( fp, "%g", *((TYPE*)p) );
#define PRINT_COMPLEX( TYPE ) fprintf( fp, "(%g, %g)", \
	((TYPE*)p)[0], ((TYPE*)p)[1] );

static int
vips2csv( IMAGE *in, FILE *fp, const char *sep )
{
	int w = IM_IMAGE_N_ELEMENTS( in );
	int es = IM_IMAGE_SIZEOF_ELEMENT( in );

	int x, y; 
	PEL *p;

	p = (PEL *) in->data; 
	for( y = 0; y < in->Ysize; y++ ) { 
		for( x = 0; x < w; x++ ) { 
			if( x > 0 )
				fprintf( fp, "%s", sep );

			switch( in->BandFmt ) {
			case IM_BANDFMT_UCHAR:		
				PRINT_INT( unsigned char ); break; 
			case IM_BANDFMT_CHAR:		
				PRINT_INT( char ); break; 
			case IM_BANDFMT_USHORT:		
				PRINT_INT( unsigned short ); break; 
			case IM_BANDFMT_SHORT:		
				PRINT_INT( short ); break; 
			case IM_BANDFMT_UINT:		
				PRINT_INT( unsigned int ); break; 
			case IM_BANDFMT_INT:		
				PRINT_INT( int ); break; 
			case IM_BANDFMT_FLOAT:		
				PRINT_FLOAT( float ); break; 
			case IM_BANDFMT_DOUBLE:		
				PRINT_FLOAT( double ); break; 
			case IM_BANDFMT_COMPLEX:	
				PRINT_COMPLEX( float ); break; 
			case IM_BANDFMT_DPCOMPLEX:	
				PRINT_COMPLEX( double ); break; 

			default: 
				assert( 0 );
			}

			 p += es; 
		} 

		fprintf( fp, "\n" ); 
	} 

	return( 0 );
}

/**
 * im_vips2csv:
 * @in: image to save 
 * @filename: file to write to 
 *
 * Save a CSV (comma-separated values) file. The image is written
 * one line of text per scanline. Complex numbers are written as 
 * "(real,imaginary)" and will need extra parsing I guess. The image must
 * have a single band.
 *
 * Write options can be embedded in the filename. The options can be given 
 * in any order and are:
 *
 * <itemizedlist>
 *   <listitem>
 *     <para>
 * <emphasis>sep:separator-string</emphasis> 
 * The string to use to separate numbers in the output. 
 * The default is "\\t" (tab).
 *     </para>
 *   </listitem>
 * </itemizedlist>
 *
 * For example:
 *
 * |[
 * im_csv2vips( in, "fred.csv:sep:\t" );
 * ]|
 *
 * Will write to fred.csv, separating numbers with tab characters.
 *
 * See also: #VipsFormat, im_csv2vips(), im_write_dmask(), im_vips2ppm().
 *
 * Returns: 0 on success, -1 on error.
 */
int 
im_vips2csv( IMAGE *in, const char *filename )
{
	char *separator = "\t";

	char name[FILENAME_MAX];
	char mode[FILENAME_MAX];
	FILE *fp;
	char *p, *q, *r;

	/* Parse mode string.
	 */
	im_filename_split( filename, name, mode );
	p = &mode[0];
	while( (q = im_getnextoption( &p )) ) {
		if( im_isprefix( "sep", q ) && (r = im_getsuboption( q )) )
			separator = r;
	}

	if( im_incheck( in ) ||
		im_check_mono( "im_vips2csv", in ) ||
		im_check_uncoded( "im_vips2csv", in ) )
		return( -1 );

	if( !(fp = im__file_open_write( name, TRUE )) ) 
		return( -1 );
	if( vips2csv( in, fp, separator ) ) {
		fclose( fp );
		return( -1 );
	}

	fclose( fp );

	return( 0 );
}
