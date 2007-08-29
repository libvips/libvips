/* @(#) im_desc_hd: Copies vips file header to an IMAGE descriptor.
 * @(#) 
 * @(#) int
 * @(#) im__read_header_bytes( IMAGE *im, unsigned char *from )
 * @(#) 
 * @(#) int
 * @(#) im__write_header_bytes( IMAGE *im, unsigned char *to )
 * @(#) 
 * @(#) Returns 0 on success and -1 on error
 *
 * Copyright: Nicos Dessipris
 * Written on: 13/02/1990
 * Modified on : 22/2/92 v6.3 Kirk Martinez
 * 17/11/94 JC
 *	- read compression fields too
 * 28/10/98 JC
 * 	- byteswap stuff added
 * 21/8/02 JC
 *	- oops, was truncating float
 * 22/8/05
 * 	- slightly less stupid 
 * 30/12/06
 * 	- use gunit32/16 for 2 and 4 byte quantities
 * 12/1/07
 * 	- override bbits in the file ... it's now deprecated
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

#include <vips/vips.h>  

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Read short/int/float LSB and MSB first.
 */
void
im__read_4byte( int msb_first, unsigned char *to, unsigned char **from )
{
	unsigned char *p = *from;
	int out;

	if( msb_first )
		out = p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3];
	else
		out = p[3] << 24 | p[2] << 16 | p[1] << 8 | p[0];

	*from += 4;
	*((guint32 *) to) = out;
}

void
im__read_2byte( int msb_first, unsigned char *to, unsigned char **from )
{
	int out;
	unsigned char *p = *from;

	if( msb_first )
		out = p[0] << 8 | p[1];
	else
		out = p[1] << 8 | p[0];

	*from += 2;
	*((guint16 *) to) = out;
}

/* We always write in native byte order.
 */
void
im__write_4byte( unsigned char **to, unsigned char *from )
{
	*((guint32 *) *to) = *((guint32 *) from);
	*to += 4;
}

void
im__write_2byte( unsigned char **to, unsigned char *from )
{
	*((guint16 *) *to) = *((guint16 *) from);
	*to += 2;
}

/* offset, read, write functions.
 */
typedef struct _FieldIO {
	glong offset;
	void (*read)( int msb_first, unsigned char *to, unsigned char **from );
	void (*write)( unsigned char **to, unsigned char *from );
} FieldIO;

static FieldIO fields[] = {
	{ G_STRUCT_OFFSET( IMAGE, Xsize ), 
		im__read_4byte, im__write_4byte },
	{ G_STRUCT_OFFSET( IMAGE, Ysize ), 
		im__read_4byte, im__write_4byte },
	{ G_STRUCT_OFFSET( IMAGE, Bands ), 
		im__read_4byte, im__write_4byte },
	{ G_STRUCT_OFFSET( IMAGE, Bbits ), 
		im__read_4byte, im__write_4byte },
	{ G_STRUCT_OFFSET( IMAGE, BandFmt ), 
		im__read_4byte, im__write_4byte },
	{ G_STRUCT_OFFSET( IMAGE, Coding ), 
		im__read_4byte, im__write_4byte },
	{ G_STRUCT_OFFSET( IMAGE, Type ), 
		im__read_4byte, im__write_4byte },
	{ G_STRUCT_OFFSET( IMAGE, Xres ), 
		im__read_4byte, im__write_4byte },
	{ G_STRUCT_OFFSET( IMAGE, Yres ), 
		im__read_4byte, im__write_4byte },
	{ G_STRUCT_OFFSET( IMAGE, Length ), 
		im__read_4byte, im__write_4byte },
	{ G_STRUCT_OFFSET( IMAGE, Compression ), 
		im__read_2byte, im__write_2byte },
	{ G_STRUCT_OFFSET( IMAGE, Level ), 
		im__read_2byte, im__write_2byte },
	{ G_STRUCT_OFFSET( IMAGE, Xoffset ), 
		im__read_4byte, im__write_4byte },
	{ G_STRUCT_OFFSET( IMAGE, Yoffset ), 
		im__read_4byte, im__write_4byte }
};

int
im__read_header_bytes( IMAGE *im, unsigned char *from )
{
	int msb_first;
	int i;

	im__read_4byte( 1, (unsigned char *) &im->magic, &from );
	if( im->magic != IM_MAGIC_INTEL && im->magic != IM_MAGIC_SPARC ) {
		im_error( "im_open", _( "\"%s\" is not a VIPS image" ), 
			im->filename );
		return( -1 );
	}
	msb_first = im->magic == IM_MAGIC_SPARC;

	for( i = 0; i < IM_NUMBER( fields ); i++ )
		fields[i].read( msb_first,
			&G_STRUCT_MEMBER( unsigned char, im, fields[i].offset ),
			&from );

	/* Set this ourselves ... bbits is deprecated in the file format.
	 */
	im->Bbits = im_bits_of_fmt( im->BandFmt );

	return( 0 );
}

int
im__write_header_bytes( IMAGE *im, unsigned char *to )
{
	guint32 magic;
	int i;
	unsigned char *q;

	/* How odd, you'd think it would be the other way around.
	 */
	magic = im_amiMSBfirst() ? IM_MAGIC_INTEL : IM_MAGIC_SPARC;
	q = to;
	im__write_4byte( &q, (unsigned char *) &magic );

	for( i = 0; i < IM_NUMBER( fields ); i++ )
		fields[i].write( &q,
			&G_STRUCT_MEMBER( unsigned char, im, 
				fields[i].offset ) );

	/* Pad spares with zeros.
	 */
	while( q - to < im->sizeof_header )
		*q++ = 0;

	return( 0 );
}
