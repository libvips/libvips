/* base64.c -- Encode/decode integers in base64 format
 * Created: Mon Sep 23 16:55:12 1996 by faith@dict.org
 * Revised: Sat Mar 30 12:02:36 2002 by faith@dict.org
 * Copyright 1996, 2002 Rickard E. Faith (faith@dict.org)
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 * 
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301  USA
 * 
 * \section{Base-64 Routines}
 *
 * \intro These routines use the 64-character subset of International
 * Alphabet IA5 discussed in RFC 1421 (printeable encoding) and RFC 1522
 * (base64 MIME).
 *

   Value Encoding  Value Encoding  Value Encoding  Value Encoding
       0 A            17 R            34 i            51 z
       1 B            18 S            35 j            52 0
       2 C            19 T            36 k            53 1
       3 D            20 U            37 l            54 2
       4 E            21 V            38 m            55 3
       5 F            22 W            39 n            56 4
       6 G            23 X            40 o            57 5
       7 H            24 Y            41 p            58 6
       8 I            25 Z            42 q            59 7
       9 J            26 a            43 r            60 8
      10 K            27 b            44 s            61 9
      11 L            28 c            45 t            62 +
      12 M            29 d            46 u            63 /
      13 N            30 e            47 v
      14 O            31 f            48 w         (pad) =
      15 P            32 g            49 x
      16 Q            33 h            50 y
 *
 */

/* 

	Hacked for VIPS ... does any length object (not just ints), formats
	base64 into 70 character lines, output to a malloc'd buffer.

	VIPS uses this to write BLOBs (like ICC profiles, for example) to the
	XML that follows an image.
 
Modified on: 
23/7/07 JC
	- oop, needed a slightly larger worst-case buffer in im__b64_encode()

12/5/09
	- fix signed/unsigned warning

25/3/11
	- move to vips_ namespace

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
#include <assert.h>

#include <vips/vips.h>

#include "base64.h"

static unsigned char b64_list[] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#define XX 100

static unsigned char b64_index[256] = {
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,62, XX,XX,XX,63,
    52,53,54,55, 56,57,58,59, 60,61,XX,XX, XX,XX,XX,XX,
    XX, 0, 1, 2,  3, 4, 5, 6,  7, 8, 9,10, 11,12,13,14,
    15,16,17,18, 19,20,21,22, 23,24,25,XX, XX,XX,XX,XX,
    XX,26,27,28, 29,30,31,32, 33,34,35,36, 37,38,39,40,
    41,42,43,44, 45,46,47,48, 49,50,51,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
};

/* Read (up to) 3 bytes from in. Be careful about byte ordering :-/ we need to
 * end up with in[2] in the bottom few bits.
 */
static int
read24( const unsigned char *in, size_t remaining )
{
	int bits;
	int i;

	bits = 0;
	for( i = 0; i < 3; i++ ) {
		bits <<= 8;
		if( remaining > 0 ) {
			bits |= in[i];
			remaining -= 1;
		}
	}

	return( bits );
}

/* Output (up to) 24 bits as four base64 chars. Pad with '=' characters.
 */
static void
encode24( char *p, int bits, size_t remaining )
{
	int i;

	for( i = 0; i < 4; i++ ) {
		if( remaining == 0 )
			p[i] = '=';
		else {
			/* Take the top 6 bits of 24.
			 */
			p[i] = b64_list[(bits >> 18) & 63];
			bits <<= 6;
			remaining -= 6;
		}
	}
}

/* Output to a malloc'd buffer, NULL on error. Try to be simple and reliable,
 * rather than quick.
 */
char *
vips__b64_encode( const unsigned char *data, size_t data_length )
{
	/* Worst case: 1.333 chars per byte, plus 10% for extra carriage 
	 * returns and stuff. And the \n\0 at the end.
	 */
	const size_t output_data_length = data_length * 44 / 30 + 2;

	char *buffer;
	char *p;
	size_t i;
	int cursor;

	if( data_length == 0 ) {
		vips_error( "vips__b64_encode", "%s", _( "too little data" ) );
		return( NULL );
	}
	if( output_data_length > 1024 * 1024 ) {
		/* We shouldn't really be used for large amounts of data.
		 */
		vips_error( "vips__b64_encode", "%s", _( "too much data" ) );
		return( NULL );
	}
	if( !(buffer = vips_malloc( NULL, output_data_length )) ) 
		return( NULL );

	p = buffer;
	*p++ = '\n';
	cursor = 0;

	for( i = 0; i < data_length; i += 3 ) {
		size_t remaining = data_length - i;
		int bits;

		bits = read24( data + i, remaining );
		encode24( p, bits, remaining * 8 );
		p += 4;
		cursor += 4;

		if( cursor >= 76 ) {
			*p++ = '\n';
			cursor = 0;
		}
	}
	if( cursor > 0 ) 
		*p++ = '\n';
	*p++ = '\0';

#ifdef DEBUG
{
	unsigned int total;

	/* Calculate a very simple checksum for debugging.
	 */
	for( total = 0, i = 0; i < data_length; i++ )
		total += data[i];

	printf( "vips__b64_encode: length = %u, checksum 0x%x\n", 
		data_length, total & 0xffff );
}
#endif /*DEBUG*/

	return( buffer );
}

/* Decode base64 back to binary in a malloc'd buffer. NULL on error.
 */
unsigned char *
vips__b64_decode( const char *buffer, size_t *data_length )
{
	const size_t buffer_length = strlen( buffer );

	/* Worst case.
	 */
	const size_t output_data_length = buffer_length * 3 / 4;

	unsigned char *data;
	unsigned char *p;
	unsigned int bits;
	int nbits;
	size_t i;

	if( output_data_length > 1024 * 1024 ) {
		/* We shouldn't really be used for large amounts of data.
		 */
		vips_error( "vips__b64_decode", "%s", _( "too much data" ) );
		return( NULL );
	}

	if( !(data = vips_malloc( NULL, output_data_length )) )
		return( NULL );

	p = data;
	bits = 0;
	nbits = 0;

	for( i = 0; i < buffer_length; i++ ) {
		unsigned int val;

		if( (val = b64_index[(int) buffer[i]]) != XX ) {
			bits <<= 6;
			bits |= val;
			nbits += 6;

			if( nbits >= 8 ) {
				*p++ = (bits >> (nbits - 8)) & 0xff;
				nbits -= 8;
			}
		}
	}

	g_assert( (size_t) (p - data) < output_data_length );

	if( data_length )
		*data_length = p - data;

#ifdef DEBUG
{
	unsigned int total;

	/* Calculate a very simple checksum for debugging.
	 */
	for( total = 0, i = 0; i < p - data; i++ )
		total += data[i];

	printf( "vips__b64_decode: length = %d, checksum 0x%x\n", 
		p - data, total & 0xffff );
}
#endif /*DEBUG*/

	return( data );
}
