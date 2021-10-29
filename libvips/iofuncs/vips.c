/* Read and write a vips file.
 * 
 * 22/5/08
 * 	- from im_open.c, im_openin.c, im_desc_hd.c, im_readhist.c,
 * 	  im_openout.c
 * 19/3/09
 *	- block mmaps of nodata images
 * 12/5/09
 *	- fix signed/unsigned warnings
 * 12/10/09
 *	- heh argh reading history always stopped after the first line
 * 9/12/09
 * 	- only wholly map input files on im_incheck() ... this reduces VM use,
 * 	  especially with large numbers of small files
 * 14/2/11
 * 	- renamed to vips.c from im_open_vips.c, some stuff chopped out for 
 * 	  image.c ... this file now just does read / write to disc
 * 28/3/11
 * 	- moved to vips_ namespace
 * 25/2/17
 * 	- use expat for xml read, printf for xml write
 * 16/8/17
 * 	- validate strs as being utf-8 before we write
 * 9/4/18 Alexander--
 * 	- use O_TMPFILE, if available
 * 23/7/18
 * 	- escape ASCII control characters in XML
 * 29/8/19
 * 	- verify bands/format for coded images
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
#define SHOW_HEADER
#define DEBUG
 */

/* Enable linux extensions like O_TMPFILE, if available.
 */
#define _GNU_SOURCE

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /*HAVE_CONFIG_H*/
#include <vips/intl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>
#endif /*HAVE_SYS_FILE_H*/
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /*HAVE_UNISTD_H*/
#ifdef HAVE_IO_H
#include <io.h>
#endif /*HAVE_IO_H*/
#include <expat.h>
#include <errno.h>

#include <vips/vips.h>

#ifdef G_OS_WIN32
#include <windows.h>
#endif /*G_OS_WIN32*/

#include <vips/debug.h>
#include <vips/internal.h>

/**
 * SECTION: vips
 * @short_description: startup, shutdown, version
 * @stability: Stable
 * @see_also: <link linkend="VipsOperation">VipsOperation</link>
 * @include: vips/vips.h
 *
 * Start VIPS up, shut VIPS down, get version information, relocation. 
 *
 * VIPS is a relocatable package, meaning you can move the directory tree you
 * compiled it to at runtime and it will still be able to find all data files.
 * This is required for OS X and Windows, but slightly unusual in the Unix
 * world. See vips_init() and vips_guess_prefix().
 */

/* Open mode for image write.
 *
 * We use O_RDWR not O_WRONLY since after writing we may want to rewind the 
 * image and read from it.
 */
#define MODE_WRITE CLOEXEC (BINARYIZE (O_RDWR | O_CREAT | O_TRUNC))

/* Mode for read/write. This is if we might later want to mmaprw () the file.
 */
#define MODE_READWRITE CLOEXEC (BINARYIZE (O_RDWR))

/* Mode for read only. This is the fallback if READWRITE fails.
 */
#define MODE_READONLY CLOEXEC (BINARYIZE (O_RDONLY))

/* Our XML namespace.
 */
#define NAMESPACE_URI "http://www.vips.ecs.soton.ac.uk/" 

/* Open for read for image files. 
 */
int
vips__open_image_read( const char *filename )
{
	int fd;

	/* Try to open read-write, so that calls to vips_image_inplace() will 
	 * work. When we later mmap this file, we set read-only, so there 
	 * is little danger of scrubbing over files we own.
	 */
	fd = vips_tracked_open( filename, MODE_READWRITE, 0 );
	if( fd == -1 ) 
		/* Open read-write failed. Fall back to open read-only.
		 */
		fd = vips_tracked_open( filename, MODE_READONLY, 0 );
	
	if( fd == -1 ) {
		vips_error_system( errno, "VipsImage", 
			_( "unable to open \"%s\"" ), filename );
		return( -1 );
	}

	return( fd );
}

/* Open for write for image files. 
 */
int
vips__open_image_write( const char *filename, gboolean temp )
{
	int flags;
	int fd;

	fd = -1;

#ifndef O_TMPFILE
	if( temp ) 
		g_info( "vips__open_image_write: O_TMPFILE not available" );
#endif /*!O_TMPFILE*/

#ifdef O_TMPFILE
	/* Linux-only extension creates an unlinked file. CREAT and TRUNC must
	 * be clear. The filename arg to open() must name a directory.
	 *
	 * This can fail since not all filesystems support it. In this case,
	 * we open as a regular file and rely on the delete-on-close
	 * mechanism, see vips_image_delete(). 
	 */
	if( temp ) {
		char *dirname;

		g_info( "vips__open_image_write: opening with O_TMPFILE" );
		dirname = g_path_get_dirname( filename ); 
		fd = vips_tracked_open( dirname, O_TMPFILE | O_RDWR , 0644 );
		g_free( dirname ); 

		if( fd < 0 ) 
			g_info( "vips__open_image_write: O_TMPFILE failed!" );
	}
#endif /*O_TMPFILE*/

	flags = MODE_WRITE;

#ifdef _O_TEMPORARY
	/* On Windows, setting _O_TEMPORARY will delete the file automatically
	 * on process exit, even if the processes crashes. 
	 */
	if( temp ) {
		g_info( "vips__open_image_write: setting _O_TEMPORARY" );
		flags |= _O_TEMPORARY;
	}
#endif /*_O_TEMPORARY*/

	if( fd < 0 ) {
		g_info( "vips__open_image_write: simple open" );
		fd = vips_tracked_open( filename, flags, 0644 );
	}

	if( fd < 0 ) {
		g_info( "vips__open_image_write: failed!" );
		vips_error_system( errno, "VipsImage", 
			_( "unable to write to \"%s\"" ), filename );
		return( -1 );
	}

	return( fd );
}

/* Predict the size of the header plus pixel data. Don't use off_t,
 * it's sometimes only 32 bits (eg. on many windows build environments) and we
 * want to always be 64 bit.
 */
static gint64
image_pixel_length( VipsImage *image )
{
	gint64 psize;

	switch( image->Coding ) {
	case VIPS_CODING_LABQ:
	case VIPS_CODING_RAD:
	case VIPS_CODING_NONE:
		psize = VIPS_IMAGE_SIZEOF_IMAGE( image );
		break;

	default:
		psize = image->Length;
		break;
	}

	return( psize + image->sizeof_header );
}

/* Copy 2 and 4 bytes, optionally swapping byte order.
 */
void
vips__copy_4byte( int swap, unsigned char *to, unsigned char *from )
{
	guint32 *in = (guint32 *) from;
	guint32 *out = (guint32 *) to;

	if( swap )
		*out = GUINT32_SWAP_LE_BE( *in );
	else
		*out = *in;
}

void
vips__copy_2byte( gboolean swap, unsigned char *to, unsigned char *from )
{
	guint16 *in = (guint16 *) from;
	guint16 *out = (guint16 *) to;

	if( swap )
		*out = GUINT16_SWAP_LE_BE( *in );
	else
		*out = *in;
}

guint32
vips__file_magic( const char *filename )
{
	guint32 magic;

	if( vips__get_bytes( filename, (unsigned char *) &magic, 4 ) == 4 &&
		(magic == VIPS_MAGIC_INTEL || 
		 magic == VIPS_MAGIC_SPARC) )
		return( magic );

	return( 0 );
}

/* offset, read, write functions.
 */
typedef struct _FieldIO {
	glong offset;
	int size;
	void (*copy)( gboolean swap, unsigned char *to, unsigned char *from );
} FieldIO;

static FieldIO fields[] = {
	{ G_STRUCT_OFFSET( VipsImage, Xsize ), 4, vips__copy_4byte },
	{ G_STRUCT_OFFSET( VipsImage, Ysize ), 4, vips__copy_4byte },
	{ G_STRUCT_OFFSET( VipsImage, Bands ), 4, vips__copy_4byte },
	{ G_STRUCT_OFFSET( VipsImage, Bbits ), 4, vips__copy_4byte },
	{ G_STRUCT_OFFSET( VipsImage, BandFmt ), 4, vips__copy_4byte },
	{ G_STRUCT_OFFSET( VipsImage, Coding ), 4, vips__copy_4byte },
	{ G_STRUCT_OFFSET( VipsImage, Type ), 4, vips__copy_4byte },
	{ G_STRUCT_OFFSET( VipsImage, Xres_float ), 4, vips__copy_4byte },
	{ G_STRUCT_OFFSET( VipsImage, Yres_float ), 4, vips__copy_4byte },
	{ G_STRUCT_OFFSET( VipsImage, Length ), 4, vips__copy_4byte },
	{ G_STRUCT_OFFSET( VipsImage, Compression ), 2, vips__copy_2byte },
	{ G_STRUCT_OFFSET( VipsImage, Level ), 2, vips__copy_2byte },
	{ G_STRUCT_OFFSET( VipsImage, Xoffset ), 4, vips__copy_4byte },
	{ G_STRUCT_OFFSET( VipsImage, Yoffset ), 4, vips__copy_4byte }
};

int
vips__read_header_bytes( VipsImage *im, unsigned char *from )
{
	gboolean swap;
	int i;
	GEnumValue *value;

#ifdef SHOW_HEADER
	printf( "vips__read_header_bytes: file bytes:\n" ); 
	for( i = 0; i < im->sizeof_header; i++ )
		printf( "%2d - 0x%02x\n", i, from[i] );
#endif /*SHOW_HEADER*/

	/* The magic number is always written MSB first, we may need to swap.
	 */
	vips__copy_4byte( !vips_amiMSBfirst(), 
		(unsigned char *) &im->magic, from );
	from += 4;
	if( im->magic != VIPS_MAGIC_INTEL && 
		im->magic != VIPS_MAGIC_SPARC ) {
		vips_error( "VipsImage", 
			_( "\"%s\" is not a VIPS image" ), im->filename );
		return( -1 );
	}

	/* We need to swap for other fields if the file byte order is 
	 * different from ours.
	 */
	swap = vips_amiMSBfirst() != vips_image_isMSBfirst( im );

	for( i = 0; i < VIPS_NUMBER( fields ); i++ ) {
		fields[i].copy( swap,
			&G_STRUCT_MEMBER( unsigned char, im, fields[i].offset ),
			from );
		from += fields[i].size;
	}

	/* Set this ourselves ... bbits is deprecated in the file format.
	 */
	im->Bbits = vips_format_sizeof( im->BandFmt ) << 3;

	/* We read xres/yres as floats to a staging area, then copy to double
	 * in the main fields.
	 */
	im->Xres = im->Xres_float;
	im->Yres = im->Yres_float;

	/* Some protection against malicious files. We also check predicted
	 * (based on these values) against real file length, see below. 
	 */
	im->Xsize = VIPS_CLIP( 1, im->Xsize, VIPS_MAX_COORD );
	im->Ysize = VIPS_CLIP( 1, im->Ysize, VIPS_MAX_COORD );
	im->Bands = VIPS_CLIP( 1, im->Bands, VIPS_MAX_COORD );
	im->BandFmt = VIPS_CLIP( 0, im->BandFmt, VIPS_FORMAT_LAST - 1 );

	/* Coding and Type have missing values, so we look up in the enum.
	 */
	value = g_enum_get_value( g_type_class_ref( VIPS_TYPE_INTERPRETATION ),
		im->Type );
	if( !value ||
		strcmp( value->value_nick, "last" ) == 0 )
		im->Type = VIPS_INTERPRETATION_ERROR;
	value = g_enum_get_value( g_type_class_ref( VIPS_TYPE_CODING ),
		im->Coding );
	if( !value ||
		strcmp( value->value_nick, "last" ) == 0 )
		im->Coding = VIPS_CODING_ERROR;

	/* Offset, Res, etc. don't affect vips file layout, just 
	 * pixel interpretation, don't clip them.
	 */

	/* Coding values imply Bands and BandFmt settings --- make sure they
	 * are sane.
	 */
	switch( im->Coding ) {
	case VIPS_CODING_ERROR:
		vips_error( "VipsImage",
			"%s", _( "unknown coding" ) );
		return( -1 );

	case VIPS_CODING_NONE:
		break;

	case VIPS_CODING_LABQ:
		if( im->Bands != 4 ||
			im->BandFmt != VIPS_FORMAT_UCHAR ) {
			vips_error( "VipsImage", 
				"%s", _( "malformed LABQ image" ) ); 
			return( -1 );
		}
		break;

	case VIPS_CODING_RAD:
		if( im->Bands != 4 ||
			im->BandFmt != VIPS_FORMAT_UCHAR ) {
			vips_error( "VipsImage", 
				"%s", _( "malformed RAD image" ) ); 
			return( -1 );
		}
		break;

	default:
		g_assert_not_reached();
		break;
	}

	return( 0 );
}

int
vips__write_header_bytes( VipsImage *im, unsigned char *to )
{
	/* Swap if the byte order we are asked to write the header in is
	 * different from ours.
	 */
	gboolean swap = vips_amiMSBfirst() != vips_image_isMSBfirst( im );

	int i;
	unsigned char *q;

	/* We set xres/yres as floats in a staging area, then copy those
	 * smaller values to the file. 
	 */
	im->Xres_float = im->Xres;
	im->Yres_float = im->Yres;

	/* Always write the magic number MSB first.
	 */
	vips__copy_4byte( !vips_amiMSBfirst(), 
		to, (unsigned char *) &im->magic );
	q = to + 4;

	for( i = 0; i < VIPS_NUMBER( fields ); i++ ) {
		fields[i].copy( swap,
			q, 
			&G_STRUCT_MEMBER( unsigned char, im, 
				fields[i].offset ) );
		q += fields[i].size;
	}

	/* Pad spares with zeros.
	 */
	while( q - to < im->sizeof_header )
		*q++ = 0;

#ifdef SHOW_HEADER
	printf( "vips__write_header_bytes: file bytes:\n" ); 
	for( i = 0; i < im->sizeof_header; i++ )
		printf( "%2d - 0x%02x\n", i, to[i] );
#endif /*SHOW_HEADER*/

	return( 0 );
}

/* Read a chunk of an fd into memory. Add a '\0' at the end.
 */
static char *
read_chunk( int fd, gint64 offset, size_t length )
{
	char *buf;

	if( vips__seek( fd, offset, SEEK_SET ) == -1 )
		return( NULL );
	if( !(buf = vips_malloc( NULL, length + 1 )) )
		return( NULL );
	if( read( fd, buf, length ) != (ssize_t) length ) {
		g_free( buf );
		vips_error( "VipsImage", "%s", _( "unable to read history" ) );
		return( NULL );
	}
	buf[length] = '\0';

	return( buf );
}

/* Does it look like an image has an extension block?
 */
int
vips__has_extension_block( VipsImage *im )
{
	gint64 psize;

	psize = image_pixel_length( im );
	g_assert( im->file_length > 0 );

	return( im->file_length - psize > 0 );
}

/* Read everything after the pixels into memory.
 */
void *
vips__read_extension_block( VipsImage *im, int *size )
{
	gint64 psize;
	void *buf;

	psize = image_pixel_length( im );
	g_assert( im->file_length > 0 );
	if( im->file_length - psize > 100 * 1024 * 1024 ) {
		vips_error( "VipsImage",
			"%s", _( "more than 100 megabytes of XML? "
			"sufferin' succotash!" ) );
		return( NULL );
	}
	if( im->file_length - psize == 0 )
		return( NULL );
	if( !(buf = read_chunk( im->fd, psize, im->file_length - psize )) )
		return( NULL );
	if( size )
		*size = im->file_length - psize;

#ifdef DEBUG
	printf( "vips__read_extension_block: read %d bytes from %s\n",
		(int) (im->file_length - psize), im->filename );
	printf( "data: \"%s\"\n", (char *) buf );
#endif /*DEBUG*/

	return( buf );
}

static int
parser_read_fd( XML_Parser parser, int fd )
{
	const int chunk_size = 1024; 

	gint64 bytes_read;
	gint64 len;

	bytes_read = 0;

	do {
		void *buf;

		if( !(buf = XML_GetBuffer( parser, chunk_size )) ) {
			vips_error( "VipsImage", 
				"%s", _( "unable to allocate read buffer" ) );
			return( -1 );
		}
		len = read( fd, buf, chunk_size );
		if( len == -1 ) {
			vips_error( "VipsImage", 
				"%s", _( "read error while fetching XML" ) );
			return( -1 );
		}

		/* Allow missing XML block.
		 */
		if( bytes_read == 0 &&
			len == 0 )
			break;
		bytes_read += len;

		if( !XML_ParseBuffer( parser, len, len == 0 ) ) {
			vips_error( "VipsImage", "%s", _( "XML parse error" ) );
			return( -1 );
		}
	} while( len > 0 );

	return( 0 );
}

#define MAX_PARSE_ATTR (256)

/* What we track during expat parse.
 */
typedef struct _VipsExpatParse {
	VipsImage *image;

	/* Set on error.
	 */
	gboolean error;

	/* TRUE for in header section.
	 */
	gboolean header;

	/* For the current node, the type and name.
	 */
	XML_Char type[MAX_PARSE_ATTR];
	XML_Char name[MAX_PARSE_ATTR];

	/* Accumulate data here.
	 */
	VipsDbuf dbuf; 
} VipsExpatParse;

static void
parser_element_start_handler( void *user_data, 
	const XML_Char *name, const XML_Char **atts )
{
	VipsExpatParse *vep = (VipsExpatParse *) user_data;
	const XML_Char **p;

#ifdef DEBUG
	printf( "parser_element_start: %s\n", name );
	for( p = atts; *p; p += 2 ) 
		printf( "%s = %s\n", p[0], p[1] );
#endif /*DEBUG*/

	if( strcmp( name, "field" ) == 0 ) { 
		for( p = atts; *p; p += 2 ) {
			if( strcmp( p[0], "name" ) == 0 )
				vips_strncpy( vep->name, p[1], MAX_PARSE_ATTR ); 
			if( strcmp( p[0], "type" ) == 0 )
				vips_strncpy( vep->type, p[1], MAX_PARSE_ATTR ); 
		}

		vips_dbuf_reset( &vep->dbuf );
	} 
	else if( strcmp( name, "header" ) == 0 )  
		vep->header = TRUE;
	else if( strcmp( name, "meta" ) == 0 )  
		vep->header = FALSE;
	else if( strcmp( name, "root" ) == 0 ) {
		for( p = atts; *p; p += 2 ) 
			if( strcmp( p[0], "xmlns" ) == 0 &&
				!vips_isprefix( NAMESPACE_URI "vips", p[1] ) ) {
				vips_error( "VipsImage", "%s", 
					_( "incorrect namespace in XML" ) );
				vep->error = TRUE;
			}
	}
}

/* Chop history into lines, add each one as a refstring.
 */
static void
set_history( VipsImage *im, char *history )
{
	GSList *history_list;
	char *p, *q;

	/* There can be history there already if we're rewinding.
	 */
	VIPS_FREEF( vips__gslist_gvalue_free, im->history_list );

	history_list = NULL;

	for( p = history; *p; p = q ) {
		if( (q = strchr( p, '\n' )) ) {
			*q = '\0';
			q += 1;
		}
		else 
			q = p + strlen( p );

		history_list = g_slist_prepend( history_list, 
			vips__gvalue_ref_string_new( p ) );
	}

	im->history_list = g_slist_reverse( history_list );
}

static int
set_meta( VipsImage *image, GType gtype, const char *name, const char *data )
{
	GValue save_value = { 0 };
	GValue value = { 0 };

	g_value_init( &save_value, VIPS_TYPE_SAVE_STRING );
	vips_value_set_save_string( &save_value, data );

	g_value_init( &value, gtype );
	if( !g_value_transform( &save_value, &value ) ) {
		g_value_unset( &save_value );
		vips_error( "VipsImage", "%s", 
			_( "error transforming from save format" ) );
		return( -1 ); 
	}

	vips_image_set( image, name, &value );
	g_value_unset( &save_value );
	g_value_unset( &value );

	return( 0 );
}

static void
parser_element_end_handler( void *user_data, const XML_Char *name )
{
	VipsExpatParse *vep = (VipsExpatParse *) user_data;

#ifdef DEBUG
	printf( "parser_element_end_handler: %s\n", name ); 
#endif /*DEBUG*/

	if( strcmp( name, "field" ) == 0 ) {
		if( vep->header ) {
			if( strcmp( name, "Hist" ) == 0 ) 
				set_history( vep->image, 
					(char *) vips_dbuf_string( &vep->dbuf, 
						NULL ) ); 
		}
		else {
			GType gtype = g_type_from_name( vep->type );

			/* Can we convert from VIPS_SAVE_STRING to type?
			 */
			if( gtype && 
				g_value_type_transformable( 
					VIPS_TYPE_SAVE_STRING, gtype ) &&
				set_meta( vep->image, 
					gtype, vep->name, 
					(char *) vips_dbuf_string( &vep->dbuf, 
						NULL ) ) )
				vep->error = TRUE;
		}
	}
}

static void
parser_data_handler( void *user_data, const XML_Char *data, int len )
{
	VipsExpatParse *vep = (VipsExpatParse *) user_data;

#ifdef DEBUG
	printf( "parser_data_handler: %d bytes\n", len ); 
#endif /*DEBUG*/

	vips_dbuf_write( &vep->dbuf, (unsigned char *) data, len );
}

/* Called at the end of vips open ... get any XML after the pixel data
 * and read it in.
 */
static int 
readhist( VipsImage *im )
{
	XML_Parser parser;
	VipsExpatParse vep;

	if( vips__seek( im->fd, image_pixel_length( im ), SEEK_SET ) == -1 ) 
		return( -1 );

	parser = XML_ParserCreate( "UTF-8" );

	vep.image = im;
	vips_dbuf_init( &vep.dbuf ); 
	vep.error = FALSE;
	XML_SetUserData( parser, &vep );

	XML_SetElementHandler( parser, 
		parser_element_start_handler, parser_element_end_handler );
	XML_SetCharacterDataHandler( parser, parser_data_handler ); 

	if( parser_read_fd( parser, im->fd ) ||
		vep.error ) { 
		vips_dbuf_destroy( &vep.dbuf ); 
		XML_ParserFree( parser );
		return( -1 );
	}

	vips_dbuf_destroy( &vep.dbuf ); 
	XML_ParserFree( parser );

	return( 0 ); 
}

int
vips__write_extension_block( VipsImage *im, void *buf, int size )
{
	gint64 length;
	gint64 psize;

	psize = image_pixel_length( im );
	if( (length = vips_file_length( im->fd )) == -1 )
		return( -1 );
	if( length < psize ) {
		vips_error( "VipsImage", "%s", _( "file has been truncated" ) );
		return( -1 );
	}

	if( vips__ftruncate( im->fd, psize ) ||
		vips__seek( im->fd, psize, SEEK_SET ) == -1 ) 
		return( -1 );
	if( vips__write( im->fd, buf, size ) )
                return( -1 );

#ifdef DEBUG
	printf( "vips__write_extension_block: written %d bytes of XML to %s\n",
		size, im->filename );
#endif /*DEBUG*/

	return( 0 );
}

/* Append a string to a buffer, but escape " as \".
 */
static void
target_write_quotes( VipsTarget *target, const char *str )
{
	const char *p;
	size_t len;

	for( p = str; *p; p += len ) {
		len = strcspn( p, "\"" );

		vips_target_write( target, (unsigned char *) p, len );
		if( p[len] == '"' )
			vips_target_writes( target, "\\" );
	}
}

static void *
build_xml_meta( VipsMeta *meta, VipsTarget *target, void *b )
{
	GType type = G_VALUE_TYPE( &meta->value );

	const char *str;

	/* If we can transform to VIPS_TYPE_SAVE_STRING and back, we can save 
	 * and restore. 
	 */
	if( g_value_type_transformable( type, VIPS_TYPE_SAVE_STRING ) &&
		g_value_type_transformable( VIPS_TYPE_SAVE_STRING, type ) ) {
		GValue save_value = { 0 };

		g_value_init( &save_value, VIPS_TYPE_SAVE_STRING );
		if( !g_value_transform( &meta->value, &save_value ) ) {
			vips_error( "VipsImage", "%s", 
				_( "error transforming to save format" ) );
			return( meta );
		}

		/* We need to validate the str to make sure we'll be able to
		 * read it back. 
		 */
		str = vips_value_get_save_string( &save_value );
		if( g_utf8_validate( str, -1, NULL ) ) { 
			vips_target_writef( target, 
				"    <field type=\"%s\" name=\"", 
				g_type_name( type ) ); 
			target_write_quotes( target, meta->name );
			vips_target_writes( target, "\">" );  
			vips_target_write_amp( target, str );
			vips_target_writes( target, "</field>\n" );  
		}

		g_value_unset( &save_value );
	}

	return( NULL );
}

/* Make the xml we append to vips images after the pixel data.
 */
static char *
build_xml( VipsImage *image )
{
	VipsTarget *target;
	const char *str;
	char *result;

	target = vips_target_new_to_memory();

	vips_target_writef( target, "<?xml version=\"1.0\"?>\n" ); 
	vips_target_writef( target, "<root xmlns=\"%svips/%d.%d.%d\">\n", 
		NAMESPACE_URI, 
		VIPS_MAJOR_VERSION, VIPS_MINOR_VERSION, VIPS_MICRO_VERSION );
	vips_target_writef( target, "  <header>\n" );  

	str = vips_image_get_history( image );
	if( g_utf8_validate( str, -1, NULL ) ) { 
		vips_target_writef( target, 
			"    <field type=\"%s\" name=\"Hist\">", 
			g_type_name( VIPS_TYPE_REF_STRING ) );
		vips_target_write_amp( target, str );
		vips_target_writef( target, "</field>\n" ); 
	}

	vips_target_writef( target, "  </header>\n" ); 
	vips_target_writef( target, "  <meta>\n" );  

	if( vips_slist_map2( image->meta_traverse, 
		(VipsSListMap2Fn) build_xml_meta, target, NULL ) ) {
		VIPS_UNREF( target ); 
		return( NULL );
	}

	vips_target_writef( target, "  </meta>\n" );  
	vips_target_writef( target, "</root>\n" );  

	result = vips_target_steal_text( target ); 

	VIPS_UNREF( target );

	return( result ); 
}

static void *
vips__xml_properties_meta( VipsImage *image, 
	const char *field, GValue *value, void *a )
{
	VipsTarget *target = (VipsTarget *) a;
	GType type = G_VALUE_TYPE( value );

	const char *str;

	/* If we can transform to VIPS_TYPE_SAVE_STRING and back, we can save 
	 * and restore. 
	 */
	if( g_value_type_transformable( type, VIPS_TYPE_SAVE_STRING ) &&
		g_value_type_transformable( VIPS_TYPE_SAVE_STRING, type ) ) {
		GValue save_value = { 0 };

		g_value_init( &save_value, VIPS_TYPE_SAVE_STRING );
		if( !g_value_transform( value, &save_value ) ) {
			vips_error( "VipsImage", "%s", 
				_( "error transforming to save format" ) );
			return( target );
		}
		str = vips_value_get_save_string( &save_value );

		vips_target_writef( target, "    <property>\n" );  
		vips_target_writef( target, "      <name>" ); 
		vips_target_write_amp( target, field );
		vips_target_writef( target, "</name>\n" ); 
		vips_target_writef( target, "      <value type=\"%s\">",
			g_type_name( type ) );  
		vips_target_write_amp( target, str );
		vips_target_writef( target, "</value>\n" ); 
		vips_target_writef( target, "    </property>\n" );  

		g_value_unset( &save_value );
	}

	return( NULL );
}

/* Make the xml we write to vips-properties in dzsave, or to TIFF. A simple
 * dump of all vips metadata. Free with g_free().
 */
char *
vips__xml_properties( VipsImage *image )
{
	VipsTarget *target;
	char *date;
	char *result;

	date = vips__get_iso8601();

	target = vips_target_new_to_memory();
	vips_target_writef( target, "<?xml version=\"1.0\"?>\n" ); 
	vips_target_writef( target, "<image xmlns=\"%s/dzsave\" "
		"date=\"%s\" version=\"%d.%d.%d\">\n", 
		NAMESPACE_URI, 
		date, 
		VIPS_MAJOR_VERSION, VIPS_MINOR_VERSION, VIPS_MICRO_VERSION );
	vips_target_writef( target, "  <properties>\n" );  

	g_free( date ); 

	if( vips_image_map( image, vips__xml_properties_meta, target ) ) {
		VIPS_UNREF( target );
		return( NULL );
	}

	vips_target_writef( target, "  </properties>\n" );  
	vips_target_writef( target, "</image>\n" );  

	result = vips_target_steal_text( target ); 

	VIPS_UNREF( target );

	return( result );
}

/* Append XML to output fd.
 */
int 
vips__writehist( VipsImage *image )
{
	char *xml;

	assert( image->dtype == VIPS_IMAGE_OPENOUT );
	assert( image->fd != -1 );

	if( !(xml = build_xml( image )) )
		return( -1 );

	if( vips__write_extension_block( image, xml, strlen( xml ) ) ) {
		g_free( xml );
                return( -1 );
        }

#ifdef DEBUG
	printf( "vips__writehist: saved XML is: \"%s\"\n", xml );
#endif /*DEBUG*/

	g_free( xml );

	return( 0 );
}

/* Open the filename, read the header, some sanity checking.
 */
int
vips_image_open_input( VipsImage *image )
{
	/* We don't use im->sizeof_header here, but we know we're reading a
	 * VIPS image anyway.
	 */
	unsigned char header[VIPS_SIZEOF_HEADER];

	gint64 psize;
	gint64 rsize;

	image->dtype = VIPS_IMAGE_OPENIN;

	/* We may have an fd already, see vips_image_rewind_output().
	 */
	if( image->fd == -1 ) {
		image->fd = vips__open_image_read( image->filename );
		if( image->fd == -1 )
			return( -1 );
	}

	vips__seek( image->fd, 0, SEEK_SET );
	if( read( image->fd, header, VIPS_SIZEOF_HEADER ) != 
		VIPS_SIZEOF_HEADER ||
		vips__read_header_bytes( image, header ) ) {
		vips_error_system( errno, "VipsImage", 
			_( "unable to read header for \"%s\"" ),
			image->filename );
		return( -1 );
	}

	/* Predict and check the file size. Only issue a warning, we want to be
	 * able to read all the header fields we can, even if the actual data
	 * isn't there. 
	 */
	psize = image_pixel_length( image );
	if( (rsize = vips_file_length( image->fd )) == -1 ) 
		return( -1 );
	image->file_length = rsize;
	if( psize > rsize )
		g_warning( _( "unable to read data for \"%s\", %s" ),
			image->filename, _( "file has been truncated" ) );

	/* Set demand style. This suits a disc file we read sequentially.
	 */
	image->dhint = VIPS_DEMAND_STYLE_THINSTRIP;

	/* Set the history part of im descriptor. Don't return an error if this
	 * fails (due to eg. corrupted XML) because it's probably mostly
	 * harmless.
	 */
	if( readhist( image ) ) {
		g_warning( _( "error reading vips image metadata: %s" ), 
			vips_error_buffer() );
		vips_error_clear();
	}

	return( 0 );
}

int 
vips_image_open_output( VipsImage *image )
{
	if( image->fd == -1 ) {
		/* Don't use im->sizeof_header here, but we know we're 
		 * writing a VIPS image anyway.
		 */
		unsigned char header[VIPS_SIZEOF_HEADER];

		if( (image->fd = vips__open_image_write( image->filename, 
			image->delete_on_close )) < 0 )
			return( -1 );

		/* We always write in native mode, so we must overwrite the
		 * magic we read from the file originally.
		 */
		image->magic = vips_amiMSBfirst() ? 
			VIPS_MAGIC_SPARC : VIPS_MAGIC_INTEL;

		if( vips__write_header_bytes( image, header ) ||
			vips__write( image->fd, header, VIPS_SIZEOF_HEADER ) )
			return( -1 );
	}

	return( 0 );
}
