/* Read and write a vips file 
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
#include <ctype.h>

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>
#endif /*HAVE_SYS_FILE_H*/
#include <sys/stat.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /*HAVE_UNISTD_H*/
#ifdef HAVE_IO_H
#include <io.h>
#endif /*HAVE_IO_H*/
#include <libxml/parser.h>
#include <errno.h>

#ifdef OS_WIN32
#include <windows.h>
#endif /*OS_WIN32*/

#include <vips/vips.h>
#include <vips/internal.h>
#include <vips/debug.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Try to make an O_BINARY ... sometimes need the leading '_'.
 */
#ifdef BINARY_OPEN
#ifndef O_BINARY
#ifdef _O_BINARY
#define O_BINARY _O_BINARY
#endif /*_O_BINARY*/
#endif /*!O_BINARY*/
#endif /*BINARY_OPEN*/

/* If we have O_BINARY, add it to a mode flags set.
 */
#ifdef O_BINARY
#define BINARYIZE(M) ((M) | O_BINARY)
#else /*!O_BINARY*/
#define BINARYIZE(M) (M)
#endif /*O_BINARY*/

/* Open mode for image write ... on some systems, have to set BINARY too.
 */
#define MODE_WRITE BINARYIZE (O_WRONLY | O_CREAT | O_TRUNC)

/* Mode for read/write. This is if we might later want to mmaprw () the file.
 */
#define MODE_READWRITE BINARYIZE (O_RDWR)

/* Mode for read only. This is the fallback if READWRITE fails.
 */
#define MODE_READONLY BINARYIZE (O_RDONLY)

/* Our XML namespace.
 */
#define NAMESPACE "http://www.vips.ecs.soton.ac.uk/vips" 

/* Sort of open for read for image files. Shared with im_binfile().
 */
int
vips__open_image_read( const char *filename )
{
	int fd;

	/* Try to open read-write, so that calls to im_makerw() will work.
	 * When we later mmap this file, we set read-only, so there 
	 * is little danger of scrubbing over files we own.
	 */
	if( (fd = open( filename, MODE_READWRITE )) == -1 ) {
		/* Open read-write failed. Fall back to open read-only.
		 */
		if( (fd = open( filename, MODE_READONLY )) == -1 ) {
			vips_error_system( errno, "VipsImage", 
				_( "unable to open \"%s\"" ), filename );
			return( -1 );
		}
	}

	return( fd );
}

/* Predict the size of the header plus pixel data. Don't use off_t,
 * it's sometimes only 32 bits (eg. on many windows build environments) and we
 * want to always be 64 bit.
 */
gint64
im__image_pixel_length( VipsImage *image )
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
	if( im->magic != VIPS_MAGIC_INTEL && 
		im->magic != VIPS_MAGIC_SPARC ) {
		vips_error( "VipsImage", _( "\"%s\" is not a VIPS image" ), 
			im->filename );
		return( -1 );
	}
	msb_first = im->magic == VIPS_MAGIC_SPARC;

	for( i = 0; i < VIPS_NUMBER( fields ); i++ )
		fields[i].read( msb_first,
			&G_STRUCT_MEMBER( unsigned char, im, fields[i].offset ),
			&from );

	/* Set this ourselves ... bbits is deprecated in the file format.
	 */
	im->Bbits = vips_format_sizeof( im->BandFmt ) << 3;

	return( 0 );
}

int
im__write_header_bytes( IMAGE *im, unsigned char *to )
{
	guint32 magic;
	int i;
	unsigned char *q;

	/* Always write the magic number MSB first.
	 */
	magic = im_amiMSBfirst() ? VIPS_MAGIC_SPARC : VIPS_MAGIC_INTEL;
	to[0] = magic >> 24;
	to[1] = magic >> 16;
	to[2] = magic >> 8;
	to[3] = magic;
	q = to + 4;

	for( i = 0; i < VIPS_NUMBER( fields ); i++ )
		fields[i].write( &q,
			&G_STRUCT_MEMBER( unsigned char, im, 
				fields[i].offset ) );

	/* Pad spares with zeros.
	 */
	while( q - to < im->sizeof_header )
		*q++ = 0;

	return( 0 );
}

/* Read a chunk of an fd into memory. Add a '\0' at the end.
 */
static char *
read_chunk( int fd, gint64 offset, size_t length )
{
	char *buf;

	if( im__seek( fd, offset ) )
		return( NULL );
	if( !(buf = vips_malloc( NULL, length + 1 )) )
		return( NULL );
	if( read( fd, buf, length ) != (ssize_t) length ) {
		vips_free( buf );
		vips_error( "VipsImage", "%s", _( "unable to read history" ) );
		return( NULL );
	}
	buf[length] = '\0';

	return( buf );
}

/* Does it look like an image has an extension block?
 */
int
im__has_extension_block( IMAGE *im )
{
	gint64 psize;

	psize = im__image_pixel_length( im );
	g_assert( im->file_length > 0 );

	return( im->file_length - psize > 0 );
}

/* Read everything after the pixels into memory.
 */
void *
im__read_extension_block( IMAGE *im, int *size )
{
	gint64 psize;
	void *buf;

	psize = im__image_pixel_length( im );
	g_assert( im->file_length > 0 );
	if( im->file_length - psize > 10 * 1024 * 1024 ) {
		vips_error( "VipsImage",
			"%s", _( "more than a 10 megabytes of XML? "
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
	printf( "im__read_extension_block: read %d bytes from %s\n",
		(int) (im->file_length - psize), im->filename );
	printf( "data: \"%s\"\n", (char *) buf );
#endif /*DEBUG*/

	return( buf );
}

/* Read everything after the pixels into memory.

	FIXME ... why can't we use xmlParserInputBufferCreateFd and parse
	directly from the fd rather than having to read the stupid thing into 
	memory

	the libxml API docs are impossible to decipher

 */
static xmlDoc *
read_xml( IMAGE *im )
{
	void *buf;
	int size;
	xmlDoc *doc;
	xmlNode *node;

	if( !(buf = im__read_extension_block( im, &size )) )
		return( NULL );
	if( !(doc = xmlParseMemory( buf, size )) ) {
		vips_free( buf );
		return( NULL );
	}
	vips_free( buf );
	if( !(node = xmlDocGetRootElement( doc )) ||
		!node->nsDef ||
		!im_isprefix( NAMESPACE, (char *) node->nsDef->href ) ) {
		vips_error( "VipsImage", 
			"%s", _( "incorrect namespace in XML" ) );
		xmlFreeDoc( doc );
		return( NULL );
	}

#ifdef DEBUG
	printf( "read_xml: namespace == %s\n", node->nsDef->href );
#endif /*DEBUG*/

	return( doc );
}

/* Find the first child node with a name.
 */
static xmlNode *
get_node( xmlNode *base, const char *name )
{
	xmlNode *i;

	for( i = base->children; i; i = i->next )
		if( strcmp( (char *) i->name, name ) == 0 )
			return( i );

	return( NULL );
}

/* Read a string property to a buffer. TRUE for success.
 */
static int
get_sprop( xmlNode *xnode, const char *name, char *buf, int sz )
{
        char *value = (char *) xmlGetProp( xnode, (xmlChar *) name );

        if( !value )
                return( 0 );

        im_strncpy( buf, value, sz );
        VIPS_FREEF( xmlFree, value );

        return( 1 );
}

/* Chop history into lines, add each one as a refstring.
 */
static void
set_history( IMAGE *im, char *history )
{
	GSList *history_list;
	char *p, *q;

	/* There can be history there already if we're rewinding.
	 */
	VIPS_FREEF( im__gslist_gvalue_free, im->history_list );

	history_list = NULL;

	for( p = history; *p; p = q ) {
		if( (q = strchr( p, '\n' )) ) {
			*q = '\0';
			q += 1;
		}
		else 
			q = p + strlen( p );

		history_list = g_slist_prepend( history_list, 
			im__gvalue_ref_string_new( p ) );
	}

	im->history_list = g_slist_reverse( history_list );
}

/* Load header fields.
 */
static int
rebuild_header_builtin( IMAGE *im, xmlNode *i )
{
	char name[256];

	if( get_sprop( i, "name", name, 256 ) ) {
		if( strcmp( name, "Hist" ) == 0 ) {
			char *history;

			/* Have to take (another) copy, since we need to free
			 * with xmlFree().
			 */
			history = (char *) xmlNodeGetContent( i );
			set_history( im, history );
			xmlFree( history );
		}
	}

	return( 0 );
}

/* Load meta fields.
 */
static int
rebuild_header_meta( IMAGE *im, xmlNode *i )
{
	char name[256];
	char type[256];

	if( get_sprop( i, "name", name, 256 ) &&
		get_sprop( i, "type", type, 256 ) ) {
		GType gtype = g_type_from_name( type );

		/* Can we convert from IM_SAVE_STRING to type?
		 */
		if( gtype && 
			g_value_type_transformable( 
				IM_TYPE_SAVE_STRING, gtype ) ) {
			char *content;
			GValue save_value = { 0 };
			GValue value = { 0 };

			content = (char *) xmlNodeGetContent( i );
			g_value_init( &save_value, IM_TYPE_SAVE_STRING );
			im_save_string_set( &save_value, content );
			xmlFree( content );

			g_value_init( &value, gtype );
			if( !g_value_transform( &save_value, &value ) ) {
				g_value_unset( &save_value );
				vips_error( "VipsImage", 
					"%s", _( "error transforming from "
					"save format" ) );
				return( -1 );
			}
			if( im_meta_set( im, name, &value ) ) {
				g_value_unset( &save_value );
				g_value_unset( &value );
				return( -1 );
			}
			g_value_unset( &save_value );
			g_value_unset( &value );
		}
	}

	return( 0 );
}

static xmlDoc *
get_xml( IMAGE *im )
{
	if( vips_image_get_typeof( im, IM_META_XML ) ) {
		xmlDoc *doc;

		if( im_meta_get_area( im, IM_META_XML, (void *) &doc ) )
			return( NULL );

		return( doc );
	}

	return( NULL );
}

/* Rebuild header fields that depend on stuff saved in xml.
 */
static int
rebuild_header( IMAGE *im )
{
	xmlDoc *doc;

	if( (doc = get_xml( im )) ) {
		xmlNode *root;
		xmlNode *block;

		if( !(root = xmlDocGetRootElement( doc )) )
			return( -1 );
		if( (block = get_node( root, "header" )) ) {
			xmlNode *i;

			for( i = block->children; i; i = i->next )
				if( strcmp( (char *) i->name, "field" ) == 0 ) 
					if( rebuild_header_builtin( im, i ) )
						return( -1 );
		}
		if( (block = get_node( root, "meta" )) ) {
			xmlNode *i;

			for( i = block->children; i; i = i->next )
				if( strcmp( (char *) i->name, "field" ) == 0 ) 
					if( rebuild_header_meta( im, i ) )
						return( -1 );
		}
	}

	return( 0 );
}

/* Called at the end of im_openin() ... get any XML after the pixel data
 * and read it in.
 */
static int 
im__readhist( IMAGE *im )
{
	/* Junk any old xml meta.
	 */
	if( vips_image_get_typeof( im, IM_META_XML ) ) 
		im_meta_set_area( im, IM_META_XML, NULL, NULL );

	if( im__has_extension_block( im ) ) {
		xmlDoc *doc;

		if( !(doc = read_xml( im )) )
			return( -1 );
		if( im_meta_set_area( im, IM_META_XML, 
			(im_callback_fn) xmlFreeDoc, doc ) ) {
			xmlFreeDoc( doc );
			return( -1 );
		}
	}

	if( rebuild_header( im ) )
		return( -1 );

	return( 0 );
}

#define MAX_STRSIZE (32768)     /* Max size of text for stack strings */

static int
set_prop( xmlNode *node, const char *name, const char *fmt, ... )
{       
        va_list ap;
        char value[MAX_STRSIZE];

        va_start( ap, fmt );
        (void) im_vsnprintf( value, MAX_STRSIZE, fmt, ap );
        va_end( ap );

        if( !xmlSetProp( node, (xmlChar *) name, (xmlChar *) value ) ) {
                vips_error( "VipsImage", _( "unable to set property \"%s\" "
                        "to value \"%s\"." ),
                        name, value );
                return( -1 );
        }       
        
        return( 0 );
}

static int
set_sprop( xmlNode *node, const char *name, const char *value )
{
        if( value && set_prop( node, name, "%s", value ) )
                return( -1 );

        return( 0 );
}

static int
set_field( xmlNode *node, 
	const char *name, const char *type, const char *content )
{
	xmlNode *field;

	if( !(field = xmlNewChild( node, NULL, (xmlChar *) "field", NULL )) || 
		set_sprop( field, "type", type ) ||
		set_sprop( field, "name", name ) )
		return( -1 );
	xmlNodeSetContent( field, (xmlChar *) content );

	return( 0 );
}

static void *
save_fields_meta( Meta *meta, xmlNode *node )
{
	GType type = G_VALUE_TYPE( &meta->value );

	/* If we can transform to IM_TYPE_SAVE_STRING and back, we can save and
	 * restore. 
	 */
	if( g_value_type_transformable( type, IM_TYPE_SAVE_STRING ) &&
		g_value_type_transformable( IM_TYPE_SAVE_STRING, type ) ) {
		GValue save_value = { 0 };

		g_value_init( &save_value, IM_TYPE_SAVE_STRING );
		if( !g_value_transform( &meta->value, &save_value ) ) {
			vips_error( "VipsImage", "%s", 
				_( "error transforming to save format" ) );
			return( node );
		}
		if( set_field( node, meta->field, g_type_name( type ), 
			im_save_string_get( &save_value ) ) ) {
			g_value_unset( &save_value );
			return( node );
		}
		g_value_unset( &save_value );
	}

	return( NULL );
}

static int
save_fields( IMAGE *im, xmlNode *node )
{
	xmlNode *this;

	/* Save header fields.
	 */
	if( !(this = xmlNewChild( node, NULL, (xmlChar *) "header", NULL )) )
		return( -1 ); 
	if( set_field( this, "Hist", 
		g_type_name( IM_TYPE_REF_STRING ), im_history_get( im ) ) ) 
		return( -1 );

	if( !(this = xmlNewChild( node, NULL, (xmlChar *) "meta", NULL )) )
		return( -1 );
	if( im->Meta_traverse && 
		im_slist_map2( im->Meta_traverse, 
			(VSListMap2Fn) save_fields_meta, this, NULL ) )
		return( -1 );

	return( 0 );
}

int
im__write_extension_block( IMAGE *im, void *buf, int size )
{
	gint64 length;
	gint64 psize;

	psize = im__image_pixel_length( im );
	if( (length = im_file_length( im->fd )) == -1 )
		return( -1 );
	if( length - psize < 0 ) {
		vips_error( "VipsImage", "%s", _( "file has been truncated" ) );
		return( -1 );
	}

	if( im__ftruncate( im->fd, psize ) ||
		im__seek( im->fd, psize ) ) 
		return( -1 );
	if( im__write( im->fd, buf, size ) )
                return( -1 );

#ifdef DEBUG
	printf( "im__write_extension_block: written %d bytes of XML to %s\n",
		size, im->filename );
#endif /*DEBUG*/

	return( 0 );
}

#ifdef DEBUG
/* Return a string of n characters. Buffer is zapped each time!
 */
const char *
rpt( char ch, int n )
{
        int i;
        static char buf[200];

        n = IM_MIN( 190, n );

        for( i = 0; i < n; i++ )
                buf[i] = ch;
        buf[i] = '\0';

        return( buf );
}

/* Return a string of n spaces. Buffer is zapped each time!
 */
const char *
spc( int n )
{
        return( rpt( ' ', n ) );
}

static void
prettify_tree_sub( xmlNode *xnode, int indent )
{
        xmlNode *txt;
        xmlNode *next;

        for(;;) {
                next = xnode->next;

                /* According to memprof, this leaks :-( If you cut it out into
                 * a separate prog though, it's OK

                        FIXME ... how odd

                 */
                txt = xmlNewText( "\n" );
                xmlAddPrevSibling( xnode, txt );
                txt = xmlNewText( spc( indent ) );
                xmlAddPrevSibling( xnode, txt );

                if( xnode->children )
                        prettify_tree_sub( xnode->children, indent + 2 );

                if( !next )
                        break;

                xnode = next;
        }

        txt = xmlNewText( spc( indent - 2 ) );
        xmlAddNextSibling( xnode, txt );
        txt = xmlNewText( "\n" );
        xmlAddNextSibling( xnode, txt );
}

/* Walk an XML document, adding extra blank text elements so that it's easier
 * to read. Don't call me twice!
 */
void
prettify_tree( xmlDoc *xdoc )
{
        xmlNode *xnode = xmlDocGetRootElement( xdoc );

        prettify_tree_sub( xnode, 0 );
}
#endif /*DEBUG*/

/* Append XML to output fd.
 */
int 
im__writehist( IMAGE *im )
{
	xmlDoc *doc;
	char namespace[256];
	char *dump;
	int dump_size;

	assert( im->dtype == VIPS_IMAGE_OPENOUT );
	assert( im->fd != -1 );

	if( !(doc = xmlNewDoc( (xmlChar *) "1.0" )) )
		return( -1 );

        im_snprintf( namespace, 256, "%s/%d.%d.%d",
                NAMESPACE,
		IM_MAJOR_VERSION, IM_MINOR_VERSION, IM_MICRO_VERSION );
	if( !(doc->children = xmlNewDocNode( doc, 
			NULL, (xmlChar *) "root", NULL )) ||
                set_sprop( doc->children, "xmlns", namespace ) ||
		save_fields( im, doc->children ) ) {
		vips_error( "VipsImage", "%s", _( "xml save error" ) );
                xmlFreeDoc( doc );
                return( -1 );
        }

	/* Bizarre double-cast stops a bogus gcc 4.1 compiler warning.
	 */
	xmlDocDumpMemory( doc, (xmlChar **) ((char *) &dump), &dump_size );
	if( !dump ) {
		vips_error( "VipsImage", "%s", _( "xml save error" ) );
                xmlFreeDoc( doc );
                return( -1 );
	}

	if( im__write_extension_block( im, dump, dump_size ) ) {
                xmlFreeDoc( doc );
		xmlFree( dump );
                return( -1 );
        }

#ifdef DEBUG
{
	char *dump2;
	int dump_size2;

	/* Uncomment to have XML pretty-printed. Can be annoying during
 	 * debugging tho'
	 */
	prettify_tree( doc );

	xmlDocDumpMemory( doc, (xmlChar **) &dump2, &dump_size2 );
	if( !dump2 ) {
		vips_error( "VipsImage", "%s", _( "xml save error" ) );
                xmlFreeDoc( doc );
		xmlFree( dump );
                return( -1 );
	}
	
	printf( "im__writehist: saved XML is: \"%s\"", dump2 );
	xmlFree( dump2 );
}
#endif /*DEBUG*/

	xmlFreeDoc( doc );
	xmlFree( dump );

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
	unsigned char header[IM_SIZEOF_HEADER];

	gint64 psize;
	gint64 rsize;

	image->dtype = VIPS_IMAGE_OPENIN;
	if( (image->fd = vips__open_image_read( image->filename )) == -1 ) 
		return( -1 );
	if( read( image->fd, header, IM_SIZEOF_HEADER ) != IM_SIZEOF_HEADER ||
		im__read_header_bytes( image, header ) ) {
		vips_error_system( errno, "VipsImage", 
			_( "unable to read header for \"%s\"" ),
			image->filename );
		return( -1 );
	}

	/* Predict and check the file size.
	 */
	psize = im__image_pixel_length( image );
	if( (rsize = im_file_length( image->fd )) == -1 ) 
		return( -1 );
	image->file_length = rsize;
	if( psize > rsize ) 
		vips_warn( "VipsImage", 
			_( "unable to read data for \"%s\", %s" ),
			image->filename, _( "file has been truncated" ) );

	/* Set demand style. This suits a disc file we read sequentially.
	 */
	image->dhint = VIPS_DEMAND_STYLE_THINSTRIP;

	/* Set the history part of im descriptor. Don't return an error if this
	 * fails (due to eg. corrupted XML) because it's probably mostly
	 * harmless.
	 */
	if( im__readhist( image ) ) {
		vips_warn( "VipsImage", _( "error reading XML: %s" ),
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
		unsigned char header[IM_SIZEOF_HEADER];

		if( (image->fd = open( image->filename, 
			MODE_WRITE, 0666 )) < 0 ) {
			vips_error_system( errno, "VipsImage", 
				_( "unable to write to \"%s\"" ), 
				image->filename );
			return( -1 );
		}

		if( im__write_header_bytes( image, header ) ||
			im__write( image->fd, header, IM_SIZEOF_HEADER ) )
			return( -1 );
	}

	return( 0 );
}
