/* @(#)  Reads one line of description and the history of the filename
 * @(#)  This is done by replacing the ending .v of the filename with .desc
 * @(#) and trying to read the new file.  If the file ending in .desc
 * @(#) does exist it is read and put into the Hist pointer of the
 * @(#) image descriptor
 * @(#)  If the .desc file does not exist or if the input file is not
 * @(#) ending with .v the Hist pointer in initialised to "filename\n" 
 * @(#) and history is kept from the current processing stage.
 * @(#)
 * @(#) int im_readhist(image)
 * @(#) IMAGE *image;
 * @(#)
 * @(#)  Returns either 0 (success) or -1 (fail)
 * Copyright: Nicos Dessipris
 * Written on: 15/01/1990
 * Modified on : 
 * 28/10/92 JC
 *	- no more wild freeing!
 *	- behaves itself, thank you
 * 13/1/94 JC
 *	- array-bounds write found and fixed 
 * 26/10/98 JC
 *	- binary open for stupid systems
 * 24/9/01 JC
 *	- slight clean up
 * 6/8/02 JC
 *	- another cleanup
 * 11/7/05
 *	- now read XML from after the image data rather than a separate
 *	  annoying file
 * 	- added im__writehist() to write XML to the image
 * 5/10/05
 * 	- added wrappers for seek/truncate with native win32 calls for long 
 * 	  file support
 * 3/1/07
 * 	- set history_list instead
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

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Our XML namespace.
 */
#define NAMESPACE "http://www.vips.ecs.soton.ac.uk/vips" 

/* Need our own seek(), since lseek() on win32 can't do long files.
 */
static int
im__seek( int fd, gint64 pos )
{
#ifdef OS_WIN32
{
	HANDLE hFile = (HANDLE) _get_osfhandle( fd );
	LARGE_INTEGER p;

	p.QuadPart = pos;
	if( !SetFilePointerEx( hFile, p, NULL, FILE_BEGIN ) ) {
                im_error_system( GetLastError(), "im__seek", 
			_( "unable to seek" ) );
		return( -1 );
	}
}
#else /*!OS_WIN32*/
	if( lseek( fd, pos, SEEK_SET ) == (off_t) -1 ) {
		im_error( "im__seek", _( "unable to seek" ) );
		return( -1 );
	}
#endif /*OS_WIN32*/

	return( 0 );
}

/* Need our own ftruncate(), since ftruncate() on win32 can't do long files.

	DANGER ... this moves the file pointer to the end of file on win32,
	but not on *nix; don't make any assumptions about the file pointer
	position after calling this

 */
static int
im__ftruncate( int fd, gint64 pos )
{
#ifdef OS_WIN32
{
	HANDLE hFile = (HANDLE) _get_osfhandle( fd );
	LARGE_INTEGER p;

	p.QuadPart = pos;
	if( im__seek( fd, pos ) )
		return( -1 );
	if( !SetEndOfFile( hFile ) ) {
                im_error_system( GetLastError(), "im__ftruncate", 
			_( "unable to truncate" ) );
		return( -1 );
	}
}
#else /*!OS_WIN32*/
	if( ftruncate( fd, pos ) ) {
		im_error_system( errno, "im__ftruncate", 
			_( "unable to truncate" ) );
		return( -1 );
	}
#endif /*OS_WIN32*/

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
	if( !(buf = im_malloc( NULL, length + 1 )) )
		return( NULL );
	if( read( fd, buf, length ) != length ) {
		im_free( buf );
		im_error( "im_readhist", _( "unable to read history" ) );
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
	gint64 length;
	gint64 psize;

	psize = im__image_pixel_length( im );
	if( (length = im_file_length( im->fd )) == -1 ) 
		return( 0 );

	return( length - psize > 0 );
}

/* Read everything after the pixels into memory.
 */
void *
im__read_extension_block( IMAGE *im, int *size )
{
	gint64 length;
	gint64 psize;
	void *buf;

	psize = im__image_pixel_length( im );
	if( (length = im_file_length( im->fd )) == -1 ) 
		return( NULL );
	if( length - psize > 10 * 1024 * 1024 ) {
		im_error( "im_readhist",
			_( "more than a 10 megabytes of XML? "
			"sufferin' succotash!" ) );
		return( NULL );
	}
	if( length - psize == 0 )
		return( NULL );
	if( !(buf = read_chunk( im->fd, psize, length - psize )) )
		return( NULL );
	if( size )
		*size = length - psize;

#ifdef DEBUG
	printf( "im__read_extension_block: read %d bytes from %s\n",
		(int) (length - psize), im->filename );
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
		im_free( buf );
		return( NULL );
	}
	im_free( buf );
	if( !(node = xmlDocGetRootElement( doc )) ||
		!node->nsDef ||
		!im_isprefix( NAMESPACE, (char *) node->nsDef->href ) ) {
		im_error( "im__readhist", _( "incorrect namespace in XML" ) );
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
        IM_FREEF( xmlFree, value );

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
	IM_FREEF( im__gslist_gvalue_free, im->history_list );

	history_list = NULL;

	for( p = history; *p; p = q ) {
		if( (q = strchr( p, '\n' )) ) 
			*q = '\0';
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
				im_error( "im__readhist", _( "error "
					"transforming from save format" ) );
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
	if( im_header_get_type( im, IM_META_XML ) ) {
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

/* Called at the end of im__read_header ... get any XML after the pixel data
 * and read it in.
 */
int 
im__readhist( IMAGE *im )
{
	/* Junk any old xml meta.
	 */
	if( im_header_get_type( im, IM_META_XML ) ) 
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
                im_error( "im_writehist", _( "unable to set property \"%s\" "
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
			im_error( "im__writehist", 
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
		im_error( "im__write_extension_block",
			_( "file has been truncated" ) );
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

	assert( im->dtype == IM_OPENOUT );
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
		im_error( "im__writehist", _( "xml save error" ) );
                xmlFreeDoc( doc );
                return( -1 );
        }

	/* Bizarre double-cast stops a bogus gcc 4.1 compiler warning.
	 */
	xmlDocDumpMemory( doc, (xmlChar **) ((char *) &dump), &dump_size );
	if( !dump ) {
		im_error( "im__writehist", _( "xml save error" ) );
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
		im_error( "im__writehist", _( "xml save error" ) );
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
