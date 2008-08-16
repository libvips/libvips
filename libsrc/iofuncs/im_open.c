/* @(#) im_open: vips front end to file open functions
ARGS: filename and mode which is one of:
"r" read by mmap (im_mmapin)
"rw" read and write by mmap (im_mmapinrw)
"w" write for write (im_writeline)
"t" for temporary memory image
"p" for partial memory image
RETURNS: IMAGE pointer or 0 on error
Copyright: Kirk Martinez 29/5/92

Modified:
 * 8/8/94 JC
 *	- ANSIfied
 *	- im_open_local added
 * 16/8/94 JC
 *	- im_malloc() added
 * 22/11/94 JC & KM
 *	- tiff added
 * 1/2/95 JC
 *	- tiff removed again!
 *	- now just im_istiff(), im_tiff2vips() and im_vips2tiff()
 * 	- applications have responsibility for making the translation
 * 26/3/96 JC
 *	- im_open_local() now closes on close, not evalend
 * 14/11/96 JC
 *	- tiff and jpeg added again
 * 	- open for read used im_istiff() and im_isjpeg() to switch
 *	- open for write looks at suffix
 * 23/4/97 JC
 *	- im_strdup() now allows NULL IMAGE parameter
 *	- subsample parameter added to im_tiff2vips()
 * 29/10/98 JC
 *	- byte-swap stuff added
 * 16/6/99 JC
 *	- 8x byte swap added for double/double complex
 *	- better error message if file does not exist
 *	- ignore case when testing suffix for save
 *	- fix im_mmapinrw() return test to stop coredump in edvips if
 *	  unwritable
 * 2/11/99 JC
 *	- malloc/strdup stuff moved to memory.c
 * 5/8/00 JC
 *	- fixes for im_vips2tiff() changes
 * 13/10/00 JC
 *	- ooops, missing 'else'
 * 22/11/00 JC
 * 	- ppm read/write added
 * 12/2/01 JC
 * 	- im__image_sanity() added
 * 16/5/01 JC
 *	- now allows RW for non-native byte order, provided it's an 8-bit
 *	  image
 * 11/7/01 JC
 *	- im_tiff2vips() no longer has subsample option
 * 25/3/02 JC
 *	- better im_open() error message
 * 12/12/02 JC
 *	- sanity no longer returns errors, just warns
 * 28/12/02 HB
 *     - Added PNG support
 * 6/5/03 JC
 *	- added im_open_header() (from header.c)
 * 22/5/03 JC
 *	- im__skip_dir() knows about ':' in filenames for vips2tiff etc.
 * 27/11/03 JC
 *	- im_image_sanity() now insists x/y/bands all >0
 * 6/1/04 JC
 *	- moved util funcs out to util.c
 * 18/2/04 JC
 *	- added an im_init_world() to help old progs
 * 16/4/04
 *	- oop, im_open() didn't know about input options in filenames
 * 2/11/04 
 *	- im_open( "r" ) is now lazier ... for non-VIPS formats, we delay 
 *	  read until the first ->generate()
 *	- so im_open_header() is now a no-op
 * 22/6/05
 *	- if TIFF open fails, try going through libmagick
 * 4/8/05
 *	- added analyze read
 * 30/9/05
 * 	- oops, lazy read error recovery didn't clear a pointer
 * 1/5/06
 *	- added OpenEXR read
 * 9/6/06
 * 	- added CSV read/write
 * 20/9/06
 * 	- test for NULL filename/mode, common if you forget to check argc
 * 	  (thanks bruno)
 * 7/11/07
 * 	- use preclose, not evalend, for delayed save
 * 	- add simple cmd-line progress feedback
 * 9/8/08
 * 	- lock global image list (thanks lee)
 * 25/5/08
 * 	- break file format stuff out to the new pluggable image format system
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
#define DEBUG_IO
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
#include <vips/debug.h>
#include <vips/internal.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/* Progress feedback. Only really useful for testing, tbh.
 */
int im__progress = 0;

void
im_progress_set( int progress )
{
	im__progress = progress;
}

/* Delayed save: if we write to TIFF or to JPEG format, actually do the write
 * to a "p" and on preclose do im_vips2tiff() or whatever. Track save
 * parameters here.
 */
typedef struct {
	int (*save_fn)();	/* Save function */
	IMAGE *im;		/* Image to save */
	char *filename;		/* Save args */
} SaveBlock;

/* From preclose callback: invoke a delayed save.
 */
static int
invoke_sb( SaveBlock *sb )
{
	if( sb->save_fn( sb->im, sb->filename ) )
		return( -1 );

	return( 0 );
}

/* Attach a SaveBlock to an image.
 */
static int
attach_sb( IMAGE *out, int (*save_fn)(), const char *filename )
{
	SaveBlock *sb = IM_NEW( out, SaveBlock );

	if( !sb )
		return( -1 );
	sb->im = out;
	sb->save_fn = save_fn;
	sb->filename = im_strdup( out, filename );

	if( im_add_preclose_callback( out, 
		(im_callback_fn) invoke_sb, (void *) sb, NULL ) )
		return( -1 );

	return( 0 );
}

/* Lazy open: init a descriptor from a filename (just read the header) but
 * delay actually decoding pixels until the first call to a start function.
 */

typedef int (*OpenLazyFn)( const char *filename, IMAGE *im );

/* What we track during a delayed open.
 */
typedef struct _OpenLazy {
	char *filename;

	OpenLazyFn read_pixels;	/* Read in pixels with this */
	IMAGE *lazy_im;		/* Image we read to .. copy from this */
} OpenLazy;

/* Our start function ... do the lazy open, if necessary, and return a region
 * on the new image.
 */
static void *
open_lazy_start( IMAGE *out, void *a, void *dummy )
{
	OpenLazy *lazy = (OpenLazy *) a;

	if( !lazy->lazy_im ) {
		if( !(lazy->lazy_im = im_open_local( out, "read", "p" )) || 
			lazy->read_pixels( lazy->filename, lazy->lazy_im ) ) {
			IM_FREEF( im_close, lazy->lazy_im );
			return( NULL );
		}
	}

	return( im_region_create( lazy->lazy_im ) );
}

/* Just copy.
 */
static int
open_lazy_generate( REGION *or, void *seq, void *a, void *b )
{
	REGION *ir = (REGION *) seq;

        Rect *r = &or->valid;

        /* Ask for input we need.
         */
        if( im_prepare( ir, r ) )
                return( -1 );

        /* Attach output region to that.
         */
        if( im_region_region( or, ir, r, r->left, r->top ) )
                return( -1 );

        return( 0 );
}

/* Lazy open ... init the header with the first OpenLazyFn, delay actually
 * decoding pixels with the second OpenLazyFn until the first generate().
 */
static int
open_lazy( OpenLazyFn read_header, OpenLazyFn read_pixels, 
	const char *filename, IMAGE *out )
{
	OpenLazy *lazy = IM_NEW( out, OpenLazy );

	if( !lazy ||
		!(lazy->filename = im_strdup( out, filename )) )
		return( -1 );
	lazy->read_pixels = read_pixels;
	lazy->lazy_im = NULL;

	if( read_header( filename, out ) )
		return( -1 );

	if( im_generate( out, 
		open_lazy_start, open_lazy_generate, im_stop_one, 
		lazy, NULL ) )
		return( -1 );

	return( 0 );
}

static IMAGE *
open_sub( OpenLazyFn read_header, OpenLazyFn read_pixels, const char *filename )
{
	IMAGE *im;

	if( !(im = im_open( filename, "p" )) || 
		open_lazy( read_header, read_pixels, filename, im ) ) {
		im_close( im );
		return( NULL );
	}

	return( im );
}

/* Progress feedback. 
 */

/* What we track during an eval.
 */
typedef struct {
	IMAGE *im;

	int last_percent;	/* The last %complete we displayed */
} Progress;

int
evalstart_cb( Progress *progress )
{
	progress->last_percent = 0;

	return( 0 );
}

int
eval_cb( Progress *progress )
{
	IMAGE *im = progress->im;

	if( im->time->percent != progress->last_percent ) {
		/* \r at end returns to the start of this line.
		 */
		printf( _( "%s %s: %d%% complete\r" ), 
			g_get_prgname(), im->filename, im->time->percent );
		fflush( stdout );

		progress->last_percent = im->time->percent;
	}

	return( 0 );
}

int
evalend_cb( Progress *progress )
{
	IMAGE *im = progress->im;

	/* Spaces at end help to erase the %complete message we overwrite.
	 */
	printf( _( "%s %s: done in %ds          \n" ), 
		g_get_prgname(), im->filename, im->time->run );

	return( 0 );
}

IMAGE *
im_open( const char *filename, const char *mode )
{
	IMAGE *im;
	im_format_t *format;
	char name[FILENAME_MAX];
	char mode2[FILENAME_MAX];

	/* Pass in a nonsense name for argv0 ... this init world is only here
	 * for old programs which are missing an im_init_world() call. We must
	 * have threads set up before we can process.
	 */
	if( im_init_world( "vips" ) )
		im_error_clear();

	if( !filename || !mode ) {
		im_error( "im_open", _( "NULL filename or mode" ) );
		return( NULL );
	}

	/*

	 	FIXME ... we have to split the filename here because 
		im_isvips() needs a filename without a mode extension

		can we fold the vips open code into the format system somehow?
		we need to consider large file and pipeline support carefully

	 */
	im_filename_split( filename, name, mode2 );

	switch( mode[0] ) {
        case 'r':
		if( im_isvips( name ) ) {
			if( !(im = im_open_vips( filename )) )
				return( NULL );
		}
		else if( (format = im_format_for_file( filename )) ) {
			if( !(im = open_sub( 
				format->header, format->load, filename )) )
				return( NULL );
		}
		else
			return( NULL );
        	break;

	case 'w':
		if( (format = im_format_for_name( filename )) ) {
			if( !(im = im_open( "im_open:lazy_write:1", "p" )) )
				return( NULL );
			if( attach_sb( im, format->save, filename ) ) {
				im_close( im );
				return( NULL );
			}
		}
		else
			im = im_openout( filename );
        	break;

        case 't':
                im = im_setbuf( filename );
                break;

        case 'p':
                im = im_partial( filename );
                break;

	default:
		im_error( "im_open", _( "bad mode \"%s\"" ), mode );
		return( NULL );
        }

	/* Attach progress feedback, if required.
	 */
	if( im__progress ) {
		Progress *progress = IM_NEW( im, Progress );

		progress->im = im;
		im_add_evalstart_callback( im, 
			(im_callback_fn) evalstart_cb, progress, NULL );
		im_add_eval_callback( im, 
			(im_callback_fn) eval_cb, progress, NULL );
		im_add_evalend_callback( im, 
			(im_callback_fn) evalend_cb, progress, NULL );
	}

#ifdef DEBUG_IO
	printf( "im_open: success for %s (%p)\n", im->filename, im );
#endif /*DEBUG_IO*/

	return( im );
}

/* Test an image for sanity. We could add many more tests here.
 */
static const char *
image_sanity( IMAGE *im )
{
	if( !im ) 
		return( "NULL descriptor" );
	if( !im->filename ) 
		return( "NULL filename" );

	g_mutex_lock( im__global_lock );
	if( !g_slist_find( im__open_images, im ) ) {
		g_mutex_unlock( im__global_lock );
		return( "not on open image list" );
	}
	g_mutex_unlock( im__global_lock );

	if( im->Xsize <= 0 || im->Ysize <= 0 || im->Bands <= 0 ) 
		return( "bad dimensions" );
	if( im->BandFmt < -1 || im->BandFmt > IM_BANDFMT_DPCOMPLEX ||
		(im->Coding != -1 &&
			im->Coding != IM_CODING_NONE && 
			im->Coding != IM_CODING_LABQ) ||
		im->Type < -1 || im->Type > IM_TYPE_GREY16 ||
		im->dtype > IM_PARTIAL || im->dhint > IM_ANY ) 
		return( "bad enum value" );
	if( im->Xres < 0 || im->Xres < 0 ) 
		return( "bad resolution" );

	return( NULL );
}

int 
im_image_sanity( IMAGE *im )
{
	const char *msg;

	if( (msg = image_sanity( im )) ) {
		im_warn( "im_image_sanity", "%p", im );
		im_warn( "im_image_sanity", "\"%s\" %s",
			im ? (im->filename ? im->filename : "") : "", 
			msg );
		im_printdesc( im );

		return( -1 );
	}

	return( 0 );
}

/* Just here for compatibility.
 */
IMAGE *
im_open_header( const char *file )
{
	return( im_open( file, "r" ) );
}
