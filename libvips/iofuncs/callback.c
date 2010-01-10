/* Close and generate callbacks.
 * 
 * 1/7/93 JC
 * 20/7/93 JC
 *	- eval callbacks added
 * 16/8/94 JC
 *	- evalend callbacks added
 * 16/1/04 JC
 *	- now always calls all callbacks, even if some fail
 * 2/7/08
 *	- added invalidate callbacks
 * 26/11/08
 * 	- don't set im_error() on callback failed, that's the user's job
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
#include <stdlib.h>
#include <stdarg.h>

#include <vips/vips.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/**
 * SECTION: callback
 * @short_description: image callbacks
 * @stability: Stable
 * @see_also: <link linkend="libvips-image">image</link>
 * @include: vips/vips.h
 *
 * Images trigger various callbacks at various points in their lifetime. You
 * can register callbacks and be notified of various events, such as
 * evaluation progress or close.
 *
 * Callbacks should return 0 for success, or -1 on error, setting an error
 * message with im_error().
 */

/* Callback struct. We attach a list of callbacks to images to be invoked when
 * the image is closed. These do things like closing previous elements in a
 * chain of operations, freeing client data, etc.
 */
typedef struct {
	IMAGE *im;		/* IMAGE we are attached to */
	im_callback_fn fn;	/* callback function */
	void *a, *b;		/* arguments to callback */
} VCallback;

/* Add a callback to an IMAGE. We can't use IM_NEW(), note! Freed eventually by
 * im__close(), or by im_generate(), etc. for evalend callbacks.
 */
static int
add_callback( IMAGE *im, GSList **cblist, im_callback_fn fn, void *a, void *b )
{	
	VCallback *cbs;

	if( !(cbs = IM_NEW( NULL, VCallback )) )
		return( -1 );
	
	cbs->fn = fn;
	cbs->a = a;
	cbs->b = b;
	cbs->im = im;
	*cblist = g_slist_prepend( *cblist, cbs );

	return( 0 );
}

/**
 * im_add_close_callback:
 * @im: image to attach callback to
 * @fn: callback function
 * @a: user data 1
 * @b: user data 2
 *
 * Attaches a close callback @fn to @im.
 *
 * Close callbacks are triggered exactly once, when the image has been closed
 * and most resources freed, but just before the memory for @im is released.
 *
 * Close callbacks are a good place to free memory that was need to generate
 * @im. You can close other images and there
 * may even be circularity in your close lists.
 *
 * See also: im_malloc() (implemented with im_add_close_callback()),
 * im_add_preclose_callback() (called earlier in the image close process),
 * im_free().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
im_add_close_callback( IMAGE *im, im_callback_fn fn, void *a, void *b )
{	
	return( add_callback( im, &im->closefns, fn, a, b ) );
}

/**
 * im_add_postclose_callback:
 * @im: image to attach callback to
 * @fn: callback function
 * @a: user data 1
 * @b: user data 2
 *
 * Attaches a close callback @fn to @im.
 *
 * Post-close callbacks are triggered exactly once, just before the memory
 * associated with @im is released. 
 *
 * Close callbacks are a good place to delete temporary files. You can close 
 * other images and there may even be circularity in your close lists.
 *
 * Returns: 0 on success, or -1 on error.
 */
int
im_add_postclose_callback( IMAGE *im, im_callback_fn fn, void *a, void *b )
{	
	return( add_callback( im, &im->postclosefns, fn, a, b ) );
}

/**
 * im_add_preclose_callback:
 * @im: image to attach callback to
 * @fn: callback function
 * @a: user data 1
 * @b: user data 2
 *
 * Attaches a pre-close callback @fn to @im.
 *
 * Pre-close callbacks are triggered exactly once just before an image is
 * closed. The image is still valid and you can do anything with it, except
 * stop close from happening.
 *
 * Pre-close callbacks are a good place for languae bindings to break as
 * association between the language object and the VIPS image.
 *
 * Returns: 0 on success, or -1 on error.
 */
int
im_add_preclose_callback( IMAGE *im, im_callback_fn fn, void *a, void *b )
{	
	return( add_callback( im, &im->preclosefns, fn, a, b ) );
}

/**
 * im_add_eval_callback:
 * @im: image to attach callback to
 * @fn: callback function
 * @a: user data 1
 * @b: user data 2
 *
 * Attaches an eval callback @fn to @im.
 *
 * Eval callbacks are called during evaluation and are a good place to give
 * the user feedback about computation progress. In the eval callback, you may
 * look at the #VipsProgress #time member of #IMAGE to get information about 
 * the number of
 * pels processed, elapsed time, and so on.
 *
 * Eval callbacks are inherited. That is, any images which use your  image
 * as  input  will inherit your eval callbacks. As a result, if you add an
 * eval callback to an image, you will be notified if any later image uses
 * your image for computation.
 *
 * If  a  later image adds eval callbacks, then the inheritance is broken,
 * and that image will recieve notification instead.
 *
 * See also: im_add_evalend_callback(), im_add_evalstart_callback().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
im_add_eval_callback( IMAGE *im, im_callback_fn fn, void *a, void *b )
{
	/* Mark this image as needing progress feedback. im__link_make()
	 * propogates this value to our children as we build a pipeline.
	 * im__handle_eval() looks up the IMAGE it should signal on.
	 */
	im->progress = im;

	return( add_callback( im, &im->evalfns, fn, a, b ) );
}

/**
 * im_add_evalend_callback:
 * @im: image to attach callback to
 * @fn: callback function
 * @a: user data 1
 * @b: user data 2
 *
 * Attaches an eval end callback @fn to @im.
 *
 * Eval end callbacks are called at the end of evaluation. They are a good
 * place to clean up after progress notification or to display some
 * diagnostics about computation (eg. an overflow count). They can be called 
 * many times. Every evalend call is guaranteed to have a matching evalstart,
 * but not necessarily any eval calls.
 *
 * Eval callbacks are inherited. That is, any images which use your  image
 * as  input  will inherit your eval callbacks. As a result, if you add an
 * eval callback to an image, you will be notified if any later image uses
 * your image for computation.
 *
 * If  a  later image adds eval callbacks, then the inheritance is broken,
 * and that image will recieve notification instead.
 *
 * See also: im_add_eval_callback(), im_add_evalstart_callback().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
im_add_evalend_callback( IMAGE *im, im_callback_fn fn, void *a, void *b )
{	
	return( add_callback( im, &im->evalendfns, fn, a, b ) );
}

/**
 * im_add_evalstart_callback:
 * @im: image to attach callback to
 * @fn: callback function
 * @a: user data 1
 * @b: user data 2
 *
 * Attaches an eval start callback @fn to @im.
 *
 * Eval start callbacks are called at the beginning of evaluation. They are a 
 * good
 * place to get ready to give progress notification.
 * They can be called 
 * many times. Every evalend call is guaranteed to have a matching evalstart,
 * but not necessarily any eval calls.
 *
 * Eval callbacks are inherited. That is, any images which use your  image
 * as  input  will inherit your eval callbacks. As a result, if you add an
 * eval callback to an image, you will be notified if any later image uses
 * your image for computation.
 *
 * If  a  later image adds eval callbacks, then the inheritance is broken,
 * and that image will recieve notification instead.
 *
 * See also: im_add_eval_callback(), im_add_evalend_callback().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
im_add_evalstart_callback( IMAGE *im, im_callback_fn fn, void *a, void *b )
{	
	return( add_callback( im, &im->evalstartfns, fn, a, b ) );
}

/**
 * im_add_invalidate_callback:
 * @im: image to attach callback to
 * @fn: callback function
 * @a: user data 1
 * @b: user data 2
 *
 * Attaches an invalidate callback @fn to @im.
 *
 * Invalidate callbacks are triggered
 * when VIPS invalidates the cache on an image. This is useful for
 * removing images from other, higher-level caches.
 *
 * See also: im_invalidate().
 *
 * Returns: 0 on success, or -1 on error.
 */
int
im_add_invalidate_callback( IMAGE *im, im_callback_fn fn, void *a, void *b )
{	
	return( add_callback( im, &im->invalidatefns, fn, a, b ) );
}

/* Perform a user callback. 
 */
static void *
call_callback( VCallback *cbs, int *result )
{
	int res;

	if( (res = cbs->fn( cbs->a, cbs->b )) ) {
		/* We don't set im_error() here, that's the callback's
		 * responsibility.
		 */
		*result = res;

#ifdef DEBUG_IO
		printf( "im__trigger_callbacks: user callback "
			"failed for %s\n", cbs->im->filename );
#endif /*DEBUG_IO*/
	}

	return( NULL );
}

/* Perform a list of user callbacks.
 */
int
im__trigger_callbacks( GSList *cblist )
{
	int result;

#ifdef DEBUG_IO
	printf( "im__trigger_callbacks: calling %d user callbacks ..\n",
		g_slist_length( cblist ) );
#endif /*DEBUG_IO*/

	result = 0;
	(void) im_slist_map2( cblist, 
		(VSListMap2Fn) call_callback, &result, NULL );

	return( result );
}
