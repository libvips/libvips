// Object part of VImage class

/*

    Copyright (C) 1991-2001 The National Gallery

    This program is free software; you can redistribute it and/or modify
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

#include <cstdlib>
#include <cstdio>

#include <vips/vips.h>
#include <vips/vipscpp.h>
#include <vips/internal.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

/*
#define DEBUG
 */

VIPS_NAMESPACE_START

void VImage::refblock::debug_print()
{
	std::list<refblock *>::iterator i;

	printf( "refblock %p:\n", this );
	printf( "  im = %p", im );
	if( im && im->filename ) 
		printf( " (im->filename = \"%s\")", im->filename );
	printf( "\n" );
	printf( "  close_on_delete = %d\n", close_on_delete );
	printf( "  nrefs (refs to us) = %d\n", nrefs );
	printf( "  orefs (refs we make) = refblocks " );
	for( i = orefs.begin(); i != orefs.end(); i++ )
		printf( "%p ", *i );
	printf( "\n" );
}

// dump all refblocks for debugging
void VImage::print_all()
{
#ifdef DEBUG
	std::list<VImage::refblock *>::iterator i;

	printf( "*** VImage::refblock::print_all() start\n" );
	for( i = all_refblock.begin(); i != all_refblock.end(); i++ )
		(*i)->debug_print();
	printf( "*** VImage::refblock::print_all() end\n" );
#endif /*DEBUG*/
}

// easy call from C version
void im__ccp_print_all()
{
	VImage::print_all();
}

// constructor
VImage::refblock::refblock() 
{
	im = 0; 
	close_on_delete = 1; 
	nrefs = 1; 

#ifdef DEBUG
	all_refblock.push_front( this );
#endif /*DEBUG*/
}

// Add a ref - this (output image) depends upon IMAGE in
void VImage::refblock::addref( refblock *in ) throw( VError )
{
	if( this == in )
		verror( "sanity failure" );

	in->nrefs++;
	orefs.push_front( in );
}

VImage::refblock::~refblock() throw( VError )
{
#ifdef DEBUG
	printf( "VImage::refblock::removeref(): death!\n" );
	debug_print();
#endif /*DEBUG*/

	std::list<refblock *>::iterator i;

	if( close_on_delete && im ) {
		if( im_close( im ) )
			verror();
		im = 0;
	}

	// remove any refs we have ... may trigger other destructs in turn
	for( i = orefs.begin(); i != orefs.end(); i++ )
		(*i)->removeref();

#ifdef DEBUG
	all_refblock.remove( this );
#endif /*DEBUG*/
}

// Remove a ref
void VImage::refblock::removeref() throw( VError )
{
	nrefs--;
	if( nrefs < 0 )
		verror( "too many closes!" );		
	if( nrefs == 0 ) 
		delete this;
}

// Init with name ... means open for read.
VImage::VImage( const char *name, const char *mode ) throw( VError )
{
	_ref = new refblock;

	if( !(_ref->im = im_open( name, mode )) )
		verror();
	_ref->close_on_delete = 1;

#ifdef DEBUG
	printf( "VImage::VImage( \"%s\", \"%s\" )\n", name, mode );
	_ref->debug_print();
#endif /*DEBUG*/
}

// Build a VImage from an IMAGE structure
VImage::VImage( im__IMAGE *in )
{
	_ref = new refblock;
	
	_ref->im = in;
	_ref->close_on_delete = 0;

#ifdef DEBUG
	printf( "VImage::VImage( IMAGE* %p )\n", in );
	_ref->debug_print();
#endif /*DEBUG*/
}

// Build from memory buffer
VImage::VImage( void *buffer, int width, int height, 
	int bands, TBandFmt format ) throw( VError )
{
	_ref = new refblock;

	if( !(_ref->im = im_image( buffer, width, height, 
		bands, int( format ) )) )
		verror();
	_ref->close_on_delete = 1;

#ifdef DEBUG
	printf( "VImage::VImage( void* %p, %d, %d )\n", 
		buffer, width, height );
	_ref->debug_print();
#endif /*DEBUG*/
}

// Empty init ... means open intermediate
VImage::VImage() throw( VError )
{
	static int id = 0;
	char filename[256];

	_ref = new refblock;

	/* This is not 100% safe if VIPS threading is not implemented on this
	 * platform ... but it doesn't really matter.
	 */
	g_mutex_lock( im__global_lock );
	im_snprintf( filename, 256, "intermediate image #%d", id++ );
	g_mutex_unlock( im__global_lock );

	if( !(_ref->im = im_open( filename, "p" )) )
		verror();
	_ref->close_on_delete = 1;

#ifdef DEBUG
	printf( "VImage::VImage()\n" ); 
	_ref->debug_print();
#endif /*DEBUG*/
}

// Copy constructor
VImage::VImage( const VImage &a ) 
{ 
	_ref = a._ref; 
	_ref->nrefs++; 
}

// Assignment
VImage &VImage::operator=( const VImage &a ) throw( VError )
{ 
	_ref->removeref(); 
	_ref = a._ref; 
	_ref->nrefs++; 
	
	return( *this ); 
}

// Extract underlying data pointer
void *VImage::data() const throw( VError )
{
	if( im_incheck( _ref->im ) )
		verror();
	
	return( (void *) _ref->im->data );
}

void VImage::debug_print()
{
	im_printdesc( image() );
}

// Write this to a VImage
VImage VImage::write( VImage out ) throw( VError )
{
	if( im_copy( _ref->im, out._ref->im ) )
		verror();
	out._ref->addref( _ref );

	return( out );
}

VImage VImage::write( const char *name ) throw( VError )
{
	VImage out( name, "w" );

	if( im_copy( _ref->im, out._ref->im ) )
		verror();
	out._ref->addref( _ref );

	return( out );
}

VImage VImage::write() throw( VError )
{
	VImage out( "VImage:w1", "t" );

	if( im_copy( _ref->im, out._ref->im ) )
		verror();
	out._ref->addref( _ref );

	return( out );
}

// Projection functions to get header fields
int VImage::Xsize() { return( _ref->im->Xsize ); }
int VImage::Ysize() { return( _ref->im->Ysize ); }
int VImage::Bands() { return( _ref->im->Bands ); }
VImage::TBandFmt VImage::BandFmt() 
	{ return( (TBandFmt) _ref->im->BandFmt ); }
VImage::TCoding VImage::Coding() 
	{ return( (TCoding) _ref->im->Coding ); }
VImage::TType VImage::Type() { return( (TType) _ref->im->Type ); }
float VImage::Xres() { return( _ref->im->Xres ); }
float VImage::Yres() { return( _ref->im->Yres ); }
int VImage::Length() { return( _ref->im->Length ); }
VImage::TCompression VImage::Compression() 
	{ return( (TCompression) _ref->im->Compression ); }
short VImage::Level() { return( _ref->im->Level ); }
int VImage::Xoffset() { return( _ref->im->Xoffset ); }
int VImage::Yoffset() { return( _ref->im->Yoffset ); }

// Derived fields
const char *VImage::filename() { return( _ref->im->filename ); }
const char *VImage::Hist() { return( im_history_get( _ref->im ) ); }

// Set header fields and setbuf() in one go.
void VImage::initdesc( int x, int y, int b,
	TBandFmt f, TCoding c, TType t, float xr, float yr, int xo, int yo )
	throw( VError )
{
	static int fmt[] = { 
		0, 				// NOTSET
		IM_BBITS_BYTE, IM_BBITS_BYTE,	// uchar/char
		IM_BBITS_SHORT, IM_BBITS_SHORT,	// ushort/short
		IM_BBITS_INT, IM_BBITS_INT,	// uint/int
		IM_BBITS_FLOAT,			// float types ...
		IM_BBITS_COMPLEX,
		IM_BBITS_DOUBLE,
		IM_BBITS_DPCOMPLEX
	};

	im_initdesc( _ref->im, x, y, b, 
		fmt[(int)f + 1], f, c, t, xr, yr, xo, yo );
	if( im_setupout( _ref->im ) )
		verror();
}

// Create a Vargv from a name
Vargv::Vargv( const char *name )
{
	im_function *f = im_find_function( (char *) name );
	
	if( !f )
		verror();

	fn = (im__function *) f;
	base = new im_object[f->argc]; 
	if( im_allocate_vargv( f, base ) ) {
		delete[] base;
		verror();
	}
}

// Destroy a Vargv
Vargv::~Vargv()
{
	im_function *f = (im_function *) fn;

	// free any memory allocated for input vectors
	// this is the stuff allocated in each function during _object* build,
	// see vipsc++.cc
	for( int i = 0; i < f->argc; i++ ) {
		im_type_desc *ty = f->argv[i].desc;

		if( !(ty->flags & IM_TYPE_OUTPUT) ) {
			if( strcmp( ty->type, IM_TYPE_IMAGEVEC ) == 0 ||
				strcmp( ty->type, IM_TYPE_DOUBLEVEC ) == 0 ||
				strcmp( ty->type, IM_TYPE_INTVEC ) == 0 ) {
				// will work for doublevec and intvec too
				im_imagevec_object *io = 
					(im_imagevec_object *) base[i];

				if( io->vec ) {
					delete[] io->vec;
					io->vec = NULL;
				}
			}
		}
	}

	im_free_vargv( f, base );
	delete[] base;
}

// Call the function
void
Vargv::call()
{
	im_function *f = (im_function *) fn;

	if( f->disp( base ) ) 
		verror();
}

/* Insert automatically generated wrappers for VIPS image processing 
 * functions.
 */
#include "vipsc++.cc"

VIPS_NAMESPACE_END
