// Object part of VMask class

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
#include <cmath>

#include <vips/vips.h>
#include <vips/vipscpp.h>

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

VIPS_NAMESPACE_START

/* Functions for VMask - refcounting layer over VPMask.
 */

VMask::~VMask()
{
	ref->nrefs--;
	if( !ref->nrefs )
		delete ref;
}

VMask &VMask::operator=( const VMask &a )
{ 
	// Loosing ref to LHS
	ref->nrefs--;

	if( ref->nrefs > 0 )
		// Need fresh refblock
		ref = new refblock;
	else 
		// Recycle old refblock
		delete ref->pmask;

	// LHS now points to RHS
	ref = a.ref; 
	ref->nrefs++; 
	
	return( *this ); 
}

// Make sure this is a private copy of pmask --- dup if nrefs != 1
void VMask::make_private()
{
	if( ref->nrefs > 1 ) {
		// Make fresh refblock
		refblock *ref2 = new refblock;

		// And copy the mask
		ref2->pmask = ref->pmask->dup();
		ref->nrefs--;
		ref = ref2;
	}
}

void VMask::ostream_print( std::ostream &file ) const
{
	file << *(ref->pmask);
}

// Embed INTMASK in VIMask
void VIMask::embed( INTMASK *i ) throw( VError )
{
	if( ref->pmask )
		verror( "embed: VIMask not empty" );
	ref->pmask = new _private_detail::VPIMask( i );
}

// Type conversions: implicit INTMASK to DOUBLEMASK 
VIMask::operator VDMask()
{
	VDMask out( xsize(), ysize() );

	out.mask().dptr->scale = scale();
	out.mask().dptr->offset = offset();

	for( int i = 0; i < size(); i++ )
		out[i] = (*this)[i];

	return( out );
}


// Forward ref of VImage class
class VImage;

// Type conversions: implicit DOUBLEMASK to INTMASK
VDMask::operator VIMask()
{
	VIMask out( xsize(), ysize() );

	out.mask().iptr->scale = int( scale() );
	out.mask().iptr->offset = int( offset() );

	for( int i = 0; i < size(); i++ )
		out[i] = (int) rint( (*this)[i] );

	return( out );
}

// Type conversions: implicit DOUBLEMASK to VImage
VDMask::operator VImage() throw( VError )
{
	VImage out;

	if( im_mask2vips( mask().dptr, out.image() ) )
		verror();

	return( out );
}

// ... and INTMASK to VImage
VIMask::operator VImage() { return( VImage( VDMask( *this ) ) ); }

// Embed DOUBLEMASK in VDMask
void VDMask::embed( DOUBLEMASK *i ) throw( VError )
{
	if( ref->pmask )
		verror( "embed: VDMask not empty" );
	ref->pmask = new _private_detail::VPDMask( i );
}

/* Functions for P*Mask - layer over im_*_*mask() functions.
 */

// Create empty imask
_private_detail::VPIMask::VPIMask( int xsize, int ysize ) throw( VError )
{
	if( !(data.iptr = im_create_imask( "VPIMask::VPIMask", xsize, ysize )) )
		verror();
	type = _private_detail::VPMask::INT;
}

// Init from vector
_private_detail::VPIMask::VPIMask( int xsize, int ysize, 
	int scale, int offset, std::vector<int> coeff )
	throw( VError )
{
	if( !(data.iptr = im_create_imask( "VPIMask::VPIMask", xsize, ysize )) )
		verror();
	type = _private_detail::VPMask::INT;

	data.iptr->scale = scale;
	data.iptr->offset = offset;
	for( int i = 0; i < xsize * ysize; i++ )
		data.iptr->coeff[i] = coeff[i];
}

// Create from filename
_private_detail::VPIMask::VPIMask( const char *name ) throw( VError )
{
	if( !(data.iptr = im_read_imask( (char *) name )) )
		verror();
	type = _private_detail::VPMask::INT;
}

// Create from existing INTMASK
_private_detail::VPIMask::VPIMask( INTMASK *imask )
{
	data.iptr = imask;
	type = _private_detail::VPMask::INT;
}

// Create empty
_private_detail::VPIMask::VPIMask()
{
	data.iptr = 0;
	type = _private_detail::VPMask::UNASSIGNED;
}

_private_detail::VPIMask::~VPIMask()
{
	if( data.iptr ) {
		im_free_imask( data.iptr );
		data.iptr = 0;
		type = _private_detail::VPMask::UNASSIGNED;
	}
}

// Duplicate -- we are a VPIMask, return a new VPIMask which is a copy of us.
// Return as a VPMask tho'.
_private_detail::VPMask *_private_detail::VPIMask::dup() const throw( VError )
{
	_private_detail::VPIMask *out = new _private_detail::VPIMask();

	INTMASK *msk;
	if( !(msk = im_dup_imask( data.iptr, "VPIMask::dup" )) ) {
		delete out;
		verror();
	}
	out->embed( msk );

	return( out );
}

// Insert INTMASK pointer
void _private_detail::VPIMask::embed( INTMASK *msk ) throw( VError )
{
	if( type != _private_detail::VPMask::UNASSIGNED )
		verror( "VPIMask::embed: VPIMask not empty" );

	data.iptr = msk;
	type = _private_detail::VPMask::INT;
}

int _private_detail::VPIMask::xsize() const throw( VError )
{
	if( !data.iptr ) 
		verror( "xsize: mask not set" );

	return( data.iptr->xsize );
}

int _private_detail::VPIMask::ysize() const throw( VError )
{
	if( !data.iptr ) 
		verror( "ysize: mask not set" );

	return( data.iptr->ysize );
}

int _private_detail::VPIMask::scale() const throw( VError )
{
	if( !data.iptr ) 
		verror( "scale: mask not set" );

	return( data.iptr->scale );
}

int _private_detail::VPIMask::offset() const throw( VError )
{
	if( !data.iptr ) 
		verror( "offset: mask not set" );

	return( data.iptr->offset );
}

const char *_private_detail::VPIMask::filename() const throw( VError )
{
	if( !data.iptr ) 
		verror( "filename: mask not set" );

	return( data.iptr->filename );
}

void _private_detail::VPIMask::ostream_print( std::ostream &file ) const 
	throw( VError )
{
	if( !data.iptr )
		verror( "internal error #7447234" );
	
	int i, j;
	int *p = data.iptr->coeff;

	file << this->xsize() << "\t" << this->ysize() << "\t";
	file << this->scale() << "\t" << this->offset() << "\n";

	for( i = 0; i < this->ysize(); i++ ) {
		for( j = 0; j < this->xsize(); j++ )
			file << *p++ << "\t";

		file << "\n";
	}
}

// Extract start of int array
int *_private_detail::VPIMask::array() const 
{ 
	return( data.iptr->coeff ); 
}

// Create empty dmask
_private_detail::VPDMask::VPDMask( int xsize, int ysize ) throw( VError )
{
	if( !(data.dptr = im_create_dmask( "VPDMask::VPDMask", xsize, ysize )) )
		verror();
	type = _private_detail::VPMask::DOUBLE;
}

// Create from vector
_private_detail::VPDMask::VPDMask( int xsize, int ysize, 
	double scale, double offset, std::vector<double> coeff ) throw( VError )
{
	if( !(data.dptr = im_create_dmask( "VPDMask::VPDMask", xsize, ysize )) )
		verror();
	type = _private_detail::VPMask::DOUBLE;

	data.dptr->scale = scale;
	data.dptr->offset = offset;
	for( int i = 0; i < xsize * ysize; i++ )
		data.dptr->coeff[i] = coeff[i];
}

// Create from filename
_private_detail::VPDMask::VPDMask( const char *name ) throw( VError )
{
	if( !(data.dptr = im_read_dmask( (char *) name )) )
		verror();
	type = _private_detail::VPMask::DOUBLE;
}

// Create empty
_private_detail::VPDMask::VPDMask()
{
	data.dptr = 0;
	type = _private_detail::VPMask::UNASSIGNED;
}

// Create from existing DOUBLEMASK
_private_detail::VPDMask::VPDMask( DOUBLEMASK *dmask )
{
	data.dptr = dmask;
	type = _private_detail::VPMask::DOUBLE;
}

_private_detail::VPDMask::~VPDMask()
{
	if( data.dptr ) {
		im_free_dmask( data.dptr );
		data.dptr = 0;
		type = _private_detail::VPMask::UNASSIGNED;
	}
}

// Duplicate -- we are a VPIMask, return a new VPIMask which is a copy of us.
// Return as a VPMask tho'.
_private_detail::VPMask *_private_detail::VPDMask::dup() const throw( VError )
{
	_private_detail::VPDMask *out = new _private_detail::VPDMask();

	DOUBLEMASK *msk;
	if( !(msk = im_dup_dmask( data.dptr, "VPDMask::dup" )) ) {
		delete out;
		verror();
	}
	out->embed( msk );

	return( out );
}

// Insert DOUBLEMASK pointer
void _private_detail::VPDMask::embed( DOUBLEMASK *msk ) throw( VError )
{
	if( type != _private_detail::VPMask::UNASSIGNED )
		verror( "VPDMask::embed: VPDMask not empty" );

	data.dptr = msk;
	type = _private_detail::VPMask::DOUBLE;
}

int _private_detail::VPDMask::xsize() const throw( VError )
{
	if( !data.dptr ) 
		verror( "xsize: mask not set" );

	return( data.dptr->xsize );
}

int _private_detail::VPDMask::ysize() const throw( VError )
{
	if( !data.dptr ) 
		verror( "ysize: mask not set" );

	return( data.dptr->ysize );
}

double _private_detail::VPDMask::scale() const throw( VError )
{
	if( !data.dptr ) 
		verror( "scale: mask not set" );

	return( data.dptr->scale );
}

double _private_detail::VPDMask::offset() const throw( VError )
{
	if( !data.dptr ) 
		verror( "offset: mask not set" );

	return( data.dptr->offset );
}

const char *_private_detail::VPDMask::filename() const throw( VError )
{
	if( !data.dptr ) 
		verror( "filename: mask not set" );

	return( data.dptr->filename );
}

void _private_detail::VPDMask::ostream_print( std::ostream &file ) const 
	throw( VError )
{
	if( !data.dptr )
		verror( "internal error #7447234" );
	
	int i, j;
	double *p = data.dptr->coeff;

	file << this->xsize() << "\t" << this->ysize() << "\t";
	file << this->scale() << "\t" << this->offset() << "\n";

	for( i = 0; i < this->ysize(); i++ ) {
		for( j = 0; j < this->xsize(); j++ )
			file << *p++ << "\t";

		file << "\n";
	}
}

// Extract data pointer
double *_private_detail::VPDMask::array() const 
{ 
	return( data.dptr->coeff ); 
}

// Build functions
VIMask VIMask::gauss( double sig, double minamp ) throw( VError )
{
	VIMask out;
	INTMASK *msk;

	if( !(msk = im_gauss_imask( "VIMask::gauss", sig, minamp )) )
		verror();
	out.embed( msk );

	return( out );
}

VDMask VDMask::gauss( double sig, double minamp ) throw( VError )
{
	VDMask out;
	DOUBLEMASK *msk;

	if( !(msk = im_gauss_dmask( "VDMask::gauss", sig, minamp )) )
		verror();
	out.embed( msk );

	return( out );
}

VIMask VIMask::log( double sig, double minamp ) throw( VError )
{
	VIMask out;
	INTMASK *msk;

	if( !(msk = im_log_imask( "VIMask::log", sig, minamp )) )
		verror();
	out.embed( msk );

	return( out );
}

VDMask VDMask::log( double sig, double minamp ) throw( VError )
{
	VDMask out;
	DOUBLEMASK *msk;

	if( !(msk = im_log_dmask( "VDMask::log", sig, minamp )) )
		verror();
	out.embed( msk );

	return( out );
}

// Manipulation functions
VIMask VIMask::rotate45() throw( VError )
{
	VIMask out;
	INTMASK *msk;

	if( !(msk = im_rotate_imask45( mask().iptr, "VIMask::rotate45" )) )
		verror();
	out.embed( msk );

	return( out );
}

VIMask VIMask::rotate90() throw( VError )
{
	VIMask out;
	INTMASK *msk;

	if( !(msk = im_rotate_imask90( mask().iptr, "VIMask::rotate90" )) )
		verror();
	out.embed( msk );

	return( out );
}

VDMask VDMask::rotate45() throw( VError )
{
	VDMask out;
	DOUBLEMASK *msk;

	if( !(msk = im_rotate_dmask45( mask().dptr, "VDMask::rotate45" )) )
		verror();
	out.embed( msk );

	return( out );
}

VDMask VDMask::rotate90() throw( VError )
{
	VDMask out;
	DOUBLEMASK *msk;

	if( !(msk = im_rotate_dmask90( mask().dptr, "VDMask::rotate90" )) )
		verror();
	out.embed( msk );

	return( out );
}

VDMask VDMask::trn() throw( VError )
{
	VDMask out;
	DOUBLEMASK *msk;

	if( !(msk = im_mattrn( mask().dptr, "VDMask::trn" )) )
		verror();
	out.embed( msk );

	return( out );
}

VDMask VDMask::inv() throw( VError )
{
	VDMask out;
	DOUBLEMASK *msk;

	if( !(msk = im_matinv( mask().dptr, "VDMask::inv" )) )
		verror();
	out.embed( msk );

	return( out );
}

VDMask VDMask::mul( VDMask m ) throw( VError )
{
	VDMask out;
	DOUBLEMASK *msk;

	if( !(msk = im_matmul( mask().dptr, m.mask().dptr, "VDMask::mul" )) )
		verror();
	out.embed( msk );

	return( out );
}

VDMask VDMask::cat( VDMask m ) throw( VError )
{
	VDMask out;
	DOUBLEMASK *msk;

	if( !(msk = im_matcat( mask().dptr, m.mask().dptr, "VDMask::cat" )) )
		verror();
	out.embed( msk );

	return( out );
}

VIMask VDMask::scalei() throw( VError )
{
	VIMask out;
	INTMASK *msk;

	if( !(msk = im_scale_dmask( mask().dptr, "VDMask::scalei" )) )
		verror();
	out.embed( msk );

	return( out );
}

// Arithmetic on a VIMask ... just cast and use VDMask
VDMask VIMask::trn() throw( VError ) 
	{ return( ((VDMask)*this).trn() ); }
VDMask VIMask::inv() throw( VError ) 
	{ return( ((VDMask)*this).inv() ); }
VDMask VIMask::cat( VDMask a ) throw( VError ) 
	{ return( ((VDMask)*this).cat( a ) ); }
VDMask VIMask::mul( VDMask a ) throw( VError ) 
	{ return( ((VDMask)*this).mul( a ) ); }

// Overload [] to get linear array subscript.
// Our caller may write to the result, so make sure we have a private
// copy.
// Involves function call, slow anyway, so do range checking
int &VIMask::operator[]( int x ) throw( VError )
{ 
	if( ref->nrefs != 1 )
		make_private();

	if( x > size() )
		verror( "VIMask::operator[]: subscript out of range" );

	return( ((_private_detail::VPIMask *)ref->pmask)->array()[x] ); 
}

double &VDMask::operator[]( int x ) throw( VError )
{ 
	if( ref->nrefs != 1 )
		make_private();

	if( x > size() )
		verror( "VDMask::operator[]: subscript out of range" );

	return( ((_private_detail::VPDMask *)ref->pmask)->array()[x] ); 
}

VIPS_NAMESPACE_END
