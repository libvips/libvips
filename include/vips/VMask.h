/* VIPS mask class.
 *
 * Just like VImage, but we don't need dependency stuff. Instead, have a base
 * wrapper over *MASK, derive VMaskD and VMaskI from that, and then put
 * refcounting over all of them.
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

#ifndef IM_VMASK_H
#define IM_VMASK_H

/* SWIG includes this file directly rather than going through vipscpp.h ... so
 * we have to define these macros here as well.
 */
#ifdef SWIG
# define VIPS_NAMESPACE_START namespace vips {
# define VIPS_NAMESPACE_END }
#endif /*SWIG*/

/* Don't include these when parsing for SWIG.
 */
#ifndef SWIG
# include <cstdarg>
# include <iosfwd>
#endif /*!SWIG*/

/* Wrap pointers to these, but we don't want to import all the old C API. Just 
 * declare them.
 */
extern "C" {
	struct im__INTMASK;
	struct im__DOUBLEMASK;
}

VIPS_NAMESPACE_START

/* This first section is private. Only expose the non-P versions of these
 * classes later on. Don't need to wrap then in SWIG either.
 */
#ifndef SWIG
namespace _private_detail { 

union MASKUNION {
       im__INTMASK *iptr;
       im__DOUBLEMASK *dptr;
}; 

// Private wrapper over *MASK - user does not see this
class VPMask {
	friend class VMask;

public:
	// Track type of mask with this
	enum VMaskType {
		UNASSIGNED,		// Not yet set
		INT,			// mask points to INTMASK
		DOUBLE			// mask points to DOUBLEMASK
	};

	MASKUNION data;			// Mask pointer - INT or DOUBLE
	VMaskType type;			// Track type too, for safety

	virtual ~VPMask() {};

	// Duplicate
	virtual VPMask *dup() const = 0;

	// Projection functions to get MASK fields
	virtual int xsize() const = 0;
	virtual int ysize() const = 0;
	virtual const char *filename() const = 0;

	// Output
	virtual void ostream_print( std::ostream & ) const = 0;
};

// Specialise for INTMASK
class VPIMask : public VPMask {
public:
	VPIMask( int xsize, int ysize ) throw( VError );
	VPIMask( int xsize, int ysize, int scale, int offset, va_list ap )
		throw( VError );
	VPIMask( const char * )
		throw( VError );
	VPIMask( im__INTMASK * );
	VPIMask();
	virtual ~VPIMask();

	VPMask *dup() const throw( VError );
	void embed( im__INTMASK * ) throw( VError );

	int xsize() const throw( VError );
	int ysize() const throw( VError );
	int scale() const throw( VError );
	int offset() const throw( VError );
	const char *filename() const throw( VError );

	// Output
	virtual void ostream_print( std::ostream & ) const throw( VError );

	// Extract start of array of ints
	int *array() const;
};

// Specialise for DOUBLEMASK
class VPDMask : public VPMask {
public:
	VPDMask( int xsize, int ysize ) throw( VError );
	VPDMask( int xsize, int ysize, 
		double scale, double offset, va_list ap ) throw( VError );
	VPDMask( const char * ) throw( VError );
	VPDMask( im__DOUBLEMASK * );
	VPDMask();
	virtual ~VPDMask();

	VPMask *dup() const throw( VError );
	void embed( im__DOUBLEMASK * ) throw( VError );

	int xsize() const throw( VError );
	int ysize() const throw( VError );
	double scale() const throw( VError );
	double offset() const throw( VError );
	const char *filename() const throw( VError );

	// Output
	virtual void ostream_print( std::ostream & ) const throw( VError );

	// Extract start of array of doubles
	double *array() const;
};

} // end of namespace _private_detail

inline std::ostream &operator<<( std::ostream &file, 
	const _private_detail::VPMask &msk )
{ 
	msk.ostream_print( file ); 
	return( file ); 
}

#endif /*!SWIG*/

// Wrapper over VP?Mask with ref counting
class VMask {
protected:
	struct refblock {
		_private_detail::VPMask *pmask;	// Mask: double or int
		int nrefs;		// Refs to us

		refblock() : pmask(0), nrefs(1) {}
		virtual ~refblock() { delete pmask; }
	};

	refblock *ref;

	// Make sure this is a private copy of pmask --- dup if nrefs != 1
	void make_private();

public:
	// Constructor leaves msk uninitialised
	VMask() { ref = new refblock; }

	// Copy constructor 
	VMask( const VMask &a ) { ref = a.ref; ref->nrefs++; }

	// Assignment
	VMask &operator=( const VMask &a );

	// Destructor
	virtual ~VMask();

	int xsize() const throw( VError ) 
		{ return( ref->pmask->xsize() ); }
	int ysize() const throw( VError ) 
		{ return( ref->pmask->ysize() ); }
	int size() const throw( VError ) 
		{ return( xsize() * ysize() ); }
	const char *filename() const throw( VError ) 
		{ return( ref->pmask->filename() ); }

	// Extract underlying type
	_private_detail::VPMask::VMaskType type() const 
		{ return( ref->pmask->type ); }

	// Extract underlying VIPS pointer
	_private_detail::MASKUNION mask() const { return( ref->pmask->data ); }

	void ostream_print( std::ostream & ) const;
};

inline std::ostream &operator<<( std::ostream &file, const VMask &msk )
{
	msk.ostream_print( file );
	return( file );
}

// Need to forward ref these
class VDMask;
class VImage;

// Wrapper over _private_detail::VPIMask with ref counting
class VIMask : public VMask {
public:
	VIMask( int xsize, int ysize )
	{
		ref->pmask = new _private_detail::VPIMask( xsize, ysize );
	}

	VIMask( int xsize, int ysize, int scale, int offset, ... )
	{
		va_list ap;

		va_start( ap, offset );
		ref->pmask = new _private_detail::VPIMask( xsize, ysize, 
			scale, offset, ap );
		va_end( ap );
	}

	VIMask( int xsize, int ysize, int scale, int offset, 
		std::vector<int> coeff )
	{
		ref->pmask = new _private_detail::VPIMask( xsize, ysize, 
			scale, offset, coeff );
	}

	VIMask( const char *name )
	{
		ref->pmask = new _private_detail::VPIMask( name );
	}

	// No mask there yet
	VIMask() {}

	int scale() 
	{ 
		return( ((_private_detail::VPIMask *)ref->pmask)->scale() ); 
	}
	
	int offset() 
	{ 
		return( ((_private_detail::VPIMask *)ref->pmask)->offset() ); 
	}

	// Embed INTMASK in VIMask
	void embed( im__INTMASK * ) throw( VError );

	// Overload [] to get linear array subscript.
	int &operator[]( int ) throw( VError );

	// Overload () to get matrix subscript.
	int &operator()( int x, int y ) throw( VError ) 
		{ return( (*this)[x + y*xsize()] ); }

	// and as a function call that SWIG can wrap
	int get( int i ) throw( VError ) 
		{ return( (*this)[i] ); }

	// Type conversion: INTMASK->DOUBLEMASK
	operator VDMask();

	// Type conversion: INTMASK->image
	operator VImage();

	// VIMask build functions
	static VIMask gauss( double, double ) throw( VError );
	static VIMask log( double, double ) throw( VError );

	// VIMask manipulation
	VIMask rotate45() throw( VError );
	VIMask rotate90() throw( VError );

	// Arithmetic ... cast to double, and use VDMask funcs. For some
	// reason, the compiler won't let us do casts to VDImage yet, so no
	// inlines.
	VDMask trn() throw( VError );
	VDMask inv() throw( VError );
	VDMask cat( VDMask ) throw( VError );
	VDMask mul( VDMask ) throw( VError );
};

// Wrapper over _private_detail::VPDMask with ref counting
class VDMask : public VMask {
public:
	VDMask( int xsize, int ysize )
	{
		ref->pmask = new _private_detail::VPDMask( xsize, ysize );
	}

	VDMask( int xsize, int ysize, double scale, double offset, ... )
	{
		va_list ap;

		va_start( ap, offset );
		ref->pmask = new _private_detail::VPDMask( xsize, ysize, 
			scale, offset, ap );
		va_end( ap );
	}

	VDMask( int xsize, int ysize, double scale, double offset, 
		std::vector<double> coeff )
	{
		ref->pmask = new _private_detail::VPDMask( xsize, ysize, 
			scale, offset, coeff );
	}

	VDMask( const char *name )
	{
		ref->pmask = new _private_detail::VPDMask( name );
	}

	// No mask yet
	VDMask() { }

	// Embed DOUBLEMASK in VDMask
	void embed( im__DOUBLEMASK * ) throw( VError );

	double scale() throw( VError )
	{ 
		return( ((_private_detail::VPDMask *)ref->pmask)->scale() ); 
	}

	double offset() throw( VError )
	{ 
		return( ((_private_detail::VPDMask *)ref->pmask)->offset() ); 
	}

	// Overload [] to get linear array subscript.
	double &operator[]( int ) throw( VError );

	// Overload () to get matrix subscript.
	double &operator()( int x, int y ) throw( VError )
		{ return( (*this)[x + y*xsize()] ); }

	// and as a function call that SWIG can wrap
	double get( int i ) throw( VError ) 
		{ return( (*this)[i] ); }

	// Type conversion: double->int
	operator VIMask();

	// Type conversion: DOUBLEMASK->image
	operator VImage() throw( VError );

	// VDMask build functions
	static VDMask gauss( double, double ) throw( VError );
	static VDMask log( double, double ) throw( VError );

	// VDMask manipulation
	VDMask rotate45() throw( VError );
	VDMask rotate90() throw( VError ); 

	// Scale to intmask
	VIMask scalei() throw( VError );

	// Simple arithmetic
	VDMask trn() throw( VError );
	VDMask inv() throw( VError );
	VDMask cat( VDMask ) throw( VError );
	VDMask mul( VDMask ) throw( VError );
};

VIPS_NAMESPACE_END

#endif /*IM_VMASK_H*/
