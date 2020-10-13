// VIPS region wrapper

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

#ifndef VIPS_VREGION_H
#define VIPS_VREGION_H

#include <vips/vips.h>

VIPS_NAMESPACE_START

template <typename T>
class VRegion : public VObject
{
public:
	VRegion( VImage &vimage ) :
		vimage{ &vimage }
	{
	}

	bool
	load( int left, int top, int width, int height )
	{
		VipsRect rect;
		rect.left = left;
		rect.top = top;
		rect.width = width;
		rect.height = height;
		region = vips_region_new( vimage->get_image() );
		if ( vips_region_prepare( region, &rect ) != 0 )
			return( false );
		region_addr = reinterpret_cast<T*>( VIPS_REGION_ADDR_TOPLEFT( region ) );
		return( true );
	}

	T
	operator[]( size_t index ) const
	{
		return( region_addr[index] );
	}

	std::vector<T>
	operator()( int x, int y ) const
	{
		return( std::vector<T>( VIPS_REGION_ADDR( region, x, y ),
			VIPS_REGION_ADDR( region, x, y ) + vimage->bands() ) );
	}

	VipsRect
	valid() const
	{
		return( region->valid );
	}

	VImage*
	get_vimage() const
	{
		return( vimage );
	}

private:
	VImage *vimage;
	VipsRegion *region;
	T *region_addr;

};

VIPS_NAMESPACE_END

#endif /*VIPS_VREGION_H*/
