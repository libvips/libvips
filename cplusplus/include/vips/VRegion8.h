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
	/**
	 * Wrap a VRegion around an underlying VipsRegion object.
	 */
	VRegion( VipsRegion *region, VSteal steal = STEAL ) : 
		VObject( (VipsObject *) region, steal )
	{
	}

	bool
	prepare( const VipsRect *rect )
	{
		if ( vips_region_prepare( (VipsRegion *) this, rect ) != 0 )
			return( false );
		return( true );
	}

	bool
	prepare( int left, int top, int width, int height )
	{
		VipsRect rect;
		rect.left = left;
		rect.top = top;
		rect.width = width;
		rect.height = height;
		return( prepare( &rect ) );
	}

	T
	operator[]( size_t index ) const
	{
		return( (T*) VIPS_REGION_ADDR_TOPLEFT( (VipsRegion *) this )[index] );
	}

	std::vector<T>
	operator()( int x, int y ) const
	{
		return( std::vector<T>( VIPS_REGION_ADDR( (VipsRegion *) this, x, y ),
			VIPS_REGION_ADDR( (VipsRegion *) this, x, y ) +
				vips_image_get_bands( ( (VipsRegion *) this )->im ) ) );
	}

	VipsRect
	valid() const
	{
		return( ( (VipsRegion *) this )->valid );
	}
};

VIPS_NAMESPACE_END

#endif /*VIPS_VREGION_H*/
