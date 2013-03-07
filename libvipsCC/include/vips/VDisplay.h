/* VIPS display class.
 *
 * Hide details of im_col_display API.
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

#ifndef IM_VDISPLAY_H
#define IM_VDISPLAY_H

/* SWIG includes this file directly rather than going through vipscpp.h ... so
 * we have to define these macros here as well.
 */
#ifdef SWIG
#define VIPS_NAMESPACE_START namespace vips {
#define VIPS_NAMESPACE_END }
#endif /*SWIG*/

/* Wrap pointers to these, but we don't want to import all the old C API. Just 
 * declare them.
 */
extern "C" {
	struct im_col_display;
	struct im_col_tab_disp;
}

VIPS_NAMESPACE_START

// Wrapper over im_col_display with ref counting
class VDisplay {
	struct refblock {
		im_col_display *disp;	// im_col_display struct
		im_col_tab_disp *luts;	// luts built from this display
		int priv;		// disp is ours, or system
		int nrefs;		// Refs to us

		// Invalidate lut
		void cleanlut();

		// Break attached stuff
		void cleanref();

		// Get ready to write
		void wready() throw( VError );

		// Check that luts are up-to-date
		void cluts() throw( VError );

		refblock() : disp(0), luts(0), priv(0), nrefs(1) {}
		~refblock() { cleanref(); }
	};

	refblock *ref;

public:
	enum VDisplayType {
		BARCO,			// Does many corrections for us
		DUMB			// Needs many corrections
	};

	// Get named display
	VDisplay( const char *name ) throw( VError );

	// Get default display
	VDisplay();

	// Copy constructor 
	VDisplay( const VDisplay &a ) { ref = a.ref; ref->nrefs++; }

	// Assignment
	VDisplay &operator=( const VDisplay &a );

	// Destructor
	virtual ~VDisplay();

	// The matrix type we use
	typedef float matrix[3][3];

	// Extract display pointer
	void *disp() const { return( ref->disp ); }

	// Extract luts pointer, rebuilding luts if necessary
	im_col_tab_disp *luts() const throw( VError ) 
		{ ref->cluts(); return( ref->luts ); }
};

VIPS_NAMESPACE_END

#endif /*IM_VDISPLAY_H*/
