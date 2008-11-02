/* @(#) Function which returns a char pointer at the beginning of the file 
 * @(#) corresponding to fd.
 * @(#) 
 * @(#) int
 * @(#) im_mapfile( im )
 * @(#) IMAGE im;
 * @(#)
 * @(#) As above, but map read-write.
 * @(#) 
 * @(#) int
 * @(#) im_mapfilerw( im )
 * @(#) IMAGE im;
 * @(#)
 * @(#) Return -1 on error, 0 for success.
 * 
 * Copyright: Nicos Dessipris
 * Wriiten on: 13/02/1990
 * Updated on:
 * 10/5/93 J.Cupitt
 *	- im_mapfilerw() added
 * 13/12/94 JC
 *	- ANSIfied
 * 5/7/99 JC
 *	- better error if unable to map rw
 * 31/3/02 JC
 *	- better mmap() fails error
 * 19/9/02 JC
 * 	- added im__mmap()/im__munmap() with windows versions
 * 5/1/04 Lev Serebryakov
 * 	- patched for freebsd compatibility
 * 5/2/04 JC
 *	- now records length as well as base, so we unmap the right amount of
 *	  memory even if files change behind our back
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
#include <errno.h>
#include <assert.h>

#include <sys/types.h>
#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif /*HAVE_SYS_MMAN_H*/
#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>
#endif /*HAVE_SYS_FILE_H*/
#include <sys/stat.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /*HAVE_UNISTD_H*/
#ifdef OS_WIN32 
#ifndef S_ISREG
#define S_ISREG(m) (!!(m & _S_IFREG))
#endif
#endif /*OS_WIN32*/

#include <vips/vips.h>

#ifdef OS_WIN32
#include <windows.h>
#endif /*OS_WIN32*/

#ifdef WITH_DMALLOC
#include <dmalloc.h>
#endif /*WITH_DMALLOC*/

void *
im__mmap( int fd, int writeable, size_t length, gint64 offset )
{
	void *baseaddr;

#ifdef DEBUG
	printf( "im__mmap: length = %d, offset = %lld\n", length, offset );
#endif /*DEBUG*/

#ifdef OS_WIN32
{
	HANDLE hFile = (HANDLE) _get_osfhandle( fd );
        HANDLE hMMFile;
	DWORD flProtect;
	DWORD dwDesiredAccess;
	DWORD dwFileOffsetHigh;
	DWORD dwFileOffsetLow;

	/* woah, slightly gross
	 */
	int dws = sizeof( DWORD );
	int shift = 8 * dws;
	gint64 mask = ((gint64) -1) >> shift;

	if( writeable ) {
		flProtect = PAGE_READWRITE;
		dwDesiredAccess = FILE_MAP_WRITE;
	}
	else {
		flProtect = PAGE_READONLY;
		dwDesiredAccess = FILE_MAP_READ;
	}

        if( !(hMMFile = CreateFileMapping( hFile,
		NULL, flProtect, 0, 0, NULL )) ) {
                im_error_system( GetLastError(), "im_mapfile", 
			"%s", _( "unable to CreateFileMapping" ) );
                return( NULL );
        }

	dwFileOffsetHigh = (offset >> shift) & mask;
	dwFileOffsetLow = offset & mask;

        if( !(baseaddr = (char *)MapViewOfFile( hMMFile, dwDesiredAccess, 
		dwFileOffsetHigh, dwFileOffsetLow, length )) ) {
                im_error_system( GetLastError(), "im_mapfile",
			"%s", _( "unable to MapViewOfFile" ) );
		CloseHandle( hMMFile );
                return( NULL );
        }

	/* Can close mapping now ... view stays until UnmapViewOfFile().

		FIXME ... is this a performance problem?

	 */
	CloseHandle( hMMFile );
}
#else /*!OS_WIN32*/
{
	int prot;

	if( writeable ) 
		prot = PROT_WRITE;
	else 
		prot = PROT_READ;

	/* Casting gint64 to off_t should be safe, even on *nixes without
	 * LARGEFILE.
	 */

	baseaddr = mmap( 0, length, prot, MAP_SHARED, fd, (off_t) offset );
	if( baseaddr == MAP_FAILED ) { 
		im_error_system( errno, "im_mapfile", 
			"%s", _( "unable to mmap" ) );
		im_warn( "im_mapfile", _( "map failed (%s), "
			"running very low on system resources, "
			"expect a crash soon" ), strerror( errno ) );
		return( NULL ); 
	}
}
#endif /*OS_WIN32*/

	return( baseaddr );
}

int
im__munmap( void *start, size_t length )
{
#ifdef OS_WIN32
	if( !UnmapViewOfFile( start ) ) {
		im_error_system( GetLastError(), "im_mapfile",
			"%s", _( "unable to UnmapViewOfFile" ) );
		return( -1 );
	}
#else /*!OS_WIN32*/
	if( munmap( start, length ) < 0 ) {
		im_error_system( errno, "im_mapfile", 
			"%s", _( "unable to munmap file" ) );
		return( -1 );
	}
#endif /*OS_WIN32*/

	return( 0 );
}

int
im_mapfile( IMAGE *im )
{
	gint64 length;
	struct stat st;
	mode_t m;

	assert( !im->baseaddr );

	/* Check the size of the file; if it is less than 64 bytes, then flag
	 * an error.
	 */
	if( (length = im_file_length( im->fd )) == -1 ) 
		return( -1 );
	if( fstat( im->fd, &st ) == -1 ) {
		im_error( "im_mapfile", 
			"%s", _( "unable to get file status" ) );
		return( -1 );
	}
	m = (mode_t) st.st_mode;
	if( length < 64 ) {
		im_error( "im_mapfile", 
			"%s", _( "file is less than 64 bytes" ) );
		return( -1 ); 
	}
	if( !S_ISREG( m ) ) {
		im_error( "im_mapfile", 
			"%s", _( "not a regular file" ) ); 
		return( -1 ); 
	}

	if( !(im->baseaddr = im__mmap( im->fd, 0, length, 0 )) )
		return( -1 );

	/* im__mmap() will fail for >2GB, so this is safe even for large
	 * files.
	 */
	im->length = length;

	return( 0 );
}

/* As above, but map read/write.
 */
int
im_mapfilerw( IMAGE *im )
{
	gint64 length;
	struct stat st;
	mode_t m;

	assert( !im->baseaddr );

	/* Check the size of the file if it is less than 64 bytes return
	 * make also sure that it is a regular file
	 */
	if( (length = im_file_length( im->fd )) == -1 ) 
		return( -1 );
	if( fstat( im->fd, &st ) == -1 ) {
		im_error( "im_mapfilerw", 
			"%s", _( "unable to get file status" ) );
		return( -1 );
	}
	m = (mode_t) st.st_mode;
	if( length < 64 || !S_ISREG( m ) ) {
		im_error( "im_mapfile", 
			"%s", _( "unable to read data" ) ); 
		return( -1 ); 
	}

	if( !(im->baseaddr = im__mmap( im->fd, 1, length, 0 )) )
		return( -1 );

	/* im__mmap() will fail for >2GB, so this is safe even for large
	 * files.
	 */
	im->length = length;

	return( 0 );
}

/* From im_rwcheck() ... image needs to be a completely mapped read-only file, 
 * we try to remap it read-write. 
 */
int
im_remapfilerw( IMAGE *image )
{
	void *baseaddr;

#ifdef OS_WIN32
{
	HANDLE hFile = (HANDLE) _get_osfhandle( image->fd );
        HANDLE hMMFile;

        if( !(hMMFile = CreateFileMapping( hFile,
		NULL, PAGE_READWRITE, 0, 0, NULL )) ) {
                im_error_system( GetLastError(), "im_mapfile", 
			"%s", _( "unable to CreateFileMapping" ) );
                return( -1 );
        }

	if( !UnmapViewOfFile( image->baseaddr ) ) {
		im_error_system( GetLastError(), "im_mapfile", 
			"%s", _( "unable to UnmapViewOfFile" ) );
		return( -1 );
	}
        if( !(baseaddr = (char *)MapViewOfFileEx( hMMFile, FILE_MAP_WRITE, 
		0, 0, 0, image->baseaddr )) ) {
                im_error_system( GetLastError(), "im_mapfile",
			"%s", _( "unable to MapViewOfFile" ) );
		CloseHandle( hMMFile );
                return( -1 );
        }

	/* Can close mapping now ... view stays until UnmapViewOfFile().

		FIXME ... is this a performance problem?

	 */
	CloseHandle( hMMFile );
}
#else /*!OS_WIN32*/
{
	assert( image->dtype == IM_MMAPIN );

	baseaddr = mmap( image->baseaddr, image->length,
		PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, 
		image->fd, 0 );
	if( baseaddr == (void *)-1 ) { 
		im_error( "im_mapfile", _( "unable to mmap: \"%s\" - %s" ),
			image->filename, strerror( errno ) );
		return( -1 ); 
	}
}
#endif /*OS_WIN32*/

	image->dtype = IM_MMAPINRW;

	if( baseaddr != image->baseaddr ) {
		im_error( "im_mapfile", _( "unable to mmap \"%s\" to same "
			"address" ), image->filename );
		image->baseaddr = baseaddr;
		return( -1 ); 
	}

	return( 0 );
}

