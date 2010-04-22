#!/usr/bin/python

from distutils.core import setup, Extension

module1 = Extension ('VImage', sources = ['vimagemodule.cxx'], include_dirs =
		['home/john/vips/include'])
module2 = Extension ('VMask', sources = ['vmaskmodule.cxx'], include_dirs =
		['home/john/vips/include'])
module3 = Extension ('VDisplay', sources = ['vdisplaymodule.cxx'],
		include_dirs = ['home/john/vips/include'])
module4 = Extension ('VError', sources = ['verrormodule.cxx'], include_dirs =
		['home/john/vips/include'])

setup (name = 'vips7',
	version = '7.21.3',
	description = 'vips-7.x image processing library',
	author = 'John Cupitt',
	author_email = 'jcupitt@gmail.com',
	url = 'http://www.vips.ecs.soton.ac.uk',
	ext_package = 'vips7',
	ext_modules = [module1, module2, module3, module4])

