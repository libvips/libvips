#!/usr/bin/python

import sys

import gi
gi.require_version('Vips', '8.0')
from gi.repository import GLib, Vips 

context = GLib.OptionContext(" - test python stuff")
main_group = GLib.OptionGroup("main", 
                              "Main options", "Main options for this program", 
                              None)
context.set_main_group(main_group)
Vips.add_option_entries(main_group)
context.parse(sys.argv)


