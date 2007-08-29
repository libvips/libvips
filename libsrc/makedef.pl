#!/usr/bin/perl

# update vips.def from "nm" output of the installed library
# 
# not very portable :-( eg mac os x and win32 will fail horribly
# 
# pass in the install prefix ... or type "make vips.def"

open DATA, "nm -B @ARGV[0]/lib/libvips.so |";

while( <DATA> ) {
	next if ! /^[a-f0-9]+ T (im_[a-zA-Z].*)$/ && 
		! /^[a-f0-9]+ T (error_exit)$/;
	push @names, $1;
}

print "EXPORTS\n";
foreach $i (sort @names) {
	print "\t$i\n";
}
