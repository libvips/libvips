#!/usr/bin/ruby

require 'fileutils'
require 'vips'

if ARGV.length != 1
    puts "usage: ./gen-api.rb vips-install-prefix"
    puts "\teg. ./gen-api.rb ~/vips"
    exit 1
end

version = Vips::version(0).to_s + "." + Vips::version(1).to_s
out_dir = "API/#{version}"

puts "wiping #{out_dir} directory ..."
FileUtils.remove_entry_secure(out_dir, force = true)

puts "copying GI-DocGen output ..."
FileUtils.cp_r "#{ARGV[0]}/share/doc/vips", "API/#{version}"

if File.directory? "#{ARGV[0]}/share/doc/vips-doc/html"
    puts "copying Doxygen output ..."
    FileUtils.cp_r "#{ARGV[0]}/share/doc/vips-doc/html", "API/#{version}/cpp"
end
