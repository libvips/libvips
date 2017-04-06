#!/usr/bin/env ruby

require 'fileutils'
require 'nokogiri'
require 'vips'

if ARGV.length != 1 
    puts "usage: ./gen-api.rb vips-docs-directory"
	puts "\teg. ./gen-api.rb ~/vips/share/gtk-doc/html/libvips"
	exit 1
end

version = Vips::version(0).to_s + "." + Vips::version(1).to_s
out_dir = "API/#{version}"

puts "wiping #{out_dir} directory ..."
FileUtils.remove_entry_secure(out_dir, force = true)
FileUtils.mkdir(out_dir)

puts "loading template ..."
template = Nokogiri::HTML(File.open("_layouts/api-default.html"))

puts "copying formatted docs ..."
Dir.foreach(ARGV[0]) do |filename|
    next if filename[0] == "." 

    if File.extname(filename) == ".html"
        puts "processing #{filename} ..." 
        doc = Nokogiri::HTML(File.open(File.join(ARGV[0], filename)))

        template.at_css(".main-content").children = doc.at_css("body").children

        File.open(File.join(out_dir, filename), 'w') {|f| f << template.to_html}
    else
        puts "copying #{filename} ..." 
        FileUtils.copy(File.join(ARGV[0], filename), File.join(out_dir, filename))
    end
end


