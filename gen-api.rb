#!/usr/bin/env ruby

require 'fileutils'
require 'nokogiri'

if ARGV.length != 1 
    puts "usage: ./gen-api.rb vips-docs-directory"
	puts "\teg. ./gen-api.sh ~/vips/share/gtk-doc/html/libvips"
	exit 1
end

puts "wiping API directory ..."
FileUtils.remove_entry_secure("API", force = true)
FileUtils.mkdir("API")

puts "loading template ..."
template = Nokogiri::HTML(File.open("_layouts/api-default.html"))

puts "copying formatted docs ..."
Dir.foreach(ARGV[0]) do |filename|
    next if filename[0] == "." 

    if File.extname(filename) == ".html"
        puts "processing #{filename} ..." 
        doc = Nokogiri::HTML(File.open(File.join(ARGV[0], filename)))

        template.at_css(".main-content").children = doc.at_css("body").children

        File.open(File.join("API", filename), 'w') {|f| f << template.to_html}
    else
        puts "copying #{filename} ..." 
        FileUtils.copy(File.join(ARGV[0], filename), File.join("API", filename))
    end
end


