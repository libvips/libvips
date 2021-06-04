#!/usr/bin/ruby

require 'fileutils'
require 'nokogiri'
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

def copy_html source, destination, template
    puts "loading template ..."
    template = Nokogiri::HTML(File.open("_layouts/#{template}"))
    FileUtils.mkdir(destination)

    Dir.foreach(source) do |filename|
        next if filename[0] == "." || filename[0] == ".." 

        if File.extname(filename) == ".html"
            puts "processing #{filename} ..." 
            doc = Nokogiri::HTML(File.open("#{source}/#{filename}"))

            template.at_css(".main-content").children = 
                doc.at_css("body").children

            File.open("#{destination}/#{filename}", 'w') do |f| 
                f << template.to_html
            end
        else
            puts "copying #{filename} ..." 
            FileUtils.cp_r("#{source}/#{filename}", 
                           "#{destination}/#{filename}")
        end
    end
end

copy_html "#{ARGV[0]}/share/gtk-doc/html/libvips", 
    "API/#{version}", "api-default.html"

if File.directory? "#{ARGV[0]}/share/doc/vips/html"
    copy_html "#{ARGV[0]}/share/doc/vips/html",
        "API/#{version}/cpp", "cpp-default.html"
end

