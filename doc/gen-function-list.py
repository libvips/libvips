#!/usr/bin/python

# walk vips and generate a list of all operators and their descriptions 
# for docs

# sample output:

# <row>
#   <entry>gamma</entry>
#   <entry>gamma an image</entry>
#   <entry>vips_gamma()</entry>
# </row>

from gi.repository import Vips, GObject

vips_type_operation = GObject.GType.from_name("VipsOperation")

def gen_function(cls):
    op = Vips.Operation.new(cls.name)
    gtype = Vips.type_find("VipsOperation", cls.name)
    nickname = Vips.nickname_find(gtype)

    print '<row>'
    print '  <entry>%s</entry>' % nickname
    print '  <entry>%s</entry>' % op.get_description()
    print '  <entry>vips_%s()</entry>' % nickname
    print '</row>'

# we have a few synonyms ... don't generate twice
generated = {}

def gen_function_list(cls):
    if not cls.is_abstract():
        gtype = Vips.type_find("VipsOperation", cls.name)
        nickname = Vips.nickname_find(gtype)
        if not nickname in generated:
            gen_function(cls)
            generated[nickname] = True

    if len(cls.children) > 0:
        for child in cls.children:
            gen_function_list(child)

if __name__ == '__main__':
    gen_function_list(vips_type_operation)

