#!/usr/bin/env python3

import sys
import argparse
import xml.etree.ElementTree as ET
from pathlib import Path


def register_all_namespaces(filename):
    namespaces = dict([node for _, node in ET.iterparse(filename, events=['start-ns'])])
    for ns in namespaces:
        ET.register_namespace(ns, namespaces[ns])


def check_sections(args):
    tree = ET.parse(args.gir)
    root = tree.getroot()

    register_all_namespaces(args.gir)
    namespace = {
        'goi': 'http://www.gtk.org/introspection/core/1.0',
        'glib': 'http://www.gtk.org/introspection/glib/1.0',
    }

    namespace_node = root.find('goi:namespace', namespace)

    file_dict = {}
    for file in args.files:
        content = Path(file).read_text()
        comment_start_idx = content.find('<!-- ')
        if comment_start_idx == -1:
            print(f'ERROR: File {file} does not contain a HTML comment',
                  file=sys.stderr)
            sys.exit(1)

        comment_end_idx = content.find(' -->', comment_start_idx)
        section_covers = content[comment_start_idx + 5:comment_end_idx]

        file_dict[section_covers] = {'file': file, 'content': content}

    tag_parser_dict = {
        f'{{{namespace['goi']}}}alias': lambda n, _ : f'[alias@{n.attrib['name']}]',
        f'{{{namespace['goi']}}}bitfield': lambda n, _ : f'[flags@{n.attrib['name']}]',
        f'{{{namespace['goi']}}}callback': lambda n, _ : f'[callback@{n.attrib['name']}]',
        f'{{{namespace['goi']}}}class': lambda n, _ : f'[class@{n.attrib['name']}]',
        f'{{{namespace['goi']}}}constructor': lambda n, p : f'[ctor@{p}{n.attrib['name']}]',
        f'{{{namespace['goi']}}}method': lambda n, p : f'[method@{p}{n.attrib['name']}]',
        f'{{{namespace['goi']}}}constant': lambda n, _ : f'[const@{n.attrib['name']}]',
        f'{{{namespace['goi']}}}enumeration': lambda n, _ : f'[enum@{n.attrib['name']}]',
        f'{{{namespace['goi']}}}function-macro': lambda n, _ : f'[func@{n.attrib['name']}]',
        f'{{{namespace['goi']}}}function': lambda n, p : f'[func@{p}{n.attrib['name']}]',
        # each struct has its own documentation
        # f'{{{namespace['goi']}}}record': lambda n, _ : f'[struct@{n.attrib['name']}]',
        # struct and enum members do not need to be listed
        # f'{{{namespace['goi']}}}field': lambda n, p : f'[struct@Vips.{p}{n.attrib['name']}]',
        # f'{{{namespace['goi']}}}member': lambda n, p : f'[enum@Vips.{p}{n.attrib['name']}]',
    }

    exitcode = 0

    parent_map = {c: p for p in namespace_node.iter() for c in p}
    for node in parent_map:
        if 'moved-to' in node.attrib:
            continue

        child = node.find('goi:doc', namespace)
        if child is None:
            continue

        filename = child.attrib['filename']
        section = next((k for k in file_dict.keys() if filename.startswith(k)), None)
        if section is None:
            continue

        parser_method = tag_parser_dict.get(node.tag, None)
        if parser_method is None:
            continue

        parent_name = parent_map.get(node, {}).attrib.get('name') or ''
        if parent_name == 'Vips':
            parent_name = ''
        if parent_name:
            parent_name += '.'

        symbol = parser_method(node, parent_name)
        if f'* {symbol}' not in file_dict[section]['content']:
            print(f"ERROR: Symbol '{symbol}' is not listed in '{file_dict[section]['file']}'",
                  file=sys.stderr)
            exitcode = 1

    sys.exit(exitcode)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--gir', help='input GIR file', type=Path)
    parser.add_argument('files', help='markdown files', type=Path, nargs=argparse.REMAINDER)

    args = parser.parse_args()
    check_sections(args)


if __name__ == '__main__':
    main()
