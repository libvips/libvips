#!/usr/bin/env python3

import argparse
import xml.etree.ElementTree as ET
from pathlib import Path


def register_all_namespaces(filename):
    namespaces = dict([node for _, node in ET.iterparse(filename, events=['start-ns'])])
    for ns in namespaces:
        ET.register_namespace(ns, namespaces[ns])


def fixup_load_as_ctor(args):
    tree = ET.parse(args.in_path)
    root = tree.getroot()

    register_all_namespaces(args.in_path)
    namespace = {
        'goi': 'http://www.gtk.org/introspection/core/1.0'
    }

    namespace_node = root.find('goi:namespace', namespace)
    image_node = namespace_node.find('goi:class[@name="Image"]', namespace)

    # Ensure every *load* function is changed to an Image ctor
    for node in namespace_node.findall('goi:function', namespace):
        name = node.get('name')
        if 'load' in name:
            namespace_node.remove(node)

            node.tag = 'constructor'
            image_node.append(node)

    tree.write(args.out_path, encoding='utf-8', xml_declaration=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('in_path', help='input file', type=Path)
    parser.add_argument('out_path', help='output file', type=Path)

    args = parser.parse_args()
    fixup_load_as_ctor(args)


if __name__ == "__main__":
    main()
