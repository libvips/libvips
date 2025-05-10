#!/usr/bin/env python3

import argparse
import xml.etree.ElementTree as ET
from pathlib import Path


def register_all_namespaces(filename):
    namespaces = dict([node for _, node in ET.iterparse(filename, events=['start-ns'])])
    for ns in namespaces:
        ET.register_namespace(ns, namespaces[ns])


def fixup_gir_for_doc(args):
    tree = ET.parse(args.in_path)
    root = tree.getroot()

    register_all_namespaces(args.in_path)
    namespace = {
        'goi': 'http://www.gtk.org/introspection/core/1.0'
    }

    namespace_node = root.find('goi:namespace', namespace)
    image_node = namespace_node.find('goi:class[@name="Image"]', namespace)
    blob_node = namespace_node.find('goi:record[@name="Blob"]', namespace)

    # A list of functions that needs to be converted to an Image constructor.
    # Note that all functions containing "load" are already converted.
    image_ctors = [
        'black',
        'eye',
        'fractsurf',
        'gaussmat',
        'gaussnoise',
        'grey',
        'identity',
        'logmat',
        'mask_butterworth',
        'mask_butterworth_band',
        'mask_butterworth_ring',
        'mask_fractal',
        'mask_gaussian',
        'mask_gaussian_band',
        'mask_gaussian_ring',
        'mask_ideal',
        'mask_ideal_band',
        'mask_ideal_ring',
        'perlin',
        'sdf',
        'sines',
        'system',
        'text',
        'thumbnail',
        'thumbnail_buffer',
        'thumbnail_source',
        'tonelut',
        'worley',
        'xyz',
        'zone',
    ]

    # Functions that take multiple images as input argument ... make them
    # part of the Image class.
    # Keep-in-sync with gen-function-list.py
    image_funcs = [
        'arrayjoin',
        'bandjoin',
        'bandrank',
        'composite',
        'sum',
        'switch',
    ]

    for node in namespace_node.findall('goi:function', namespace):
        name = node.get('name')
        if name == 'profile_load':
            namespace_node.remove(node)

            node.tag = 'constructor'
            blob_node.append(node)
        elif 'load' in name or name in image_ctors:
            namespace_node.remove(node)

            node.tag = 'constructor'
            image_node.append(node)
        elif name in image_funcs:
            namespace_node.remove(node)
            image_node.append(node)

    tree.write(args.out_path, encoding='utf-8', xml_declaration=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('in_path', help='input file', type=Path)
    parser.add_argument('out_path', help='output file', type=Path)

    args = parser.parse_args()
    fixup_gir_for_doc(args)


if __name__ == '__main__':
    main()
