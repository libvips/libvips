colour_sources = files(
    'profiles.c',
    'profile_load.c',
    'colour.c',
    'CMYK2XYZ.c',
    'XYZ2CMYK.c',
    'colourspace.c',
    'dE76.c',
    'dE00.c',
    'dECMC.c',
    'icc_transform.c',
    'Lab2XYZ.c',
    'Lab2LCh.c',
    'LCh2Lab.c',
    'LCh2UCS.c',
    'UCS2LCh.c',
    'XYZ2Lab.c',
    'XYZ2Yxy.c',
    'Yxy2XYZ.c',
    'float2rad.c',
    'rad2float.c',
    'Lab2LabQ.c',
    'LabQ2Lab.c',
    'LabS2Lab.c',
    'Lab2LabS.c',
    'LabS2LabQ.c',
    'LabQ2LabS.c',
    'LabQ2sRGB.c',
    'sRGB2scRGB.c',
    'sRGB2HSV.c',
    'HSV2sRGB.c',
    'scRGB2XYZ.c',
    'scRGB2BW.c',
    'XYZ2scRGB.c',
    'scRGB2sRGB.c',
)

colour_headers = files(
    'profiles.h',
    'pcolour.h',
)

libvips_sources += colour_sources

colour_lib = static_library('colour',
    colour_sources,
    colour_headers,
    dependencies: libvips_deps,
    gnu_symbol_visibility: 'hidden',
)

libvips_components += colour_lib
