colour_sources = files(
    'CMYK2XYZ.c',
    'colour.c',
    'colourspace.c',
    'dE00.c',
    'dE76.c',
    'dECMC.c',
    'float2rad.c',
    'HSV2sRGB.c',
    'icc_transform.c',
    'Lab2LabQ.c',
    'Lab2LabS.c',
    'Lab2LCh.c',
    'Lab2XYZ.c',
    'LabQ2Lab.c',
    'LabQ2LabS.c',
    'LabQ2sRGB.c',
    'LabS2Lab.c',
    'LabS2LabQ.c',
    'LCh2Lab.c',
    'LCh2UCS.c',
    'profile_load.c',
    'profiles.c',
    'rad2float.c',
    'scRGB2BW.c',
    'scRGB2sRGB.c',
    'scRGB2XYZ.c',
    'sRGB2HSV.c',
    'sRGB2scRGB.c',
    'UCS2LCh.c',
    'XYZ2CMYK.c',
    'XYZ2Lab.c',
    'XYZ2scRGB.c',
    'XYZ2Yxy.c',
    'Yxy2XYZ.c',
  )

colour_headers = files(
    'pcolour.h',
    'profiles.h',
)

libvips_sources += colour_sources

colour_lib = static_library('colour',
    colour_sources,
    colour_headers,
    dependencies: libvips_deps,
    gnu_symbol_visibility: 'hidden',
)

libvips_components += colour_lib
