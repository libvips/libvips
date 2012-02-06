
// headers for package arithmetic
// this file automatically generated from
// VIPS library 7.28.0-Tue Jan 31 10:51:45 GMT 2012
VImage abs() throw( VError );
VImage acos() throw( VError );
VImage add( VImage add_in2 ) throw( VError );
VImage asin() throw( VError );
VImage atan() throw( VError );
double avg() throw( VError );
double point_bilinear( double point_bilinear_x, double point_bilinear_y, int point_bilinear_band ) throw( VError );
VImage bandmean() throw( VError );
VImage ceil() throw( VError );
VImage cos() throw( VError );
VImage cross_phase( VImage cross_phase_in2 ) throw( VError );
double deviate() throw( VError );
VImage divide( VImage divide_in2 ) throw( VError );
VImage exp10() throw( VError );
VImage expn( double expn_x ) throw( VError );
VImage expn( std::vector<double> expn_v ) throw( VError );
VImage exp() throw( VError );
VImage floor() throw( VError );
VImage invert() throw( VError );
VImage lin( double lin_a, double lin_b ) throw( VError );
static VImage linreg( std::vector<VImage> linreg_ins, std::vector<double> linreg_xs ) throw( VError );
VImage lin( std::vector<double> lin_a, std::vector<double> lin_b ) throw( VError );
VImage log10() throw( VError );
VImage log() throw( VError );
double max() throw( VError );
std::complex<double> maxpos() throw( VError );
double maxpos_avg( double& maxpos_avg_y, double& maxpos_avg_out ) throw( VError );
VDMask measure( int measure_x, int measure_y, int measure_w, int measure_h, int measure_h_patches, int measure_v_patches ) throw( VError );
double min() throw( VError );
std::complex<double> minpos() throw( VError );
VImage multiply( VImage multiply_in2 ) throw( VError );
VImage pow( double pow_x ) throw( VError );
VImage pow( std::vector<double> pow_v ) throw( VError );
VImage recomb( VDMask recomb_matrix ) throw( VError );
VImage remainder( VImage remainder_in2 ) throw( VError );
VImage remainder( double remainder_x ) throw( VError );
VImage remainder( std::vector<double> remainder_x ) throw( VError );
VImage rint() throw( VError );
VImage sign() throw( VError );
VImage sin() throw( VError );
VDMask stats() throw( VError );
VImage subtract( VImage subtract_in2 ) throw( VError );
VImage tan() throw( VError );

// headers for package cimg
// this file automatically generated from
// VIPS library 7.28.0-Tue Jan 31 10:51:45 GMT 2012
VImage greyc( int greyc_iterations, double greyc_amplitude, double greyc_sharpness, double greyc_anisotropy, double greyc_alpha, double greyc_sigma, double greyc_dl, double greyc_da, double greyc_gauss_prec, int greyc_interpolation, int greyc_fast_approx ) throw( VError );
VImage greyc_mask( VImage greyc_mask_mask, int greyc_mask_iterations, double greyc_mask_amplitude, double greyc_mask_sharpness, double greyc_mask_anisotropy, double greyc_mask_alpha, double greyc_mask_sigma, double greyc_mask_dl, double greyc_mask_da, double greyc_mask_gauss_prec, int greyc_mask_interpolation, int greyc_mask_fast_approx ) throw( VError );

// headers for package colour
// this file automatically generated from
// VIPS library 7.28.0-Tue Jan 31 10:51:45 GMT 2012
VImage LCh2Lab() throw( VError );
VImage LCh2UCS() throw( VError );
VImage Lab2LCh() throw( VError );
VImage Lab2LabQ() throw( VError );
VImage Lab2LabS() throw( VError );
VImage Lab2UCS() throw( VError );
VImage Lab2XYZ() throw( VError );
VImage Lab2XYZ_temp( double Lab2XYZ_temp_X0, double Lab2XYZ_temp_Y0, double Lab2XYZ_temp_Z0 ) throw( VError );
VImage Lab2disp( VDisplay Lab2disp_disp ) throw( VError );
VImage LabQ2LabS() throw( VError );
VImage LabQ2Lab() throw( VError );
VImage LabQ2XYZ() throw( VError );
VImage LabQ2disp( VDisplay LabQ2disp_disp ) throw( VError );
VImage LabS2LabQ() throw( VError );
VImage LabS2Lab() throw( VError );
VImage UCS2LCh() throw( VError );
VImage UCS2Lab() throw( VError );
VImage UCS2XYZ() throw( VError );
VImage XYZ2Lab() throw( VError );
VImage XYZ2Lab_temp( double XYZ2Lab_temp_X0, double XYZ2Lab_temp_Y0, double XYZ2Lab_temp_Z0 ) throw( VError );
VImage XYZ2UCS() throw( VError );
VImage XYZ2Yxy() throw( VError );
VImage XYZ2disp( VDisplay XYZ2disp_disp ) throw( VError );
VImage XYZ2sRGB() throw( VError );
VImage Yxy2XYZ() throw( VError );
VImage dE00_fromLab( VImage dE00_fromLab_in2 ) throw( VError );
VImage dECMC_fromLab( VImage dECMC_fromLab_in2 ) throw( VError );
VImage dECMC_fromdisp( VImage dECMC_fromdisp_in2, VDisplay dECMC_fromdisp_disp ) throw( VError );
VImage dE_fromLab( VImage dE_fromLab_in2 ) throw( VError );
VImage dE_fromXYZ( VImage dE_fromXYZ_in2 ) throw( VError );
VImage dE_fromdisp( VImage dE_fromdisp_in2, VDisplay dE_fromdisp_disp ) throw( VError );
VImage disp2Lab( VDisplay disp2Lab_disp ) throw( VError );
VImage disp2XYZ( VDisplay disp2XYZ_disp ) throw( VError );
VImage float2rad() throw( VError );
VImage argb2rgba() throw( VError );
VImage icc_ac2rc( char* icc_ac2rc_profile ) throw( VError );
VImage icc_export_depth( int icc_export_depth_depth, char* icc_export_depth_output_profile, int icc_export_depth_intent ) throw( VError );
VImage icc_import( char* icc_import_input_profile, int icc_import_intent ) throw( VError );
VImage icc_import_embedded( int icc_import_embedded_intent ) throw( VError );
VImage icc_transform( char* icc_transform_input_profile, char* icc_transform_output_profile, int icc_transform_intent ) throw( VError );
VImage lab_morph( VDMask lab_morph_greyscale, double lab_morph_L_offset, double lab_morph_L_scale, double lab_morph_a_scale, double lab_morph_b_scale ) throw( VError );
VImage rad2float() throw( VError );
VImage sRGB2XYZ() throw( VError );

// headers for package conversion
// this file automatically generated from
// VIPS library 7.28.0-Tue Jan 31 10:51:45 GMT 2012
static VImage gaussnoise( int gaussnoise_xsize, int gaussnoise_ysize, double gaussnoise_mean, double gaussnoise_sigma ) throw( VError );
VImage bandjoin( VImage bandjoin_in2 ) throw( VError );
static VImage black( int black_x_size, int black_y_size, int black_bands ) throw( VError );
VImage c2amph() throw( VError );
VImage c2imag() throw( VError );
VImage c2real() throw( VError );
VImage c2rect() throw( VError );
VImage clip2fmt( int clip2fmt_ofmt ) throw( VError );
VImage copy() throw( VError );
VImage copy_file() throw( VError );
VImage copy_morph( int copy_morph_Bands, int copy_morph_BandFmt, int copy_morph_Coding ) throw( VError );
VImage copy_swap() throw( VError );
VImage copy_set( int copy_set_Type, double copy_set_Xres, double copy_set_Yres, int copy_set_Xoffset, int copy_set_Yoffset ) throw( VError );
VImage extract_area( int extract_area_left, int extract_area_top, int extract_area_width, int extract_area_height ) throw( VError );
VImage extract_areabands( int extract_areabands_left, int extract_areabands_top, int extract_areabands_width, int extract_areabands_height, int extract_areabands_band, int extract_areabands_nbands ) throw( VError );
VImage extract_band( int extract_band_band ) throw( VError );
VImage extract_bands( int extract_bands_band, int extract_bands_nbands ) throw( VError );
VImage extract( int extract_left, int extract_top, int extract_width, int extract_height, int extract_band ) throw( VError );
VImage falsecolour() throw( VError );
VImage fliphor() throw( VError );
VImage flipver() throw( VError );
static VImage gbandjoin( std::vector<VImage> gbandjoin_in ) throw( VError );
VImage grid( int grid_tile_height, int grid_across, int grid_down ) throw( VError );
VImage insert( VImage insert_sub, int insert_x, int insert_y ) throw( VError );
VImage insert( VImage insert_sub, std::vector<int> insert_x, std::vector<int> insert_y ) throw( VError );
VImage insert_noexpand( VImage insert_noexpand_sub, int insert_noexpand_x, int insert_noexpand_y ) throw( VError );
VImage embed( int embed_type, int embed_x, int embed_y, int embed_width, int embed_height ) throw( VError );
VImage lrjoin( VImage lrjoin_in2 ) throw( VError );
VImage msb() throw( VError );
VImage msb_band( int msb_band_band ) throw( VError );
VImage replicate( int replicate_across, int replicate_down ) throw( VError );
VImage ri2c( VImage ri2c_in2 ) throw( VError );
VImage rot180() throw( VError );
VImage rot270() throw( VError );
VImage rot90() throw( VError );
VImage scale() throw( VError );
VImage scaleps() throw( VError );
VImage subsample( int subsample_xshrink, int subsample_yshrink ) throw( VError );
char* system( char* system_command ) throw( VError );
VImage system_image( char* system_image_in_format, char* system_image_out_format, char* system_image_command, char*& system_image_log ) throw( VError );
VImage tbjoin( VImage tbjoin_in2 ) throw( VError );
static VImage text( char* text_text, char* text_font, int text_width, int text_alignment, int text_dpi ) throw( VError );
VImage wrap( int wrap_x, int wrap_y ) throw( VError );
VImage zoom( int zoom_xfac, int zoom_yfac ) throw( VError );

// headers for package convolution
// this file automatically generated from
// VIPS library 7.28.0-Tue Jan 31 10:51:45 GMT 2012
VImage aconvsep( VDMask aconvsep_matrix, int aconvsep_n_layers ) throw( VError );
VImage aconv( VDMask aconv_matrix, int aconv_n_layers, int aconv_cluster ) throw( VError );
VImage addgnoise( double addgnoise_sigma ) throw( VError );
VImage compass( VIMask compass_matrix ) throw( VError );
VImage contrast_surface( int contrast_surface_half_win_size, int contrast_surface_spacing ) throw( VError );
VImage conv( VIMask conv_matrix ) throw( VError );
VImage conv( VDMask conv_matrix ) throw( VError );
VImage convsep( VIMask convsep_matrix ) throw( VError );
VImage convsep( VDMask convsep_matrix ) throw( VError );
VImage fastcor( VImage fastcor_in2 ) throw( VError );
VImage gradcor( VImage gradcor_in2 ) throw( VError );
VImage gradient( VIMask gradient_matrix ) throw( VError );
VImage grad_x() throw( VError );
VImage grad_y() throw( VError );
VImage lindetect( VIMask lindetect_matrix ) throw( VError );
VImage sharpen( int sharpen_mask_size, double sharpen_x1, double sharpen_y2, double sharpen_y3, double sharpen_m1, double sharpen_m2 ) throw( VError );
VImage spcor( VImage spcor_in2 ) throw( VError );

// headers for package deprecated
// this file automatically generated from
// VIPS library 7.28.0-Tue Jan 31 10:51:45 GMT 2012
VImage flood_copy( int flood_copy_start_x, int flood_copy_start_y, std::vector<double> flood_copy_ink ) throw( VError );
VImage flood_blob_copy( int flood_blob_copy_start_x, int flood_blob_copy_start_y, std::vector<double> flood_blob_copy_ink ) throw( VError );
VImage flood_other_copy( VImage flood_other_copy_mark, int flood_other_copy_start_x, int flood_other_copy_start_y, int flood_other_copy_serial ) throw( VError );
VImage clip() throw( VError );
VImage c2ps() throw( VError );
VImage resize_linear( int resize_linear_X, int resize_linear_Y ) throw( VError );
VImage cmulnorm( VImage cmulnorm_in2 ) throw( VError );
VImage fav4( VImage fav4_in2, VImage fav4_in3, VImage fav4_in4 ) throw( VError );
VImage gadd( double gadd_a, double gadd_b, VImage gadd_in2, double gadd_c ) throw( VError );
VImage icc_export( char* icc_export_output_profile, int icc_export_intent ) throw( VError );
VImage litecor( VImage litecor_white, int litecor_clip, double litecor_factor ) throw( VError );
VImage affine( double affine_a, double affine_b, double affine_c, double affine_d, double affine_dx, double affine_dy, int affine_x, int affine_y, int affine_w, int affine_h ) throw( VError );
VImage clip2c() throw( VError );
VImage clip2cm() throw( VError );
VImage clip2d() throw( VError );
VImage clip2dcm() throw( VError );
VImage clip2f() throw( VError );
VImage clip2i() throw( VError );
VImage convsub( VIMask convsub_matrix, int convsub_xskip, int convsub_yskip ) throw( VError );
VImage convf( VDMask convf_matrix ) throw( VError );
VImage convsepf( VDMask convsepf_matrix ) throw( VError );
VImage clip2s() throw( VError );
VImage clip2ui() throw( VError );
VImage insertplace( VImage insertplace_sub, std::vector<int> insertplace_x, std::vector<int> insertplace_y ) throw( VError );
VImage clip2us() throw( VError );
VImage slice( double slice_thresh1, double slice_thresh2 ) throw( VError );
VImage segment( int& segment_segments ) throw( VError );
void line( int line_x1, int line_y1, int line_x2, int line_y2, int line_pelval ) throw( VError );
VImage thresh( double thresh_threshold ) throw( VError );
VImage convf_raw( VDMask convf_raw_matrix ) throw( VError );
VImage conv_raw( VIMask conv_raw_matrix ) throw( VError );
VImage contrast_surface_raw( int contrast_surface_raw_half_win_size, int contrast_surface_raw_spacing ) throw( VError );
VImage convsepf_raw( VDMask convsepf_raw_matrix ) throw( VError );
VImage convsep_raw( VIMask convsep_raw_matrix ) throw( VError );
VImage fastcor_raw( VImage fastcor_raw_in2 ) throw( VError );
VImage gradcor_raw( VImage gradcor_raw_in2 ) throw( VError );
VImage spcor_raw( VImage spcor_raw_in2 ) throw( VError );
VImage lhisteq_raw( int lhisteq_raw_width, int lhisteq_raw_height ) throw( VError );
VImage stdif_raw( double stdif_raw_a, double stdif_raw_m0, double stdif_raw_b, double stdif_raw_s0, int stdif_raw_xw, int stdif_raw_yw ) throw( VError );
VImage rank_raw( int rank_raw_xsize, int rank_raw_ysize, int rank_raw_n ) throw( VError );
VImage dilate_raw( VIMask dilate_raw_mask ) throw( VError );
VImage erode_raw( VIMask erode_raw_mask ) throw( VError );
VImage similarity_area( double similarity_area_a, double similarity_area_b, double similarity_area_dx, double similarity_area_dy, int similarity_area_x, int similarity_area_y, int similarity_area_w, int similarity_area_h ) throw( VError );
VImage similarity( double similarity_a, double similarity_b, double similarity_dx, double similarity_dy ) throw( VError );
static VImage mask2vips( VDMask mask2vips_input ) throw( VError );
VDMask vips2mask() throw( VError );
void insertplace( VImage insertplace_sub, int insertplace_x, int insertplace_y ) throw( VError );
void circle( int circle_cx, int circle_cy, int circle_radius, int circle_intensity ) throw( VError );
VImage andimage( VImage andimage_in2 ) throw( VError );
VImage andimage( int andimage_c ) throw( VError );
VImage andimage( std::vector<double> andimage_vec ) throw( VError );
VImage orimage( VImage orimage_in2 ) throw( VError );
VImage orimage( int orimage_c ) throw( VError );
VImage orimage( std::vector<double> orimage_vec ) throw( VError );
VImage eorimage( VImage eorimage_in2 ) throw( VError );
VImage eorimage( int eorimage_c ) throw( VError );
VImage eorimage( std::vector<double> eorimage_vec ) throw( VError );
VImage shiftleft( std::vector<double> shiftleft_vec ) throw( VError );
VImage shiftleft( int shiftleft_c ) throw( VError );
VImage shiftright( std::vector<double> shiftright_vec ) throw( VError );
VImage shiftright( int shiftright_c ) throw( VError );
VImage blend( VImage blend_in1, VImage blend_in2 ) throw( VError );
VImage equal( VImage equal_in2 ) throw( VError );
VImage equal( std::vector<double> equal_vec ) throw( VError );
VImage equal( double equal_c ) throw( VError );
VImage ifthenelse( VImage ifthenelse_in1, VImage ifthenelse_in2 ) throw( VError );
VImage less( VImage less_in2 ) throw( VError );
VImage less( std::vector<double> less_vec ) throw( VError );
VImage less( double less_c ) throw( VError );
VImage lesseq( VImage lesseq_in2 ) throw( VError );
VImage lesseq( std::vector<double> lesseq_vec ) throw( VError );
VImage lesseq( double lesseq_c ) throw( VError );
VImage more( VImage more_in2 ) throw( VError );
VImage more( std::vector<double> more_vec ) throw( VError );
VImage more( double more_c ) throw( VError );
VImage moreeq( VImage moreeq_in2 ) throw( VError );
VImage moreeq( std::vector<double> moreeq_vec ) throw( VError );
VImage moreeq( double moreeq_c ) throw( VError );
VImage notequal( VImage notequal_in2 ) throw( VError );
VImage notequal( std::vector<double> notequal_vec ) throw( VError );
VImage notequal( double notequal_c ) throw( VError );

// headers for package format
// this file automatically generated from
// VIPS library 7.28.0-Tue Jan 31 10:51:45 GMT 2012
static VImage csv2vips( char* csv2vips_filename ) throw( VError );
static VImage fits2vips( char* fits2vips_in ) throw( VError );
static VImage jpeg2vips( char* jpeg2vips_in ) throw( VError );
static VImage magick2vips( char* magick2vips_in ) throw( VError );
static VImage png2vips( char* png2vips_in ) throw( VError );
static VImage exr2vips( char* exr2vips_in ) throw( VError );
static VImage ppm2vips( char* ppm2vips_filename ) throw( VError );
static VImage analyze2vips( char* analyze2vips_filename ) throw( VError );
static VImage tiff2vips( char* tiff2vips_in ) throw( VError );
void vips2csv( char* vips2csv_filename ) throw( VError );
void vips2jpeg( char* vips2jpeg_out ) throw( VError );
void vips2mimejpeg( int vips2mimejpeg_qfac ) throw( VError );
void vips2png( char* vips2png_out ) throw( VError );
void vips2ppm( char* vips2ppm_filename ) throw( VError );
void vips2tiff( char* vips2tiff_out ) throw( VError );

// headers for package freq_filt
// this file automatically generated from
// VIPS library 7.28.0-Tue Jan 31 10:51:45 GMT 2012
static VImage create_fmask( int create_fmask_width, int create_fmask_height, int create_fmask_type, double create_fmask_p1, double create_fmask_p2, double create_fmask_p3, double create_fmask_p4, double create_fmask_p5 ) throw( VError );
VImage disp_ps() throw( VError );
VImage flt_image_freq( int flt_image_freq_type, double flt_image_freq_p1, double flt_image_freq_p2, double flt_image_freq_p3, double flt_image_freq_p4, double flt_image_freq_p5 ) throw( VError );
static VImage fractsurf( int fractsurf_size, double fractsurf_dimension ) throw( VError );
VImage freqflt( VImage freqflt_mask ) throw( VError );
VImage fwfft() throw( VError );
VImage rotquad() throw( VError );
VImage invfft() throw( VError );
VImage phasecor_fft( VImage phasecor_fft_in2 ) throw( VError );
VImage invfftr() throw( VError );

// headers for package histograms_lut
// this file automatically generated from
// VIPS library 7.28.0-Tue Jan 31 10:51:45 GMT 2012
VImage gammacorrect( double gammacorrect_exponent ) throw( VError );
VImage heq( int heq_band_number ) throw( VError );
VImage hist( int hist_band_number ) throw( VError );
VImage histcum() throw( VError );
VImage histeq() throw( VError );
VImage hist_indexed( VImage hist_indexed_value ) throw( VError );
VImage histgr( int histgr_band_number ) throw( VError );
VImage histnD( int histnD_bins ) throw( VError );
VImage histnorm() throw( VError );
VImage histplot() throw( VError );
VImage histspec( VImage histspec_ref ) throw( VError );
VImage hsp( VImage hsp_ref ) throw( VError );
static VImage identity( int identity_nbands ) throw( VError );
static VImage identity_ushort( int identity_ushort_nbands, int identity_ushort_size ) throw( VError );
int ismonotonic() throw( VError );
VImage lhisteq( int lhisteq_width, int lhisteq_height ) throw( VError );
int mpercent( double mpercent_percent ) throw( VError );
static VImage invertlut( VDMask invertlut_measures, int invertlut_lut_size ) throw( VError );
static VImage buildlut( VDMask buildlut_xyes ) throw( VError );
VImage maplut( VImage maplut_lut ) throw( VError );
VImage project( VImage& project_vout ) throw( VError );
VImage stdif( double stdif_a, double stdif_m0, double stdif_b, double stdif_s0, int stdif_xw, int stdif_yw ) throw( VError );
VImage tone_analyse( double tone_analyse_Ps, double tone_analyse_Pm, double tone_analyse_Ph, double tone_analyse_S, double tone_analyse_M, double tone_analyse_H ) throw( VError );
static VImage tone_build( double tone_build_Lb, double tone_build_Lw, double tone_build_Ps, double tone_build_Pm, double tone_build_Ph, double tone_build_S, double tone_build_M, double tone_build_H ) throw( VError );
static VImage tone_build_range( int tone_build_range_in_max, int tone_build_range_out_max, double tone_build_range_Lb, double tone_build_range_Lw, double tone_build_range_Ps, double tone_build_range_Pm, double tone_build_range_Ph, double tone_build_range_S, double tone_build_range_M, double tone_build_range_H ) throw( VError );
VImage tone_map( VImage tone_map_lut ) throw( VError );

// headers for package inplace
// this file automatically generated from
// VIPS library 7.28.0-Tue Jan 31 10:51:45 GMT 2012
void draw_circle( int draw_circle_cx, int draw_circle_cy, int draw_circle_radius, int draw_circle_fill, std::vector<double> draw_circle_ink ) throw( VError );
void draw_rect( int draw_rect_left, int draw_rect_top, int draw_rect_width, int draw_rect_height, int draw_rect_fill, std::vector<double> draw_rect_ink ) throw( VError );
void draw_line( int draw_line_x1, int draw_line_y1, int draw_line_x2, int draw_line_y2, std::vector<double> draw_line_ink ) throw( VError );
void draw_point( int draw_point_x, int draw_point_y, std::vector<double> draw_point_ink ) throw( VError );
void draw_smudge( int draw_smudge_left, int draw_smudge_top, int draw_smudge_width, int draw_smudge_height ) throw( VError );
void draw_flood( int draw_flood_x, int draw_flood_y, std::vector<double> draw_flood_ink ) throw( VError );
void draw_flood_blob( int draw_flood_blob_x, int draw_flood_blob_y, std::vector<double> draw_flood_blob_ink ) throw( VError );
void draw_flood_other( VImage draw_flood_other_test, int draw_flood_other_x, int draw_flood_other_y, int draw_flood_other_serial ) throw( VError );
void draw_image( VImage draw_image_sub, int draw_image_x, int draw_image_y ) throw( VError );
void draw_mask( VImage draw_mask_mask, int draw_mask_x, int draw_mask_y, std::vector<double> draw_mask_ink ) throw( VError );
VImage line( VImage line_mask, VImage line_ink, std::vector<int> line_x1, std::vector<int> line_y1, std::vector<int> line_x2, std::vector<int> line_y2 ) throw( VError );

// headers for package iofuncs
// this file automatically generated from
// VIPS library 7.28.0-Tue Jan 31 10:51:45 GMT 2012
static VImage binfile( char* binfile_filename, int binfile_width, int binfile_height, int binfile_bands, int binfile_offset ) throw( VError );
VImage cache( int cache_tile_width, int cache_tile_height, int cache_max_tiles ) throw( VError );
char* getext() throw( VError );
int header_get_typeof( char* header_get_typeof_field ) throw( VError );
int header_int( char* header_int_field ) throw( VError );
double header_double( char* header_double_field ) throw( VError );
char* header_string( char* header_string_field ) throw( VError );
char* history_get() throw( VError );
void printdesc() throw( VError );

// headers for package mask
// this file automatically generated from
// VIPS library 7.28.0-Tue Jan 31 10:51:45 GMT 2012

// headers for package morphology
// this file automatically generated from
// VIPS library 7.28.0-Tue Jan 31 10:51:45 GMT 2012
double cntlines( int cntlines_direction ) throw( VError );
VImage dilate( VIMask dilate_mask ) throw( VError );
VImage rank( int rank_xsize, int rank_ysize, int rank_n ) throw( VError );
static VImage rank_image( std::vector<VImage> rank_image_in, int rank_image_index ) throw( VError );
static VImage maxvalue( std::vector<VImage> maxvalue_in ) throw( VError );
VImage label_regions( int& label_regions_segments ) throw( VError );
VImage zerox( int zerox_flag ) throw( VError );
VImage erode( VIMask erode_mask ) throw( VError );
VImage profile( int profile_direction ) throw( VError );

// headers for package mosaicing
// this file automatically generated from
// VIPS library 7.28.0-Tue Jan 31 10:51:45 GMT 2012
VImage align_bands() throw( VError );
double correl( VImage correl_sec, int correl_xref, int correl_yref, int correl_xsec, int correl_ysec, int correl_hwindowsize, int correl_hsearchsize, int& correl_x, int& correl_y ) throw( VError );
int _find_lroverlap( VImage _find_lroverlap_sec, int _find_lroverlap_bandno, int _find_lroverlap_xr, int _find_lroverlap_yr, int _find_lroverlap_xs, int _find_lroverlap_ys, int _find_lroverlap_halfcorrelation, int _find_lroverlap_halfarea, int& _find_lroverlap_dy0, double& _find_lroverlap_scale1, double& _find_lroverlap_angle1, double& _find_lroverlap_dx1, double& _find_lroverlap_dy1 ) throw( VError );
int _find_tboverlap( VImage _find_tboverlap_sec, int _find_tboverlap_bandno, int _find_tboverlap_xr, int _find_tboverlap_yr, int _find_tboverlap_xs, int _find_tboverlap_ys, int _find_tboverlap_halfcorrelation, int _find_tboverlap_halfarea, int& _find_tboverlap_dy0, double& _find_tboverlap_scale1, double& _find_tboverlap_angle1, double& _find_tboverlap_dx1, double& _find_tboverlap_dy1 ) throw( VError );
VImage global_balance( double global_balance_gamma ) throw( VError );
VImage global_balancef( double global_balancef_gamma ) throw( VError );
VImage lrmerge( VImage lrmerge_sec, int lrmerge_dx, int lrmerge_dy, int lrmerge_mwidth ) throw( VError );
VImage lrmerge1( VImage lrmerge1_sec, int lrmerge1_xr1, int lrmerge1_yr1, int lrmerge1_xs1, int lrmerge1_ys1, int lrmerge1_xr2, int lrmerge1_yr2, int lrmerge1_xs2, int lrmerge1_ys2, int lrmerge1_mwidth ) throw( VError );
VImage lrmosaic( VImage lrmosaic_sec, int lrmosaic_bandno, int lrmosaic_xr, int lrmosaic_yr, int lrmosaic_xs, int lrmosaic_ys, int lrmosaic_halfcorrelation, int lrmosaic_halfarea, int lrmosaic_balancetype, int lrmosaic_mwidth ) throw( VError );
VImage lrmosaic1( VImage lrmosaic1_sec, int lrmosaic1_bandno, int lrmosaic1_xr1, int lrmosaic1_yr1, int lrmosaic1_xs1, int lrmosaic1_ys1, int lrmosaic1_xr2, int lrmosaic1_yr2, int lrmosaic1_xs2, int lrmosaic1_ys2, int lrmosaic1_halfcorrelation, int lrmosaic1_halfarea, int lrmosaic1_balancetype, int lrmosaic1_mwidth ) throw( VError );
VImage match_linear( VImage match_linear_sec, int match_linear_xref1, int match_linear_yref1, int match_linear_xsec1, int match_linear_ysec1, int match_linear_xref2, int match_linear_yref2, int match_linear_xsec2, int match_linear_ysec2 ) throw( VError );
VImage match_linear_search( VImage match_linear_search_sec, int match_linear_search_xref1, int match_linear_search_yref1, int match_linear_search_xsec1, int match_linear_search_ysec1, int match_linear_search_xref2, int match_linear_search_yref2, int match_linear_search_xsec2, int match_linear_search_ysec2, int match_linear_search_hwindowsize, int match_linear_search_hsearchsize ) throw( VError );
double maxpos_subpel( double& maxpos_subpel_y ) throw( VError );
VImage remosaic( char* remosaic_old_str, char* remosaic_new_str ) throw( VError );
VImage tbmerge( VImage tbmerge_sec, int tbmerge_dx, int tbmerge_dy, int tbmerge_mwidth ) throw( VError );
VImage tbmerge1( VImage tbmerge1_sec, int tbmerge1_xr1, int tbmerge1_yr1, int tbmerge1_xs1, int tbmerge1_ys1, int tbmerge1_xr2, int tbmerge1_yr2, int tbmerge1_xs2, int tbmerge1_ys2, int tbmerge1_mwidth ) throw( VError );
VImage tbmosaic( VImage tbmosaic_sec, int tbmosaic_bandno, int tbmosaic_xr, int tbmosaic_yr, int tbmosaic_xs, int tbmosaic_ys, int tbmosaic_halfcorrelation, int tbmosaic_halfarea, int tbmosaic_balancetype, int tbmosaic_mwidth ) throw( VError );
VImage tbmosaic1( VImage tbmosaic1_sec, int tbmosaic1_bandno, int tbmosaic1_xr1, int tbmosaic1_yr1, int tbmosaic1_xs1, int tbmosaic1_ys1, int tbmosaic1_xr2, int tbmosaic1_yr2, int tbmosaic1_xs2, int tbmosaic1_ys2, int tbmosaic1_halfcorrelation, int tbmosaic1_halfarea, int tbmosaic1_balancetype, int tbmosaic1_mwidth ) throw( VError );

// headers for package other
// this file automatically generated from
// VIPS library 7.28.0-Tue Jan 31 10:51:45 GMT 2012
VImage benchmark() throw( VError );
double benchmark2() throw( VError );
VImage benchmarkn( int benchmarkn_n ) throw( VError );
static VImage eye( int eye_xsize, int eye_ysize, double eye_factor ) throw( VError );
static VImage grey( int grey_xsize, int grey_ysize ) throw( VError );
static VImage feye( int feye_xsize, int feye_ysize, double feye_factor ) throw( VError );
static VImage fgrey( int fgrey_xsize, int fgrey_ysize ) throw( VError );
static VImage fzone( int fzone_size ) throw( VError );
static VImage make_xy( int make_xy_xsize, int make_xy_ysize ) throw( VError );
static VImage sines( int sines_xsize, int sines_ysize, double sines_horfreq, double sines_verfreq ) throw( VError );
static VImage zone( int zone_size ) throw( VError );

// headers for package resample
// this file automatically generated from
// VIPS library 7.28.0-Tue Jan 31 10:51:45 GMT 2012
VImage rightshift_size( int rightshift_size_xshift, int rightshift_size_yshift, int rightshift_size_band_fmt ) throw( VError );
VImage shrink( double shrink_xfac, double shrink_yfac ) throw( VError );
VImage stretch3( double stretch3_xdisp, double stretch3_ydisp ) throw( VError );

// headers for package video
// this file automatically generated from
// VIPS library 7.28.0-Tue Jan 31 10:51:45 GMT 2012
static VImage video_test( int video_test_brightness, int video_test_error ) throw( VError );
static VImage video_v4l1( char* video_v4l1_device, int video_v4l1_channel, int video_v4l1_brightness, int video_v4l1_colour, int video_v4l1_contrast, int video_v4l1_hue, int video_v4l1_ngrabs ) throw( VError );

