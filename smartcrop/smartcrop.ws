<?xml version="1.0"?>
<root xmlns="http://www.vips.ecs.soton.ac.uk/nip/8.5.1">
  <Workspace window_x="0" window_y="28" window_width="1920" window_height="1172" view="WORKSPACE_MODE_REGULAR" scale="1" offset="0" locked="false" lpane_position="100" lpane_open="false" rpane_position="400" rpane_open="false" local_defs="// private definitions for this tab&#10;" name="tab2" caption="Default empty tab" filename="/data/john/pics/smartcrop/smartcrop.ws">
    <Column x="0" y="0" open="true" selected="false" sform="false" next="6" name="A" caption="load, downsize and LAB">
      <Subcolumn vislevel="3">
        <Row popup="false" name="A1">
          <Rhs vislevel="1" flags="1">
            <iImage image_left="0" image_top="0" image_mag="0" show_status="false" show_paintbox="false" show_convert="false" show_rulers="false" scale="0" offset="0" falsecolour="false" type="true"/>
            <Subcolumn vislevel="0"/>
            <iText formula="Image_file &quot;/data/john/pics/smartcrop/quagga.jpg&quot;"/>
          </Rhs>
        </Row>
        <Row popup="false" name="A5">
          <Rhs vislevel="3" flags="7">
            <iImage image_left="0" image_top="0" image_mag="0" show_status="false" show_paintbox="false" show_convert="false" show_rulers="false" scale="0" offset="0" falsecolour="false" type="true"/>
            <Subcolumn vislevel="1">
              <Row name="x">
                <Rhs vislevel="0" flags="4">
                  <iText/>
                </Rhs>
              </Row>
              <Row name="super">
                <Rhs vislevel="0" flags="4">
                  <iImage image_left="0" image_top="0" image_mag="0" show_status="false" show_paintbox="false" show_convert="false" show_rulers="false" scale="0" offset="0" falsecolour="false" type="true"/>
                  <Subcolumn vislevel="0"/>
                  <iText/>
                </Rhs>
              </Row>
              <Row name="which">
                <Rhs vislevel="1" flags="1">
                  <Option/>
                  <Subcolumn vislevel="0"/>
                  <iText/>
                </Rhs>
              </Row>
              <Row name="size">
                <Rhs vislevel="1" flags="1">
                  <Expression caption="Resize to (pixels)"/>
                  <Subcolumn vislevel="0"/>
                  <iText/>
                </Rhs>
              </Row>
              <Row name="aspect">
                <Rhs vislevel="1" flags="1">
                  <Toggle/>
                  <Subcolumn vislevel="0"/>
                  <iText/>
                </Rhs>
              </Row>
              <Row name="kernel">
                <Rhs vislevel="2" flags="6">
                  <Subcolumn vislevel="1">
                    <Row name="default">
                      <Rhs vislevel="0" flags="4">
                        <iText/>
                      </Rhs>
                    </Row>
                    <Row name="super">
                      <Rhs vislevel="1" flags="4">
                        <Subcolumn vislevel="0"/>
                        <iText/>
                      </Rhs>
                    </Row>
                    <Row name="kernel">
                      <Rhs vislevel="1" flags="1">
                        <Option caption="Kernel" labelsn="5" labels0="Nearest neighbour" labels1="Linear" labels2="Cubic" labels3="Lanczos, two lobes" labels4="Lanczos, three lobes" value="4"/>
                        <Subcolumn vislevel="0"/>
                        <iText/>
                      </Rhs>
                    </Row>
                  </Subcolumn>
                  <iText/>
                </Rhs>
              </Row>
            </Subcolumn>
            <iText formula="Image_transform_item.Resize_item.Size_item.action A1"/>
          </Rhs>
        </Row>
        <Row popup="false" name="A3">
          <Rhs vislevel="3" flags="7">
            <iImage image_left="0" image_top="0" image_mag="0" show_status="false" show_paintbox="false" show_convert="false" show_rulers="false" scale="0" offset="0" falsecolour="false" type="true"/>
            <Subcolumn vislevel="1">
              <Row name="dest">
                <Rhs vislevel="0" flags="4">
                  <iText/>
                </Rhs>
              </Row>
              <Row name="x">
                <Rhs vislevel="3" flags="4">
                  <iText/>
                </Rhs>
              </Row>
              <Row name="super">
                <Rhs vislevel="0" flags="4">
                  <iImage image_left="0" image_top="0" image_mag="0" show_status="false" show_paintbox="false" show_convert="false" show_rulers="false" scale="0" offset="0" falsecolour="false" type="true"/>
                  <Subcolumn vislevel="0"/>
                  <iText/>
                </Rhs>
              </Row>
              <Row name="to">
                <Rhs vislevel="1" flags="1">
                  <Option caption="Convert to" labelsn="11" labels0="Mono" labels1="sRGB" labels2="RGB16" labels3="GREY16" labels4="Lab" labels5="LabQ" labels6="LabS" labels7="LCh" labels8="XYZ" labels9="Yxy" labels10="UCS" value="8"/>
                  <Subcolumn vislevel="0"/>
                  <iText/>
                </Rhs>
              </Row>
            </Subcolumn>
            <iText formula="Colour_convert_item.Lab_item.action A5"/>
          </Rhs>
        </Row>
      </Subcolumn>
    </Column>
    <Column x="488" y="677" open="true" selected="false" sform="false" next="4" name="E" caption="find saturated colours">
      <Subcolumn vislevel="3">
        <Row popup="false" name="E1">
          <Rhs vislevel="2" flags="5">
            <iImage image_left="0" image_top="0" image_mag="0" show_status="false" show_paintbox="false" show_convert="false" show_rulers="false" scale="0" offset="0" falsecolour="false" type="true"/>
            <Subcolumn vislevel="0"/>
            <iText formula="A3"/>
          </Rhs>
        </Row>
        <Row popup="false" name="E2">
          <Rhs vislevel="3" flags="7">
            <iImage image_left="0" image_top="0" image_mag="0" show_status="false" show_paintbox="false" show_convert="false" show_rulers="false" scale="0" offset="0" falsecolour="false" type="true"/>
            <Subcolumn vislevel="1"/>
            <iText formula="Colour_convert_item.LCh_item.action E1"/>
          </Rhs>
        </Row>
        <Row popup="false" name="E3">
          <Rhs vislevel="2" flags="5">
            <iImage window_x="29" window_y="29" window_width="437" window_height="418" image_left="212" image_top="154" image_mag="1" show_status="true" show_paintbox="false" show_convert="true" show_rulers="false" scale="3.3570370916406809" offset="0" falsecolour="false" type="true"/>
            <Subcolumn vislevel="0"/>
            <iText formula="E2?1"/>
          </Rhs>
        </Row>
      </Subcolumn>
    </Column>
    <Column x="1020" y="0" open="true" selected="false" sform="false" next="9" name="F" caption="combine masks and shrink">
      <Subcolumn vislevel="3">
        <Row popup="false" name="F1">
          <Rhs vislevel="2" flags="5">
            <iImage window_x="29" window_y="29" window_width="450" window_height="167" image_left="212" image_top="28" image_mag="1" show_status="true" show_paintbox="false" show_convert="true" show_rulers="false" scale="1" offset="0" falsecolour="false" type="true"/>
            <Subcolumn vislevel="0"/>
            <iText formula="M9"/>
          </Rhs>
        </Row>
        <Row popup="false" name="F2">
          <Rhs vislevel="2" flags="5">
            <iImage image_left="0" image_top="0" image_mag="0" show_status="false" show_paintbox="false" show_convert="false" show_rulers="false" scale="0" offset="0" falsecolour="false" type="true"/>
            <Subcolumn vislevel="0"/>
            <iText formula="E3"/>
          </Rhs>
        </Row>
        <Row popup="false" name="F3">
          <Rhs vislevel="2" flags="5">
            <iImage window_x="29" window_y="29" window_width="438" window_height="167" image_left="206" image_top="28" image_mag="1" show_status="true" show_paintbox="false" show_convert="true" show_rulers="false" scale="1" offset="0" falsecolour="false" type="true"/>
            <Subcolumn vislevel="0"/>
            <iText formula="B8"/>
          </Rhs>
        </Row>
        <Row popup="false" name="F4">
          <Rhs vislevel="2" flags="5">
            <iImage image_left="0" image_top="0" image_mag="0" show_status="false" show_paintbox="false" show_convert="false" show_rulers="false" scale="0" offset="0" falsecolour="false" type="true"/>
            <Subcolumn vislevel="0"/>
            <iText formula="F1 + F2 + F3"/>
          </Rhs>
        </Row>
        <Row popup="false" name="F7">
          <Rhs vislevel="1" flags="4">
            <iText formula="32 / F4.width"/>
          </Rhs>
        </Row>
        <Row popup="false" name="F5">
          <Rhs vislevel="1" flags="4">
            <iText formula="32 / F4.height"/>
          </Rhs>
        </Row>
        <Row popup="false" name="F6">
          <Rhs vislevel="3" flags="7">
            <iImage window_x="89" window_y="129" window_width="571" window_height="755" image_left="139" image_top="161" image_mag="2" show_status="true" show_paintbox="false" show_convert="true" show_rulers="false" scale="0.49310903303608372" offset="0" falsecolour="true" type="true"/>
            <Subcolumn vislevel="1">
              <Row name="x">
                <Rhs vislevel="0" flags="4">
                  <iText/>
                </Rhs>
              </Row>
              <Row name="super">
                <Rhs vislevel="0" flags="4">
                  <iImage image_left="0" image_top="0" image_mag="0" show_status="false" show_paintbox="false" show_convert="false" show_rulers="false" scale="0" offset="0" falsecolour="false" type="true"/>
                  <Subcolumn vislevel="0"/>
                  <iText/>
                </Rhs>
              </Row>
              <Row name="xfactor">
                <Rhs vislevel="1" flags="1">
                  <Expression caption="Horizontal scale factor"/>
                  <Subcolumn vislevel="0">
                    <Row name="caption">
                      <Rhs vislevel="0" flags="4">
                        <iText/>
                      </Rhs>
                    </Row>
                    <Row name="expr">
                      <Rhs vislevel="0" flags="4">
                        <iText formula="F7"/>
                      </Rhs>
                    </Row>
                    <Row name="super">
                      <Rhs vislevel="1" flags="4">
                        <Subcolumn vislevel="0"/>
                        <iText/>
                      </Rhs>
                    </Row>
                  </Subcolumn>
                  <iText/>
                </Rhs>
              </Row>
              <Row name="yfactor">
                <Rhs vislevel="1" flags="1">
                  <Expression caption="Vertical scale factor"/>
                  <Subcolumn vislevel="0">
                    <Row name="caption">
                      <Rhs vislevel="0" flags="4">
                        <iText/>
                      </Rhs>
                    </Row>
                    <Row name="expr">
                      <Rhs vislevel="0" flags="4">
                        <iText formula="F5"/>
                      </Rhs>
                    </Row>
                    <Row name="super">
                      <Rhs vislevel="1" flags="4">
                        <Subcolumn vislevel="0"/>
                        <iText/>
                      </Rhs>
                    </Row>
                  </Subcolumn>
                  <iText/>
                </Rhs>
              </Row>
              <Row name="kernel">
                <Rhs vislevel="2" flags="6">
                  <Subcolumn vislevel="1">
                    <Row name="default">
                      <Rhs vislevel="0" flags="4">
                        <iText/>
                      </Rhs>
                    </Row>
                    <Row name="super">
                      <Rhs vislevel="1" flags="4">
                        <Subcolumn vislevel="0"/>
                        <iText/>
                      </Rhs>
                    </Row>
                    <Row name="kernel">
                      <Rhs vislevel="1" flags="1">
                        <Option caption="Kernel" labelsn="5" labels0="Nearest neighbour" labels1="Linear" labels2="Cubic" labels3="Lanczos, two lobes" labels4="Lanczos, three lobes" value="1"/>
                        <Subcolumn vislevel="0"/>
                        <iText/>
                      </Rhs>
                    </Row>
                  </Subcolumn>
                  <iText/>
                </Rhs>
              </Row>
            </Subcolumn>
            <iText formula="Image_transform_item.Resize_item.Scale_item.action F4"/>
          </Rhs>
        </Row>
        <Row popup="false" name="F8">
          <Rhs vislevel="3" flags="7">
            <iImage window_x="73" window_y="72" window_width="507" window_height="153" image_left="247" image_top="21" image_mag="1" show_status="true" show_paintbox="false" show_convert="true" show_rulers="false" scale="0.67358101485091437" offset="0" falsecolour="true" type="true"/>
            <Subcolumn vislevel="1">
              <Row name="x">
                <Rhs vislevel="3" flags="4">
                  <iText/>
                </Rhs>
              </Row>
              <Row name="super">
                <Rhs vislevel="0" flags="4">
                  <iImage image_left="0" image_top="0" image_mag="0" show_status="false" show_paintbox="false" show_convert="false" show_rulers="false" scale="0" offset="0" falsecolour="false" type="true"/>
                  <Subcolumn vislevel="0"/>
                  <iText/>
                </Rhs>
              </Row>
              <Row name="type">
                <Rhs vislevel="1" flags="1">
                  <Option/>
                  <Subcolumn vislevel="0"/>
                  <iText/>
                </Rhs>
              </Row>
              <Row name="r">
                <Rhs vislevel="1" flags="1">
                  <Slider caption="Radius" from="1" to="100" value="10.834437086092715"/>
                  <Subcolumn vislevel="0"/>
                  <iText/>
                </Rhs>
              </Row>
              <Row name="fac">
                <Rhs vislevel="1" flags="1">
                  <Slider/>
                  <Subcolumn vislevel="0"/>
                  <iText/>
                </Rhs>
              </Row>
              <Row name="layers">
                <Rhs vislevel="1" flags="1">
                  <Slider/>
                  <Subcolumn vislevel="0"/>
                  <iText/>
                </Rhs>
              </Row>
              <Row name="shape">
                <Rhs vislevel="1" flags="1">
                  <Option caption="Mask shape" labelsn="2" labels0="Square" labels1="Gaussian" value="1"/>
                  <Subcolumn vislevel="0"/>
                  <iText/>
                </Rhs>
              </Row>
              <Row name="prec">
                <Rhs vislevel="1" flags="1">
                  <Option caption="Precision" labelsn="3" labels0="Int" labels1="Float" labels2="Approximate" value="0"/>
                  <Subcolumn vislevel="0"/>
                  <iText/>
                </Rhs>
              </Row>
            </Subcolumn>
            <iText formula="Filter_conv_item.Custom_blur_item.action F6"/>
          </Rhs>
        </Row>
      </Subcolumn>
    </Column>
    <Column x="1515" y="0" open="true" selected="false" sform="false" next="5" name="H" caption="position crop">
      <Subcolumn vislevel="3">
        <Row popup="false" name="H1">
          <Rhs vislevel="2" flags="5">
            <iImage window_x="73" window_y="72" window_width="518" window_height="326" image_left="63" image_top="27" image_mag="4" show_status="true" show_paintbox="false" show_convert="true" show_rulers="false" scale="0.45737913117857182" offset="0" falsecolour="true" type="true"/>
            <Subcolumn vislevel="0"/>
            <iText formula="F8"/>
          </Rhs>
        </Row>
        <Row popup="false" name="H2">
          <Rhs vislevel="1" flags="4">
            <iText formula="Math_stats_item.Maxpos_item.action H1"/>
          </Rhs>
        </Row>
        <Row popup="false" name="H3">
          <Rhs vislevel="1" flags="4">
            <iText formula="re H2 / F7"/>
          </Rhs>
        </Row>
        <Row popup="false" name="H4">
          <Rhs vislevel="1" flags="4">
            <iText formula="im H2 / F5"/>
          </Rhs>
        </Row>
      </Subcolumn>
    </Column>
    <Column x="0" y="542" open="true" selected="false" sform="false" next="10" name="I" caption="result">
      <Subcolumn vislevel="3">
        <Row popup="false" name="I5">
          <Rhs vislevel="1" flags="1">
            <Expression caption="crop width"/>
            <Subcolumn vislevel="0">
              <Row name="caption">
                <Rhs vislevel="0" flags="4">
                  <iText/>
                </Rhs>
              </Row>
              <Row name="expr">
                <Rhs vislevel="0" flags="4">
                  <iText formula="128"/>
                </Rhs>
              </Row>
              <Row name="super">
                <Rhs vislevel="1" flags="4">
                  <Subcolumn vislevel="0"/>
                  <iText/>
                </Rhs>
              </Row>
            </Subcolumn>
            <iText formula="Expression &quot;crop width&quot; 64"/>
          </Rhs>
        </Row>
        <Row popup="false" name="I3">
          <Rhs vislevel="1" flags="1">
            <Expression caption="crop height"/>
            <Subcolumn vislevel="0">
              <Row name="caption">
                <Rhs vislevel="0" flags="4">
                  <iText/>
                </Rhs>
              </Row>
              <Row name="expr">
                <Rhs vislevel="0" flags="4">
                  <iText formula="128"/>
                </Rhs>
              </Row>
              <Row name="super">
                <Rhs vislevel="1" flags="4">
                  <Subcolumn vislevel="0"/>
                  <iText/>
                </Rhs>
              </Row>
            </Subcolumn>
            <iText formula="Expression &quot;crop height&quot; 64"/>
          </Rhs>
        </Row>
        <Row popup="false" name="I6">
          <Rhs vislevel="1" flags="4">
            <iText formula="&quot; &quot;"/>
          </Rhs>
        </Row>
        <Row popup="false" name="I1">
          <Rhs vislevel="1" flags="4">
            <iText formula="H3"/>
          </Rhs>
        </Row>
        <Row popup="false" name="I2">
          <Rhs vislevel="1" flags="4">
            <iText formula="H4"/>
          </Rhs>
        </Row>
        <Row popup="false" name="I7">
          <Rhs vislevel="1" flags="4">
            <iText formula="min [A5.width - I5.expr, max [0, I1 - I5.expr / 2]]"/>
          </Rhs>
        </Row>
        <Row popup="false" name="I4">
          <Rhs vislevel="1" flags="4">
            <iText formula="min [A5.height - I3.expr, max [0, I2 - I3.expr / 2]]"/>
          </Rhs>
        </Row>
        <Row popup="false" name="I9">
          <Rhs vislevel="2" flags="5">
            <iRegion image_left="0" image_top="0" image_mag="0" show_status="false" show_paintbox="false" show_convert="false" show_rulers="false" scale="0" offset="0" falsecolour="false" type="true">
              <iRegiongroup/>
            </iRegion>
            <Subcolumn vislevel="0"/>
            <iText formula="Region A3 I7 I4 I5.expr I3.expr"/>
          </Rhs>
        </Row>
      </Subcolumn>
    </Column>
    <Column x="488" y="1089" open="true" selected="true" sform="false" next="9" name="B" caption="detect skin">
      <Subcolumn vislevel="3">
        <Row popup="false" name="B1">
          <Rhs vislevel="2" flags="5">
            <iImage window_x="29" window_y="29" window_width="570" window_height="412" image_left="279" image_top="151" image_mag="1" show_status="true" show_paintbox="false" show_convert="true" show_rulers="false" scale="1" offset="0" falsecolour="false" type="true"/>
            <Subcolumn vislevel="0"/>
            <iText formula="A3"/>
          </Rhs>
        </Row>
        <Row popup="false" name="B2">
          <Rhs vislevel="2" flags="5">
            <iImage image_left="0" image_top="0" image_mag="0" show_status="false" show_paintbox="false" show_convert="false" show_rulers="false" scale="0" offset="0" falsecolour="false" type="true"/>
            <Subcolumn vislevel="0"/>
            <iText formula="Math_arithmetic_item.Absolute_value_vector_item.action B1"/>
          </Rhs>
        </Row>
        <Row popup="false" name="B3">
          <Rhs vislevel="2" flags="5">
            <Vector/>
            <Subcolumn vislevel="0"/>
            <iText formula="Vector [0.78, 0.57, 0.44]"/>
          </Rhs>
        </Row>
        <Row popup="false" name="B4">
          <Rhs vislevel="2" flags="5">
            <iImage window_x="29" window_y="29" window_width="570" window_height="167" image_left="272" image_top="28" image_mag="1" show_status="true" show_paintbox="false" show_convert="true" show_rulers="false" scale="255.00000000000043" offset="77.378531073446339" falsecolour="false" type="true"/>
            <Subcolumn vislevel="0"/>
            <iText formula="B1 / B2 - B3"/>
          </Rhs>
        </Row>
        <Row popup="false" name="B5">
          <Rhs vislevel="2" flags="5">
            <iImage window_x="29" window_y="29" window_width="447" window_height="167" image_left="211" image_top="28" image_mag="1" show_status="true" show_paintbox="false" show_convert="true" show_rulers="false" scale="255.00000000000043" offset="0" falsecolour="false" type="true"/>
            <Subcolumn vislevel="0"/>
            <iText formula="Math_arithmetic_item.Absolute_value_vector_item.action B4"/>
          </Rhs>
        </Row>
        <Row popup="false" name="B6">
          <Rhs vislevel="2" flags="5">
            <iImage window_x="356" window_y="539" window_width="447" window_height="485" image_left="217" image_top="187" image_mag="1" show_status="true" show_paintbox="false" show_convert="true" show_rulers="false" scale="1.2284159198575442" offset="0" falsecolour="false" type="true"/>
            <Subcolumn vislevel="0"/>
            <iText formula="100 * (1 - B5)"/>
          </Rhs>
        </Row>
        <Row popup="false" name="B8">
          <Rhs vislevel="2" flags="5">
            <iImage window_x="29" window_y="29" window_width="450" window_height="349" image_left="219" image_top="119" image_mag="1" show_status="true" show_paintbox="false" show_convert="true" show_rulers="false" scale="1" offset="0" falsecolour="false" type="true"/>
            <Subcolumn vislevel="0"/>
            <iText formula="if B1?1 &gt; 5 then B6 else 0"/>
          </Rhs>
        </Row>
      </Subcolumn>
    </Column>
    <Column x="488" y="0" open="true" selected="false" sform="false" next="11" name="M" caption="find edges with laplacian">
      <Subcolumn vislevel="3">
        <Row popup="false" name="M1">
          <Rhs vislevel="2" flags="5">
            <iImage image_left="0" image_top="0" image_mag="0" show_status="false" show_paintbox="false" show_convert="false" show_rulers="false" scale="0" offset="0" falsecolour="false" type="true"/>
            <Subcolumn vislevel="0"/>
            <iText formula="A3"/>
          </Rhs>
        </Row>
        <Row popup="false" name="M2">
          <Rhs vislevel="2" flags="5">
            <iImage image_left="0" image_top="0" image_mag="0" show_status="false" show_paintbox="false" show_convert="false" show_rulers="false" scale="0" offset="0" falsecolour="false" type="true"/>
            <Subcolumn vislevel="0"/>
            <iText formula="M1?1"/>
          </Rhs>
        </Row>
        <Row popup="false" name="M7">
          <Rhs vislevel="3" flags="7">
            <iImage image_left="0" image_top="0" image_mag="0" show_status="false" show_paintbox="false" show_convert="false" show_rulers="false" scale="0" offset="0" falsecolour="false" type="true"/>
            <Subcolumn vislevel="1">
              <Row name="x">
                <Rhs vislevel="0" flags="4">
                  <iText/>
                </Rhs>
              </Row>
              <Row name="super">
                <Rhs vislevel="0" flags="4">
                  <iImage image_left="0" image_top="0" image_mag="0" show_status="false" show_paintbox="false" show_convert="false" show_rulers="false" scale="0" offset="0" falsecolour="false" type="true"/>
                  <Subcolumn vislevel="0"/>
                  <iText/>
                </Rhs>
              </Row>
              <Row name="matrix">
                <Rhs vislevel="1" flags="1">
                  <Matrix valuen="9" value0="0" value1="-1" value2="0" value3="-1" value4="4" value5="-1" value6="0" value7="-1" value8="0" width="3" height="3" scale="1" offset="0" filename="" display="3"/>
                  <Subcolumn vislevel="0"/>
                  <iText/>
                </Rhs>
              </Row>
              <Row name="separable">
                <Rhs vislevel="1" flags="4">
                  <iText/>
                </Rhs>
              </Row>
              <Row name="type">
                <Rhs vislevel="1" flags="1">
                  <Option/>
                  <Subcolumn vislevel="0"/>
                  <iText/>
                </Rhs>
              </Row>
              <Row name="rotate">
                <Rhs vislevel="1" flags="1">
                  <Option/>
                  <Subcolumn vislevel="0"/>
                  <iText/>
                </Rhs>
              </Row>
            </Subcolumn>
            <iText formula="Filter_conv_item.Custom_conv_item.action M2"/>
          </Rhs>
        </Row>
        <Row popup="false" name="M9">
          <Rhs vislevel="2" flags="5">
            <iImage image_left="0" image_top="0" image_mag="0" show_status="false" show_paintbox="false" show_convert="false" show_rulers="false" scale="0" offset="0" falsecolour="false" type="true"/>
            <Subcolumn vislevel="0"/>
            <iText formula="5 * abs M7"/>
          </Rhs>
        </Row>
      </Subcolumn>
    </Column>
  </Workspace>
</root>
