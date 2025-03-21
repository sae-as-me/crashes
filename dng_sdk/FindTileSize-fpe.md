## Affected Projects
**dng_sdk** commit `f8f6cf848d0a2146ac284dae2ccd7a795538ea0f`
([https://android.googlesource.com/platform/external/dng_sdk/](https://android.googlesource.com/platform/external/dng_sdk/))
## Problem Type
CWE-369: Divide By Zero
## Description
### Summary
A  vulnerability was discovered in the `dng_area_task::FindTileSize` function within dng_sdk. This issue occurs when processing certain files, leading to a potential application crash.
### Details
The vulnerability arises in the `dng_area_task::FindTileSize` function defined in `source/dng_area_task.cpp` at line `145`. 
The value of **`repeatH`** may be `0`, which leads to the result of **`tileSize.h = Min_int32(repeatH, maxTileSize.h);`** being `0`, resulting in `Divide By Zero` in **`uint32 countH = (repeatH + tileSize.h - 1) / tileSize.h;`**.
```c++
dng_point dng_area_task::FindTileSize(const dng_rect & area) const {

    dng_rect repeatingTile1 = RepeatingTile1();
    dng_rect repeatingTile2 = RepeatingTile2();
    dng_rect repeatingTile3 = RepeatingTile3();

    if (repeatingTile1.IsEmpty()) {
        repeatingTile1 = area;
    }

    if (repeatingTile2.IsEmpty()) {
        repeatingTile2 = area;
    }

    if (repeatingTile3.IsEmpty()) {
        repeatingTile3 = area;
    }

    uint32 repeatV = Min_uint32(Min_uint32(repeatingTile1.H(),
            repeatingTile2.H()),
        repeatingTile3.H());

    uint32 repeatH = Min_uint32(Min_uint32(repeatingTile1.W(),
            repeatingTile2.W()),
        repeatingTile3.W());

    dng_point maxTileSize = MaxTileSize();

    dng_point tileSize;

    tileSize.v = Min_int32(repeatV, maxTileSize.v);
    tileSize.h = Min_int32(repeatH, maxTileSize.h);    //the repeatH may be 0

    // What this is doing is, if the smallest repeating image tile is larger than the 
    // maximum tile size, adjusting the tile size down so that the tiles are as small
    // as possible while still having the same number of tiles covering the
    // repeat area.  This makes the areas more equal in size, making MP
    // algorithms work better.

    // The image core team did not understand this code, and disabled it.
    // Really stupid idea to turn off code you don't understand!
    // I'm undoing this removal, because I think the code is correct and useful.

    uint32 countV = (repeatV + tileSize.v - 1) / tileSize.v;
    uint32 countH = (repeatH + tileSize.h - 1) / tileSize.h;    //Divide By Zero

    tileSize.v = (repeatV + countV - 1) / countV;
    tileSize.h = (repeatH + countH - 1) / countH;

    // Round up to unit cell size.

    dng_point unitCell = UnitCell();

    if (unitCell.h != 1 || unitCell.v != 1) {
        tileSize.v = ((tileSize.v + unitCell.v - 1) / unitCell.v) * unitCell.v;
        tileSize.h = ((tileSize.h + unitCell.h - 1) / unitCell.h) * unitCell.h;
    }

    // But if that is larger than maximum tile size, round down to unit cell size.

    if (tileSize.v > maxTileSize.v) {
        tileSize.v = (maxTileSize.v / unitCell.v) * unitCell.v;
    }

    if (tileSize.h > maxTileSize.h) {
        tileSize.h = (maxTileSize.h / unitCell.h) * unitCell.h;
    }

    #if qImagecore
    if (gPrintTimings) {
        fprintf(stdout, "\nRender tile for below: %d x %d\n", (int32) tileSize.h, (int32) tileSize.v);
    }
    #endif

    return tileSize;

}
```
![image](https://github.com/sae-as-me/crashes/blob/main/dng_sdk/FindTileSize-fpe.png)
### PoC
**Steps to reproduce:**
1. Clone the glslang repository and build it using the following commands : 
```sh
git clone https://android.googlesource.com/platform/external/dng_sdk/
cd dng_sdk

export CC='clang'
export CXX='clang++'
export CFLAGS='-fsanitize=address -O0 -g'
export CXXFLAGS='-fsanitize=address -O0 -g'

# compile source
cd ./source
rm dng_xmp*
find . -name "*.cpp" -exec $CXX $CXXFLAGS -DqDNGUseLibJPEG=1 -DqDNGUseXMP=0 -DqDNGThreadSafe=1 -c {} \;
ar cr libdns_sdk.a *.o

```
2. Compile the fuzzer like oss-fuzz: 
- all harnesses are from oss-fuzz:
```sh
export LIB_FUZZING_ENGINE='-fsanitize=fuzzer'
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE ../fuzzer/dng_parser_fuzzer.cpp -o $OUT/dng_parser_fuzzer \
  ./libdns_sdk.a -I./ -l:libjpeg.a -lz
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE $SRC/dng_stage_fuzzer.cpp -o $OUT/dng_stage_fuzzer \
  ./libdns_sdk.a -I./ -l:libjpeg.a -lz
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE $SRC/dng_camera_profile_fuzzer.cpp -o $OUT/dng_camera_profile_fuzzer \
  ./libdns_sdk.a -I./ -l:libjpeg.a -lz

sed -i 's/main/main2/g' $SRC/dng_sdk/source/dng_validate.cpp
sed -i 's/printf ("Val/\/\//g' $SRC/dng_sdk/source/dng_validate.cpp
sed -i 's/static//g' $SRC/dng_sdk/source/dng_validate.cpp

cat $SRC/dng_sdk/source/dng_validate.cpp $SRC/dng_validate_fuzzer.cpp >> $SRC/dng_validate_fuzzer.tmp
mv $SRC/dng_validate_fuzzer.tmp $SRC/dng_validate_fuzzer.cpp
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE -DqDNGValidateTarget \
  $SRC/dng_sdk/source/dng_globals.cpp \
  $SRC/dng_validate_fuzzer.cpp \
  -o $OUT/dng_validate_fuzzer \
  ./libdns_sdk.a -I./ -l:libjpeg.a -lz

cat $SRC/dng_sdk/source/dng_validate.cpp $SRC/dng_fixed_validate_fuzzer.cpp >> $SRC/dng_fixed_validate_fuzzer.tmp
mv $SRC/dng_fixed_validate_fuzzer.tmp $SRC/dng_fixed_validate_fuzzer.cpp
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE -DqDNGValidateTarget \
  $SRC/dng_sdk/source/dng_globals.cpp \
  $SRC/dng_fixed_validate_fuzzer.cpp \
  -o $OUT/dng_fixed_validate_fuzzer \
  ./libdns_sdk.a -I./ -l:libjpeg.a -lz
```
3. Run the fuzzer to trigger the segmentation fault: 
[FindTileSize-fpe](https://github.com/sae-as-me/Crashes/raw/refs/heads/main/dng_sdk/FindTileSize-fpe)
```
./dng_fixed_validate_fuzzer ./FindTileSize-fpe
```
This will cause AddressSanitizer to report a segmentation fault during the execution of the post-processing logic.
### ASAN Report
```sh
Running: ./FindTileSize-fpe
Raw image read time: 0.000 sec
AddressSanitizer:DEADLYSIGNAL
=================================================================
==7850==ERROR: AddressSanitizer: FPE on unknown address 0x648d3adf2f47 (pc 0x648d3adf2f47 bp 0x7ffff166e470 sp 0x7ffff166dfc0 T0)
    #0 0x648d3adf2f47 in dng_area_task::FindTileSize(dng_rect const&) const /fuzz/project/dng_sdk/source/./dng_area_task.cpp:145:45
    #1 0x648d3adf47d3 in dng_area_task::Perform(dng_area_task&, dng_rect const&, dng_memory_allocator*, dng_abort_sniffer*) /fuzz/project/dng_sdk/source/./dng_area_task.cpp:260:27
    #2 0x648d3aca1e41 in dng_host::PerformAreaTask(dng_area_task&, dng_rect const&) /fuzz/project/dng_sdk/source/./dng_host.cpp:238:2
    #3 0x648d3ae51d7b in dng_jpeg_image::FindDigest(dng_host&) const /fuzz/project/dng_sdk/source/./dng_jpeg_image.cpp:345:8
    #4 0x648d3ad515fd in dng_negative::FindRawJPEGImageDigest(dng_host&) const /fuzz/project/dng_sdk/source/./dng_negative.cpp:3578:41
    #5 0x648d3ad50f68 in dng_negative::ValidateRawImageDigest(dng_host&) /fuzz/project/dng_sdk/source/./dng_negative.cpp:1902:4
    #6 0x648d3ac8e30d in dng_validate(char const*) /fuzz/project/dng_fixed_validate_fuzzer.cpp:167:14
    #7 0x648d3ac9643a in LLVMFuzzerTestOneInput /fuzz/project/dng_fixed_validate_fuzzer.cpp:976:3
    #8 0x648d3abb39b3 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/fuzz/fuzzers/dng_fixed_validate_fuzzer+0x5e9b3) (BuildId: ca1fe9f1ffe2b7bbb31494efae49bd58003bcf07)
    #9 0x648d3ab9d72f in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) (/fuzz/fuzzers/dng_fixed_validate_fuzzer+0x4872f) (BuildId: ca1fe9f1ffe2b7bbb31494efae49bd58003bcf07)
    #10 0x648d3aba3486 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) (/fuzz/fuzzers/dng_fixed_validate_fuzzer+0x4e486) (BuildId: ca1fe9f1ffe2b7bbb31494efae49bd58003bcf07)
    #11 0x648d3abcd2a2 in main (/fuzz/fuzzers/dng_fixed_validate_fuzzer+0x782a2) (BuildId: ca1fe9f1ffe2b7bbb31494efae49bd58003bcf07)
    #12 0x752bd4b34d8f in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #13 0x752bd4b34e3f in __libc_start_main csu/../csu/libc-start.c:392:3
    #14 0x648d3ab97ff4 in _start (/fuzz/fuzzers/dng_fixed_validate_fuzzer+0x42ff4) (BuildId: ca1fe9f1ffe2b7bbb31494efae49bd58003bcf07)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: FPE /fuzz/project/dng_sdk/source/./dng_area_task.cpp:145:45 in dng_area_task::FindTileSize(dng_rect const&) const
==7850==ABORTING
```
