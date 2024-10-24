
/*
 * 26 128-bytes blocks, 521 pointers.
 * 14920 bytes on 32-bit platforms, 17000 bytes on 64-bit platforms.
 */

#define NXT_UNICODE_MAX_LOWCASE 0x10427

#define NXT_UNICODE_BLOCK_SIZE 128

static const uint32_t nxt_unicode_block_000[128] nxt_aligned(64) = {
    0x00000, 0x00001, 0x00002, 0x00003, 0x00004, 0x00005, 0x00006, 0x00007, 0x00008, 0x00009, 0x0000A, 0x0000B, 0x0000C,
    0x0000D, 0x0000E, 0x0000F, 0x00010, 0x00011, 0x00012, 0x00013, 0x00014, 0x00015, 0x00016, 0x00017, 0x00018, 0x00019,
    0x0001A, 0x0001B, 0x0001C, 0x0001D, 0x0001E, 0x0001F, 0x00020, 0x00021, 0x00022, 0x00023, 0x00024, 0x00025, 0x00026,
    0x00027, 0x00028, 0x00029, 0x0002A, 0x0002B, 0x0002C, 0x0002D, 0x0002E, 0x0002F, 0x00030, 0x00031, 0x00032, 0x00033,
    0x00034, 0x00035, 0x00036, 0x00037, 0x00038, 0x00039, 0x0003A, 0x0003B, 0x0003C, 0x0003D, 0x0003E, 0x0003F, 0x00040,
    0x00061, 0x00062, 0x00063, 0x00064, 0x00065, 0x00066, 0x00067, 0x00068, 0x00069, 0x0006A, 0x0006B, 0x0006C, 0x0006D,
    0x0006E, 0x0006F, 0x00070, 0x00071, 0x00072, 0x00073, 0x00074, 0x00075, 0x00076, 0x00077, 0x00078, 0x00079, 0x0007A,
    0x0005B, 0x0005C, 0x0005D, 0x0005E, 0x0005F, 0x00060, 0x00061, 0x00062, 0x00063, 0x00064, 0x00065, 0x00066, 0x00067,
    0x00068, 0x00069, 0x0006A, 0x0006B, 0x0006C, 0x0006D, 0x0006E, 0x0006F, 0x00070, 0x00071, 0x00072, 0x00073, 0x00074,
    0x00075, 0x00076, 0x00077, 0x00078, 0x00079, 0x0007A, 0x0007B, 0x0007C, 0x0007D, 0x0007E, 0x0007F,
};

static const uint32_t nxt_unicode_block_001[128] nxt_aligned(64) = {
    0x00080, 0x00081, 0x00082, 0x00083, 0x00084, 0x00085, 0x00086, 0x00087, 0x00088, 0x00089, 0x0008A, 0x0008B, 0x0008C,
    0x0008D, 0x0008E, 0x0008F, 0x00090, 0x00091, 0x00092, 0x00093, 0x00094, 0x00095, 0x00096, 0x00097, 0x00098, 0x00099,
    0x0009A, 0x0009B, 0x0009C, 0x0009D, 0x0009E, 0x0009F, 0x000A0, 0x000A1, 0x000A2, 0x000A3, 0x000A4, 0x000A5, 0x000A6,
    0x000A7, 0x000A8, 0x000A9, 0x000AA, 0x000AB, 0x000AC, 0x000AD, 0x000AE, 0x000AF, 0x000B0, 0x000B1, 0x000B2, 0x000B3,
    0x000B4, 0x003BC, 0x000B6, 0x000B7, 0x000B8, 0x000B9, 0x000BA, 0x000BB, 0x000BC, 0x000BD, 0x000BE, 0x000BF, 0x000E0,
    0x000E1, 0x000E2, 0x000E3, 0x000E4, 0x000E5, 0x000E6, 0x000E7, 0x000E8, 0x000E9, 0x000EA, 0x000EB, 0x000EC, 0x000ED,
    0x000EE, 0x000EF, 0x000F0, 0x000F1, 0x000F2, 0x000F3, 0x000F4, 0x000F5, 0x000F6, 0x000D7, 0x000F8, 0x000F9, 0x000FA,
    0x000FB, 0x000FC, 0x000FD, 0x000FE, 0x000DF, 0x000E0, 0x000E1, 0x000E2, 0x000E3, 0x000E4, 0x000E5, 0x000E6, 0x000E7,
    0x000E8, 0x000E9, 0x000EA, 0x000EB, 0x000EC, 0x000ED, 0x000EE, 0x000EF, 0x000F0, 0x000F1, 0x000F2, 0x000F3, 0x000F4,
    0x000F5, 0x000F6, 0x000F7, 0x000F8, 0x000F9, 0x000FA, 0x000FB, 0x000FC, 0x000FD, 0x000FE, 0x000FF,
};

static const uint32_t nxt_unicode_block_002[128] nxt_aligned(64) = {
    0x00101, 0x00101, 0x00103, 0x00103, 0x00105, 0x00105, 0x00107, 0x00107, 0x00109, 0x00109, 0x0010B, 0x0010B, 0x0010D,
    0x0010D, 0x0010F, 0x0010F, 0x00111, 0x00111, 0x00113, 0x00113, 0x00115, 0x00115, 0x00117, 0x00117, 0x00119, 0x00119,
    0x0011B, 0x0011B, 0x0011D, 0x0011D, 0x0011F, 0x0011F, 0x00121, 0x00121, 0x00123, 0x00123, 0x00125, 0x00125, 0x00127,
    0x00127, 0x00129, 0x00129, 0x0012B, 0x0012B, 0x0012D, 0x0012D, 0x0012F, 0x0012F, 0x00130, 0x00131, 0x00133, 0x00133,
    0x00135, 0x00135, 0x00137, 0x00137, 0x00138, 0x0013A, 0x0013A, 0x0013C, 0x0013C, 0x0013E, 0x0013E, 0x00140, 0x00140,
    0x00142, 0x00142, 0x00144, 0x00144, 0x00146, 0x00146, 0x00148, 0x00148, 0x00149, 0x0014B, 0x0014B, 0x0014D, 0x0014D,
    0x0014F, 0x0014F, 0x00151, 0x00151, 0x00153, 0x00153, 0x00155, 0x00155, 0x00157, 0x00157, 0x00159, 0x00159, 0x0015B,
    0x0015B, 0x0015D, 0x0015D, 0x0015F, 0x0015F, 0x00161, 0x00161, 0x00163, 0x00163, 0x00165, 0x00165, 0x00167, 0x00167,
    0x00169, 0x00169, 0x0016B, 0x0016B, 0x0016D, 0x0016D, 0x0016F, 0x0016F, 0x00171, 0x00171, 0x00173, 0x00173, 0x00175,
    0x00175, 0x00177, 0x00177, 0x000FF, 0x0017A, 0x0017A, 0x0017C, 0x0017C, 0x0017E, 0x0017E, 0x00073,
};

static const uint32_t nxt_unicode_block_003[128] nxt_aligned(64) = {
    0x00180, 0x00253, 0x00183, 0x00183, 0x00185, 0x00185, 0x00254, 0x00188, 0x00188, 0x00256, 0x00257, 0x0018C, 0x0018C,
    0x0018D, 0x001DD, 0x00259, 0x0025B, 0x00192, 0x00192, 0x00260, 0x00263, 0x00195, 0x00269, 0x00268, 0x00199, 0x00199,
    0x0019A, 0x0019B, 0x0026F, 0x00272, 0x0019E, 0x00275, 0x001A1, 0x001A1, 0x001A3, 0x001A3, 0x001A5, 0x001A5, 0x00280,
    0x001A8, 0x001A8, 0x00283, 0x001AA, 0x001AB, 0x001AD, 0x001AD, 0x00288, 0x001B0, 0x001B0, 0x0028A, 0x0028B, 0x001B4,
    0x001B4, 0x001B6, 0x001B6, 0x00292, 0x001B9, 0x001B9, 0x001BA, 0x001BB, 0x001BD, 0x001BD, 0x001BE, 0x001BF, 0x001C0,
    0x001C1, 0x001C2, 0x001C3, 0x001C6, 0x001C6, 0x001C6, 0x001C9, 0x001C9, 0x001C9, 0x001CC, 0x001CC, 0x001CC, 0x001CE,
    0x001CE, 0x001D0, 0x001D0, 0x001D2, 0x001D2, 0x001D4, 0x001D4, 0x001D6, 0x001D6, 0x001D8, 0x001D8, 0x001DA, 0x001DA,
    0x001DC, 0x001DC, 0x001DD, 0x001DF, 0x001DF, 0x001E1, 0x001E1, 0x001E3, 0x001E3, 0x001E5, 0x001E5, 0x001E7, 0x001E7,
    0x001E9, 0x001E9, 0x001EB, 0x001EB, 0x001ED, 0x001ED, 0x001EF, 0x001EF, 0x001F0, 0x001F3, 0x001F3, 0x001F3, 0x001F5,
    0x001F5, 0x00195, 0x001BF, 0x001F9, 0x001F9, 0x001FB, 0x001FB, 0x001FD, 0x001FD, 0x001FF, 0x001FF,
};

static const uint32_t nxt_unicode_block_004[128] nxt_aligned(64) = {
    0x00201, 0x00201, 0x00203, 0x00203, 0x00205, 0x00205, 0x00207, 0x00207, 0x00209, 0x00209, 0x0020B, 0x0020B, 0x0020D,
    0x0020D, 0x0020F, 0x0020F, 0x00211, 0x00211, 0x00213, 0x00213, 0x00215, 0x00215, 0x00217, 0x00217, 0x00219, 0x00219,
    0x0021B, 0x0021B, 0x0021D, 0x0021D, 0x0021F, 0x0021F, 0x0019E, 0x00221, 0x00223, 0x00223, 0x00225, 0x00225, 0x00227,
    0x00227, 0x00229, 0x00229, 0x0022B, 0x0022B, 0x0022D, 0x0022D, 0x0022F, 0x0022F, 0x00231, 0x00231, 0x00233, 0x00233,
    0x00234, 0x00235, 0x00236, 0x00237, 0x00238, 0x00239, 0x02C65, 0x0023C, 0x0023C, 0x0019A, 0x02C66, 0x0023F, 0x00240,
    0x00242, 0x00242, 0x00180, 0x00289, 0x0028C, 0x00247, 0x00247, 0x00249, 0x00249, 0x0024B, 0x0024B, 0x0024D, 0x0024D,
    0x0024F, 0x0024F, 0x00250, 0x00251, 0x00252, 0x00253, 0x00254, 0x00255, 0x00256, 0x00257, 0x00258, 0x00259, 0x0025A,
    0x0025B, 0x0025C, 0x0025D, 0x0025E, 0x0025F, 0x00260, 0x00261, 0x00262, 0x00263, 0x00264, 0x00265, 0x00266, 0x00267,
    0x00268, 0x00269, 0x0026A, 0x0026B, 0x0026C, 0x0026D, 0x0026E, 0x0026F, 0x00270, 0x00271, 0x00272, 0x00273, 0x00274,
    0x00275, 0x00276, 0x00277, 0x00278, 0x00279, 0x0027A, 0x0027B, 0x0027C, 0x0027D, 0x0027E, 0x0027F,
};

static const uint32_t nxt_unicode_block_006[128] nxt_aligned(64) = {
    0x00300, 0x00301, 0x00302, 0x00303, 0x00304, 0x00305, 0x00306, 0x00307, 0x00308, 0x00309, 0x0030A, 0x0030B, 0x0030C,
    0x0030D, 0x0030E, 0x0030F, 0x00310, 0x00311, 0x00312, 0x00313, 0x00314, 0x00315, 0x00316, 0x00317, 0x00318, 0x00319,
    0x0031A, 0x0031B, 0x0031C, 0x0031D, 0x0031E, 0x0031F, 0x00320, 0x00321, 0x00322, 0x00323, 0x00324, 0x00325, 0x00326,
    0x00327, 0x00328, 0x00329, 0x0032A, 0x0032B, 0x0032C, 0x0032D, 0x0032E, 0x0032F, 0x00330, 0x00331, 0x00332, 0x00333,
    0x00334, 0x00335, 0x00336, 0x00337, 0x00338, 0x00339, 0x0033A, 0x0033B, 0x0033C, 0x0033D, 0x0033E, 0x0033F, 0x00340,
    0x00341, 0x00342, 0x00343, 0x00344, 0x003B9, 0x00346, 0x00347, 0x00348, 0x00349, 0x0034A, 0x0034B, 0x0034C, 0x0034D,
    0x0034E, 0x0034F, 0x00350, 0x00351, 0x00352, 0x00353, 0x00354, 0x00355, 0x00356, 0x00357, 0x00358, 0x00359, 0x0035A,
    0x0035B, 0x0035C, 0x0035D, 0x0035E, 0x0035F, 0x00360, 0x00361, 0x00362, 0x00363, 0x00364, 0x00365, 0x00366, 0x00367,
    0x00368, 0x00369, 0x0036A, 0x0036B, 0x0036C, 0x0036D, 0x0036E, 0x0036F, 0x00371, 0x00371, 0x00373, 0x00373, 0x00374,
    0x00375, 0x00377, 0x00377, 0x00378, 0x00379, 0x0037A, 0x0037B, 0x0037C, 0x0037D, 0x0037E, 0x0037F,
};

static const uint32_t nxt_unicode_block_007[128] nxt_aligned(64) = {
    0x00380, 0x00381, 0x00382, 0x00383, 0x00384, 0x00385, 0x003AC, 0x00387, 0x003AD, 0x003AE, 0x003AF, 0x0038B, 0x003CC,
    0x0038D, 0x003CD, 0x003CE, 0x00390, 0x003B1, 0x003B2, 0x003B3, 0x003B4, 0x003B5, 0x003B6, 0x003B7, 0x003B8, 0x003B9,
    0x003BA, 0x003BB, 0x003BC, 0x003BD, 0x003BE, 0x003BF, 0x003C0, 0x003C1, 0x003A2, 0x003C3, 0x003C4, 0x003C5, 0x003C6,
    0x003C7, 0x003C8, 0x003C9, 0x003CA, 0x003CB, 0x003AC, 0x003AD, 0x003AE, 0x003AF, 0x003B0, 0x003B1, 0x003B2, 0x003B3,
    0x003B4, 0x003B5, 0x003B6, 0x003B7, 0x003B8, 0x003B9, 0x003BA, 0x003BB, 0x003BC, 0x003BD, 0x003BE, 0x003BF, 0x003C0,
    0x003C1, 0x003C3, 0x003C3, 0x003C4, 0x003C5, 0x003C6, 0x003C7, 0x003C8, 0x003C9, 0x003CA, 0x003CB, 0x003CC, 0x003CD,
    0x003CE, 0x003D7, 0x003B2, 0x003B8, 0x003D2, 0x003D3, 0x003D4, 0x003C6, 0x003C0, 0x003D7, 0x003D9, 0x003D9, 0x003DB,
    0x003DB, 0x003DD, 0x003DD, 0x003DF, 0x003DF, 0x003E1, 0x003E1, 0x003E3, 0x003E3, 0x003E5, 0x003E5, 0x003E7, 0x003E7,
    0x003E9, 0x003E9, 0x003EB, 0x003EB, 0x003ED, 0x003ED, 0x003EF, 0x003EF, 0x003BA, 0x003C1, 0x003F2, 0x003F3, 0x003B8,
    0x003B5, 0x003F6, 0x003F8, 0x003F8, 0x003F2, 0x003FB, 0x003FB, 0x003FC, 0x0037B, 0x0037C, 0x0037D,
};

static const uint32_t nxt_unicode_block_008[128] nxt_aligned(64) = {
    0x00450, 0x00451, 0x00452, 0x00453, 0x00454, 0x00455, 0x00456, 0x00457, 0x00458, 0x00459, 0x0045A, 0x0045B, 0x0045C,
    0x0045D, 0x0045E, 0x0045F, 0x00430, 0x00431, 0x00432, 0x00433, 0x00434, 0x00435, 0x00436, 0x00437, 0x00438, 0x00439,
    0x0043A, 0x0043B, 0x0043C, 0x0043D, 0x0043E, 0x0043F, 0x00440, 0x00441, 0x00442, 0x00443, 0x00444, 0x00445, 0x00446,
    0x00447, 0x00448, 0x00449, 0x0044A, 0x0044B, 0x0044C, 0x0044D, 0x0044E, 0x0044F, 0x00430, 0x00431, 0x00432, 0x00433,
    0x00434, 0x00435, 0x00436, 0x00437, 0x00438, 0x00439, 0x0043A, 0x0043B, 0x0043C, 0x0043D, 0x0043E, 0x0043F, 0x00440,
    0x00441, 0x00442, 0x00443, 0x00444, 0x00445, 0x00446, 0x00447, 0x00448, 0x00449, 0x0044A, 0x0044B, 0x0044C, 0x0044D,
    0x0044E, 0x0044F, 0x00450, 0x00451, 0x00452, 0x00453, 0x00454, 0x00455, 0x00456, 0x00457, 0x00458, 0x00459, 0x0045A,
    0x0045B, 0x0045C, 0x0045D, 0x0045E, 0x0045F, 0x00461, 0x00461, 0x00463, 0x00463, 0x00465, 0x00465, 0x00467, 0x00467,
    0x00469, 0x00469, 0x0046B, 0x0046B, 0x0046D, 0x0046D, 0x0046F, 0x0046F, 0x00471, 0x00471, 0x00473, 0x00473, 0x00475,
    0x00475, 0x00477, 0x00477, 0x00479, 0x00479, 0x0047B, 0x0047B, 0x0047D, 0x0047D, 0x0047F, 0x0047F,
};

static const uint32_t nxt_unicode_block_009[128] nxt_aligned(64) = {
    0x00481, 0x00481, 0x00482, 0x00483, 0x00484, 0x00485, 0x00486, 0x00487, 0x00488, 0x00489, 0x0048B, 0x0048B, 0x0048D,
    0x0048D, 0x0048F, 0x0048F, 0x00491, 0x00491, 0x00493, 0x00493, 0x00495, 0x00495, 0x00497, 0x00497, 0x00499, 0x00499,
    0x0049B, 0x0049B, 0x0049D, 0x0049D, 0x0049F, 0x0049F, 0x004A1, 0x004A1, 0x004A3, 0x004A3, 0x004A5, 0x004A5, 0x004A7,
    0x004A7, 0x004A9, 0x004A9, 0x004AB, 0x004AB, 0x004AD, 0x004AD, 0x004AF, 0x004AF, 0x004B1, 0x004B1, 0x004B3, 0x004B3,
    0x004B5, 0x004B5, 0x004B7, 0x004B7, 0x004B9, 0x004B9, 0x004BB, 0x004BB, 0x004BD, 0x004BD, 0x004BF, 0x004BF, 0x004CF,
    0x004C2, 0x004C2, 0x004C4, 0x004C4, 0x004C6, 0x004C6, 0x004C8, 0x004C8, 0x004CA, 0x004CA, 0x004CC, 0x004CC, 0x004CE,
    0x004CE, 0x004CF, 0x004D1, 0x004D1, 0x004D3, 0x004D3, 0x004D5, 0x004D5, 0x004D7, 0x004D7, 0x004D9, 0x004D9, 0x004DB,
    0x004DB, 0x004DD, 0x004DD, 0x004DF, 0x004DF, 0x004E1, 0x004E1, 0x004E3, 0x004E3, 0x004E5, 0x004E5, 0x004E7, 0x004E7,
    0x004E9, 0x004E9, 0x004EB, 0x004EB, 0x004ED, 0x004ED, 0x004EF, 0x004EF, 0x004F1, 0x004F1, 0x004F3, 0x004F3, 0x004F5,
    0x004F5, 0x004F7, 0x004F7, 0x004F9, 0x004F9, 0x004FB, 0x004FB, 0x004FD, 0x004FD, 0x004FF, 0x004FF,
};

static const uint32_t nxt_unicode_block_00a[128] nxt_aligned(64) = {
    0x00501, 0x00501, 0x00503, 0x00503, 0x00505, 0x00505, 0x00507, 0x00507, 0x00509, 0x00509, 0x0050B, 0x0050B, 0x0050D,
    0x0050D, 0x0050F, 0x0050F, 0x00511, 0x00511, 0x00513, 0x00513, 0x00515, 0x00515, 0x00517, 0x00517, 0x00519, 0x00519,
    0x0051B, 0x0051B, 0x0051D, 0x0051D, 0x0051F, 0x0051F, 0x00521, 0x00521, 0x00523, 0x00523, 0x00525, 0x00525, 0x00527,
    0x00527, 0x00528, 0x00529, 0x0052A, 0x0052B, 0x0052C, 0x0052D, 0x0052E, 0x0052F, 0x00530, 0x00561, 0x00562, 0x00563,
    0x00564, 0x00565, 0x00566, 0x00567, 0x00568, 0x00569, 0x0056A, 0x0056B, 0x0056C, 0x0056D, 0x0056E, 0x0056F, 0x00570,
    0x00571, 0x00572, 0x00573, 0x00574, 0x00575, 0x00576, 0x00577, 0x00578, 0x00579, 0x0057A, 0x0057B, 0x0057C, 0x0057D,
    0x0057E, 0x0057F, 0x00580, 0x00581, 0x00582, 0x00583, 0x00584, 0x00585, 0x00586, 0x00557, 0x00558, 0x00559, 0x0055A,
    0x0055B, 0x0055C, 0x0055D, 0x0055E, 0x0055F, 0x00560, 0x00561, 0x00562, 0x00563, 0x00564, 0x00565, 0x00566, 0x00567,
    0x00568, 0x00569, 0x0056A, 0x0056B, 0x0056C, 0x0056D, 0x0056E, 0x0056F, 0x00570, 0x00571, 0x00572, 0x00573, 0x00574,
    0x00575, 0x00576, 0x00577, 0x00578, 0x00579, 0x0057A, 0x0057B, 0x0057C, 0x0057D, 0x0057E, 0x0057F,
};

static const uint32_t nxt_unicode_block_021[128] nxt_aligned(64) = {
    0x01080, 0x01081, 0x01082, 0x01083, 0x01084, 0x01085, 0x01086, 0x01087, 0x01088, 0x01089, 0x0108A, 0x0108B, 0x0108C,
    0x0108D, 0x0108E, 0x0108F, 0x01090, 0x01091, 0x01092, 0x01093, 0x01094, 0x01095, 0x01096, 0x01097, 0x01098, 0x01099,
    0x0109A, 0x0109B, 0x0109C, 0x0109D, 0x0109E, 0x0109F, 0x02D00, 0x02D01, 0x02D02, 0x02D03, 0x02D04, 0x02D05, 0x02D06,
    0x02D07, 0x02D08, 0x02D09, 0x02D0A, 0x02D0B, 0x02D0C, 0x02D0D, 0x02D0E, 0x02D0F, 0x02D10, 0x02D11, 0x02D12, 0x02D13,
    0x02D14, 0x02D15, 0x02D16, 0x02D17, 0x02D18, 0x02D19, 0x02D1A, 0x02D1B, 0x02D1C, 0x02D1D, 0x02D1E, 0x02D1F, 0x02D20,
    0x02D21, 0x02D22, 0x02D23, 0x02D24, 0x02D25, 0x010C6, 0x02D27, 0x010C8, 0x010C9, 0x010CA, 0x010CB, 0x010CC, 0x02D2D,
    0x010CE, 0x010CF, 0x010D0, 0x010D1, 0x010D2, 0x010D3, 0x010D4, 0x010D5, 0x010D6, 0x010D7, 0x010D8, 0x010D9, 0x010DA,
    0x010DB, 0x010DC, 0x010DD, 0x010DE, 0x010DF, 0x010E0, 0x010E1, 0x010E2, 0x010E3, 0x010E4, 0x010E5, 0x010E6, 0x010E7,
    0x010E8, 0x010E9, 0x010EA, 0x010EB, 0x010EC, 0x010ED, 0x010EE, 0x010EF, 0x010F0, 0x010F1, 0x010F2, 0x010F3, 0x010F4,
    0x010F5, 0x010F6, 0x010F7, 0x010F8, 0x010F9, 0x010FA, 0x010FB, 0x010FC, 0x010FD, 0x010FE, 0x010FF,
};

static const uint32_t nxt_unicode_block_03c[128] nxt_aligned(64) = {
    0x01E01, 0x01E01, 0x01E03, 0x01E03, 0x01E05, 0x01E05, 0x01E07, 0x01E07, 0x01E09, 0x01E09, 0x01E0B, 0x01E0B, 0x01E0D,
    0x01E0D, 0x01E0F, 0x01E0F, 0x01E11, 0x01E11, 0x01E13, 0x01E13, 0x01E15, 0x01E15, 0x01E17, 0x01E17, 0x01E19, 0x01E19,
    0x01E1B, 0x01E1B, 0x01E1D, 0x01E1D, 0x01E1F, 0x01E1F, 0x01E21, 0x01E21, 0x01E23, 0x01E23, 0x01E25, 0x01E25, 0x01E27,
    0x01E27, 0x01E29, 0x01E29, 0x01E2B, 0x01E2B, 0x01E2D, 0x01E2D, 0x01E2F, 0x01E2F, 0x01E31, 0x01E31, 0x01E33, 0x01E33,
    0x01E35, 0x01E35, 0x01E37, 0x01E37, 0x01E39, 0x01E39, 0x01E3B, 0x01E3B, 0x01E3D, 0x01E3D, 0x01E3F, 0x01E3F, 0x01E41,
    0x01E41, 0x01E43, 0x01E43, 0x01E45, 0x01E45, 0x01E47, 0x01E47, 0x01E49, 0x01E49, 0x01E4B, 0x01E4B, 0x01E4D, 0x01E4D,
    0x01E4F, 0x01E4F, 0x01E51, 0x01E51, 0x01E53, 0x01E53, 0x01E55, 0x01E55, 0x01E57, 0x01E57, 0x01E59, 0x01E59, 0x01E5B,
    0x01E5B, 0x01E5D, 0x01E5D, 0x01E5F, 0x01E5F, 0x01E61, 0x01E61, 0x01E63, 0x01E63, 0x01E65, 0x01E65, 0x01E67, 0x01E67,
    0x01E69, 0x01E69, 0x01E6B, 0x01E6B, 0x01E6D, 0x01E6D, 0x01E6F, 0x01E6F, 0x01E71, 0x01E71, 0x01E73, 0x01E73, 0x01E75,
    0x01E75, 0x01E77, 0x01E77, 0x01E79, 0x01E79, 0x01E7B, 0x01E7B, 0x01E7D, 0x01E7D, 0x01E7F, 0x01E7F,
};

static const uint32_t nxt_unicode_block_03d[128] nxt_aligned(64) = {
    0x01E81, 0x01E81, 0x01E83, 0x01E83, 0x01E85, 0x01E85, 0x01E87, 0x01E87, 0x01E89, 0x01E89, 0x01E8B, 0x01E8B, 0x01E8D,
    0x01E8D, 0x01E8F, 0x01E8F, 0x01E91, 0x01E91, 0x01E93, 0x01E93, 0x01E95, 0x01E95, 0x01E96, 0x01E97, 0x01E98, 0x01E99,
    0x01E9A, 0x01E61, 0x01E9C, 0x01E9D, 0x000DF, 0x01E9F, 0x01EA1, 0x01EA1, 0x01EA3, 0x01EA3, 0x01EA5, 0x01EA5, 0x01EA7,
    0x01EA7, 0x01EA9, 0x01EA9, 0x01EAB, 0x01EAB, 0x01EAD, 0x01EAD, 0x01EAF, 0x01EAF, 0x01EB1, 0x01EB1, 0x01EB3, 0x01EB3,
    0x01EB5, 0x01EB5, 0x01EB7, 0x01EB7, 0x01EB9, 0x01EB9, 0x01EBB, 0x01EBB, 0x01EBD, 0x01EBD, 0x01EBF, 0x01EBF, 0x01EC1,
    0x01EC1, 0x01EC3, 0x01EC3, 0x01EC5, 0x01EC5, 0x01EC7, 0x01EC7, 0x01EC9, 0x01EC9, 0x01ECB, 0x01ECB, 0x01ECD, 0x01ECD,
    0x01ECF, 0x01ECF, 0x01ED1, 0x01ED1, 0x01ED3, 0x01ED3, 0x01ED5, 0x01ED5, 0x01ED7, 0x01ED7, 0x01ED9, 0x01ED9, 0x01EDB,
    0x01EDB, 0x01EDD, 0x01EDD, 0x01EDF, 0x01EDF, 0x01EE1, 0x01EE1, 0x01EE3, 0x01EE3, 0x01EE5, 0x01EE5, 0x01EE7, 0x01EE7,
    0x01EE9, 0x01EE9, 0x01EEB, 0x01EEB, 0x01EED, 0x01EED, 0x01EEF, 0x01EEF, 0x01EF1, 0x01EF1, 0x01EF3, 0x01EF3, 0x01EF5,
    0x01EF5, 0x01EF7, 0x01EF7, 0x01EF9, 0x01EF9, 0x01EFB, 0x01EFB, 0x01EFD, 0x01EFD, 0x01EFF, 0x01EFF,
};

static const uint32_t nxt_unicode_block_03e[128] nxt_aligned(64) = {
    0x01F00, 0x01F01, 0x01F02, 0x01F03, 0x01F04, 0x01F05, 0x01F06, 0x01F07, 0x01F00, 0x01F01, 0x01F02, 0x01F03, 0x01F04,
    0x01F05, 0x01F06, 0x01F07, 0x01F10, 0x01F11, 0x01F12, 0x01F13, 0x01F14, 0x01F15, 0x01F16, 0x01F17, 0x01F10, 0x01F11,
    0x01F12, 0x01F13, 0x01F14, 0x01F15, 0x01F1E, 0x01F1F, 0x01F20, 0x01F21, 0x01F22, 0x01F23, 0x01F24, 0x01F25, 0x01F26,
    0x01F27, 0x01F20, 0x01F21, 0x01F22, 0x01F23, 0x01F24, 0x01F25, 0x01F26, 0x01F27, 0x01F30, 0x01F31, 0x01F32, 0x01F33,
    0x01F34, 0x01F35, 0x01F36, 0x01F37, 0x01F30, 0x01F31, 0x01F32, 0x01F33, 0x01F34, 0x01F35, 0x01F36, 0x01F37, 0x01F40,
    0x01F41, 0x01F42, 0x01F43, 0x01F44, 0x01F45, 0x01F46, 0x01F47, 0x01F40, 0x01F41, 0x01F42, 0x01F43, 0x01F44, 0x01F45,
    0x01F4E, 0x01F4F, 0x01F50, 0x01F51, 0x01F52, 0x01F53, 0x01F54, 0x01F55, 0x01F56, 0x01F57, 0x01F58, 0x01F51, 0x01F5A,
    0x01F53, 0x01F5C, 0x01F55, 0x01F5E, 0x01F57, 0x01F60, 0x01F61, 0x01F62, 0x01F63, 0x01F64, 0x01F65, 0x01F66, 0x01F67,
    0x01F60, 0x01F61, 0x01F62, 0x01F63, 0x01F64, 0x01F65, 0x01F66, 0x01F67, 0x01F70, 0x01F71, 0x01F72, 0x01F73, 0x01F74,
    0x01F75, 0x01F76, 0x01F77, 0x01F78, 0x01F79, 0x01F7A, 0x01F7B, 0x01F7C, 0x01F7D, 0x01F7E, 0x01F7F,
};

static const uint32_t nxt_unicode_block_03f[128] nxt_aligned(64) = {
    0x01F80, 0x01F81, 0x01F82, 0x01F83, 0x01F84, 0x01F85, 0x01F86, 0x01F87, 0x01F80, 0x01F81, 0x01F82, 0x01F83, 0x01F84,
    0x01F85, 0x01F86, 0x01F87, 0x01F90, 0x01F91, 0x01F92, 0x01F93, 0x01F94, 0x01F95, 0x01F96, 0x01F97, 0x01F90, 0x01F91,
    0x01F92, 0x01F93, 0x01F94, 0x01F95, 0x01F96, 0x01F97, 0x01FA0, 0x01FA1, 0x01FA2, 0x01FA3, 0x01FA4, 0x01FA5, 0x01FA6,
    0x01FA7, 0x01FA0, 0x01FA1, 0x01FA2, 0x01FA3, 0x01FA4, 0x01FA5, 0x01FA6, 0x01FA7, 0x01FB0, 0x01FB1, 0x01FB2, 0x01FB3,
    0x01FB4, 0x01FB5, 0x01FB6, 0x01FB7, 0x01FB0, 0x01FB1, 0x01F70, 0x01F71, 0x01FB3, 0x01FBD, 0x003B9, 0x01FBF, 0x01FC0,
    0x01FC1, 0x01FC2, 0x01FC3, 0x01FC4, 0x01FC5, 0x01FC6, 0x01FC7, 0x01F72, 0x01F73, 0x01F74, 0x01F75, 0x01FC3, 0x01FCD,
    0x01FCE, 0x01FCF, 0x01FD0, 0x01FD1, 0x01FD2, 0x01FD3, 0x01FD4, 0x01FD5, 0x01FD6, 0x01FD7, 0x01FD0, 0x01FD1, 0x01F76,
    0x01F77, 0x01FDC, 0x01FDD, 0x01FDE, 0x01FDF, 0x01FE0, 0x01FE1, 0x01FE2, 0x01FE3, 0x01FE4, 0x01FE5, 0x01FE6, 0x01FE7,
    0x01FE0, 0x01FE1, 0x01F7A, 0x01F7B, 0x01FE5, 0x01FED, 0x01FEE, 0x01FEF, 0x01FF0, 0x01FF1, 0x01FF2, 0x01FF3, 0x01FF4,
    0x01FF5, 0x01FF6, 0x01FF7, 0x01F78, 0x01F79, 0x01F7C, 0x01F7D, 0x01FF3, 0x01FFD, 0x01FFE, 0x01FFF,
};

static const uint32_t nxt_unicode_block_042[128] nxt_aligned(64) = {
    0x02100, 0x02101, 0x02102, 0x02103, 0x02104, 0x02105, 0x02106, 0x02107, 0x02108, 0x02109, 0x0210A, 0x0210B, 0x0210C,
    0x0210D, 0x0210E, 0x0210F, 0x02110, 0x02111, 0x02112, 0x02113, 0x02114, 0x02115, 0x02116, 0x02117, 0x02118, 0x02119,
    0x0211A, 0x0211B, 0x0211C, 0x0211D, 0x0211E, 0x0211F, 0x02120, 0x02121, 0x02122, 0x02123, 0x02124, 0x02125, 0x003C9,
    0x02127, 0x02128, 0x02129, 0x0006B, 0x000E5, 0x0212C, 0x0212D, 0x0212E, 0x0212F, 0x02130, 0x02131, 0x0214E, 0x02133,
    0x02134, 0x02135, 0x02136, 0x02137, 0x02138, 0x02139, 0x0213A, 0x0213B, 0x0213C, 0x0213D, 0x0213E, 0x0213F, 0x02140,
    0x02141, 0x02142, 0x02143, 0x02144, 0x02145, 0x02146, 0x02147, 0x02148, 0x02149, 0x0214A, 0x0214B, 0x0214C, 0x0214D,
    0x0214E, 0x0214F, 0x02150, 0x02151, 0x02152, 0x02153, 0x02154, 0x02155, 0x02156, 0x02157, 0x02158, 0x02159, 0x0215A,
    0x0215B, 0x0215C, 0x0215D, 0x0215E, 0x0215F, 0x02170, 0x02171, 0x02172, 0x02173, 0x02174, 0x02175, 0x02176, 0x02177,
    0x02178, 0x02179, 0x0217A, 0x0217B, 0x0217C, 0x0217D, 0x0217E, 0x0217F, 0x02170, 0x02171, 0x02172, 0x02173, 0x02174,
    0x02175, 0x02176, 0x02177, 0x02178, 0x02179, 0x0217A, 0x0217B, 0x0217C, 0x0217D, 0x0217E, 0x0217F,
};

static const uint32_t nxt_unicode_block_043[128] nxt_aligned(64) = {
    0x02180, 0x02181, 0x02182, 0x02184, 0x02184, 0x02185, 0x02186, 0x02187, 0x02188, 0x02189, 0x0218A, 0x0218B, 0x0218C,
    0x0218D, 0x0218E, 0x0218F, 0x02190, 0x02191, 0x02192, 0x02193, 0x02194, 0x02195, 0x02196, 0x02197, 0x02198, 0x02199,
    0x0219A, 0x0219B, 0x0219C, 0x0219D, 0x0219E, 0x0219F, 0x021A0, 0x021A1, 0x021A2, 0x021A3, 0x021A4, 0x021A5, 0x021A6,
    0x021A7, 0x021A8, 0x021A9, 0x021AA, 0x021AB, 0x021AC, 0x021AD, 0x021AE, 0x021AF, 0x021B0, 0x021B1, 0x021B2, 0x021B3,
    0x021B4, 0x021B5, 0x021B6, 0x021B7, 0x021B8, 0x021B9, 0x021BA, 0x021BB, 0x021BC, 0x021BD, 0x021BE, 0x021BF, 0x021C0,
    0x021C1, 0x021C2, 0x021C3, 0x021C4, 0x021C5, 0x021C6, 0x021C7, 0x021C8, 0x021C9, 0x021CA, 0x021CB, 0x021CC, 0x021CD,
    0x021CE, 0x021CF, 0x021D0, 0x021D1, 0x021D2, 0x021D3, 0x021D4, 0x021D5, 0x021D6, 0x021D7, 0x021D8, 0x021D9, 0x021DA,
    0x021DB, 0x021DC, 0x021DD, 0x021DE, 0x021DF, 0x021E0, 0x021E1, 0x021E2, 0x021E3, 0x021E4, 0x021E5, 0x021E6, 0x021E7,
    0x021E8, 0x021E9, 0x021EA, 0x021EB, 0x021EC, 0x021ED, 0x021EE, 0x021EF, 0x021F0, 0x021F1, 0x021F2, 0x021F3, 0x021F4,
    0x021F5, 0x021F6, 0x021F7, 0x021F8, 0x021F9, 0x021FA, 0x021FB, 0x021FC, 0x021FD, 0x021FE, 0x021FF,
};

static const uint32_t nxt_unicode_block_049[128] nxt_aligned(64) = {
    0x02480, 0x02481, 0x02482, 0x02483, 0x02484, 0x02485, 0x02486, 0x02487, 0x02488, 0x02489, 0x0248A, 0x0248B, 0x0248C,
    0x0248D, 0x0248E, 0x0248F, 0x02490, 0x02491, 0x02492, 0x02493, 0x02494, 0x02495, 0x02496, 0x02497, 0x02498, 0x02499,
    0x0249A, 0x0249B, 0x0249C, 0x0249D, 0x0249E, 0x0249F, 0x024A0, 0x024A1, 0x024A2, 0x024A3, 0x024A4, 0x024A5, 0x024A6,
    0x024A7, 0x024A8, 0x024A9, 0x024AA, 0x024AB, 0x024AC, 0x024AD, 0x024AE, 0x024AF, 0x024B0, 0x024B1, 0x024B2, 0x024B3,
    0x024B4, 0x024B5, 0x024D0, 0x024D1, 0x024D2, 0x024D3, 0x024D4, 0x024D5, 0x024D6, 0x024D7, 0x024D8, 0x024D9, 0x024DA,
    0x024DB, 0x024DC, 0x024DD, 0x024DE, 0x024DF, 0x024E0, 0x024E1, 0x024E2, 0x024E3, 0x024E4, 0x024E5, 0x024E6, 0x024E7,
    0x024E8, 0x024E9, 0x024D0, 0x024D1, 0x024D2, 0x024D3, 0x024D4, 0x024D5, 0x024D6, 0x024D7, 0x024D8, 0x024D9, 0x024DA,
    0x024DB, 0x024DC, 0x024DD, 0x024DE, 0x024DF, 0x024E0, 0x024E1, 0x024E2, 0x024E3, 0x024E4, 0x024E5, 0x024E6, 0x024E7,
    0x024E8, 0x024E9, 0x024EA, 0x024EB, 0x024EC, 0x024ED, 0x024EE, 0x024EF, 0x024F0, 0x024F1, 0x024F2, 0x024F3, 0x024F4,
    0x024F5, 0x024F6, 0x024F7, 0x024F8, 0x024F9, 0x024FA, 0x024FB, 0x024FC, 0x024FD, 0x024FE, 0x024FF,
};

static const uint32_t nxt_unicode_block_058[128] nxt_aligned(64) = {
    0x02C30, 0x02C31, 0x02C32, 0x02C33, 0x02C34, 0x02C35, 0x02C36, 0x02C37, 0x02C38, 0x02C39, 0x02C3A, 0x02C3B, 0x02C3C,
    0x02C3D, 0x02C3E, 0x02C3F, 0x02C40, 0x02C41, 0x02C42, 0x02C43, 0x02C44, 0x02C45, 0x02C46, 0x02C47, 0x02C48, 0x02C49,
    0x02C4A, 0x02C4B, 0x02C4C, 0x02C4D, 0x02C4E, 0x02C4F, 0x02C50, 0x02C51, 0x02C52, 0x02C53, 0x02C54, 0x02C55, 0x02C56,
    0x02C57, 0x02C58, 0x02C59, 0x02C5A, 0x02C5B, 0x02C5C, 0x02C5D, 0x02C5E, 0x02C2F, 0x02C30, 0x02C31, 0x02C32, 0x02C33,
    0x02C34, 0x02C35, 0x02C36, 0x02C37, 0x02C38, 0x02C39, 0x02C3A, 0x02C3B, 0x02C3C, 0x02C3D, 0x02C3E, 0x02C3F, 0x02C40,
    0x02C41, 0x02C42, 0x02C43, 0x02C44, 0x02C45, 0x02C46, 0x02C47, 0x02C48, 0x02C49, 0x02C4A, 0x02C4B, 0x02C4C, 0x02C4D,
    0x02C4E, 0x02C4F, 0x02C50, 0x02C51, 0x02C52, 0x02C53, 0x02C54, 0x02C55, 0x02C56, 0x02C57, 0x02C58, 0x02C59, 0x02C5A,
    0x02C5B, 0x02C5C, 0x02C5D, 0x02C5E, 0x02C5F, 0x02C61, 0x02C61, 0x0026B, 0x01D7D, 0x0027D, 0x02C65, 0x02C66, 0x02C68,
    0x02C68, 0x02C6A, 0x02C6A, 0x02C6C, 0x02C6C, 0x00251, 0x00271, 0x00250, 0x00252, 0x02C71, 0x02C73, 0x02C73, 0x02C74,
    0x02C76, 0x02C76, 0x02C77, 0x02C78, 0x02C79, 0x02C7A, 0x02C7B, 0x02C7C, 0x02C7D, 0x0023F, 0x00240,
};

static const uint32_t nxt_unicode_block_059[128] nxt_aligned(64) = {
    0x02C81, 0x02C81, 0x02C83, 0x02C83, 0x02C85, 0x02C85, 0x02C87, 0x02C87, 0x02C89, 0x02C89, 0x02C8B, 0x02C8B, 0x02C8D,
    0x02C8D, 0x02C8F, 0x02C8F, 0x02C91, 0x02C91, 0x02C93, 0x02C93, 0x02C95, 0x02C95, 0x02C97, 0x02C97, 0x02C99, 0x02C99,
    0x02C9B, 0x02C9B, 0x02C9D, 0x02C9D, 0x02C9F, 0x02C9F, 0x02CA1, 0x02CA1, 0x02CA3, 0x02CA3, 0x02CA5, 0x02CA5, 0x02CA7,
    0x02CA7, 0x02CA9, 0x02CA9, 0x02CAB, 0x02CAB, 0x02CAD, 0x02CAD, 0x02CAF, 0x02CAF, 0x02CB1, 0x02CB1, 0x02CB3, 0x02CB3,
    0x02CB5, 0x02CB5, 0x02CB7, 0x02CB7, 0x02CB9, 0x02CB9, 0x02CBB, 0x02CBB, 0x02CBD, 0x02CBD, 0x02CBF, 0x02CBF, 0x02CC1,
    0x02CC1, 0x02CC3, 0x02CC3, 0x02CC5, 0x02CC5, 0x02CC7, 0x02CC7, 0x02CC9, 0x02CC9, 0x02CCB, 0x02CCB, 0x02CCD, 0x02CCD,
    0x02CCF, 0x02CCF, 0x02CD1, 0x02CD1, 0x02CD3, 0x02CD3, 0x02CD5, 0x02CD5, 0x02CD7, 0x02CD7, 0x02CD9, 0x02CD9, 0x02CDB,
    0x02CDB, 0x02CDD, 0x02CDD, 0x02CDF, 0x02CDF, 0x02CE1, 0x02CE1, 0x02CE3, 0x02CE3, 0x02CE4, 0x02CE5, 0x02CE6, 0x02CE7,
    0x02CE8, 0x02CE9, 0x02CEA, 0x02CEC, 0x02CEC, 0x02CEE, 0x02CEE, 0x02CEF, 0x02CF0, 0x02CF1, 0x02CF3, 0x02CF3, 0x02CF4,
    0x02CF5, 0x02CF6, 0x02CF7, 0x02CF8, 0x02CF9, 0x02CFA, 0x02CFB, 0x02CFC, 0x02CFD, 0x02CFE, 0x02CFF,
};

static const uint32_t nxt_unicode_block_14c[128] nxt_aligned(64) = {
    0x0A600, 0x0A601, 0x0A602, 0x0A603, 0x0A604, 0x0A605, 0x0A606, 0x0A607, 0x0A608, 0x0A609, 0x0A60A, 0x0A60B, 0x0A60C,
    0x0A60D, 0x0A60E, 0x0A60F, 0x0A610, 0x0A611, 0x0A612, 0x0A613, 0x0A614, 0x0A615, 0x0A616, 0x0A617, 0x0A618, 0x0A619,
    0x0A61A, 0x0A61B, 0x0A61C, 0x0A61D, 0x0A61E, 0x0A61F, 0x0A620, 0x0A621, 0x0A622, 0x0A623, 0x0A624, 0x0A625, 0x0A626,
    0x0A627, 0x0A628, 0x0A629, 0x0A62A, 0x0A62B, 0x0A62C, 0x0A62D, 0x0A62E, 0x0A62F, 0x0A630, 0x0A631, 0x0A632, 0x0A633,
    0x0A634, 0x0A635, 0x0A636, 0x0A637, 0x0A638, 0x0A639, 0x0A63A, 0x0A63B, 0x0A63C, 0x0A63D, 0x0A63E, 0x0A63F, 0x0A641,
    0x0A641, 0x0A643, 0x0A643, 0x0A645, 0x0A645, 0x0A647, 0x0A647, 0x0A649, 0x0A649, 0x0A64B, 0x0A64B, 0x0A64D, 0x0A64D,
    0x0A64F, 0x0A64F, 0x0A651, 0x0A651, 0x0A653, 0x0A653, 0x0A655, 0x0A655, 0x0A657, 0x0A657, 0x0A659, 0x0A659, 0x0A65B,
    0x0A65B, 0x0A65D, 0x0A65D, 0x0A65F, 0x0A65F, 0x0A661, 0x0A661, 0x0A663, 0x0A663, 0x0A665, 0x0A665, 0x0A667, 0x0A667,
    0x0A669, 0x0A669, 0x0A66B, 0x0A66B, 0x0A66D, 0x0A66D, 0x0A66E, 0x0A66F, 0x0A670, 0x0A671, 0x0A672, 0x0A673, 0x0A674,
    0x0A675, 0x0A676, 0x0A677, 0x0A678, 0x0A679, 0x0A67A, 0x0A67B, 0x0A67C, 0x0A67D, 0x0A67E, 0x0A67F,
};

static const uint32_t nxt_unicode_block_14d[128] nxt_aligned(64) = {
    0x0A681, 0x0A681, 0x0A683, 0x0A683, 0x0A685, 0x0A685, 0x0A687, 0x0A687, 0x0A689, 0x0A689, 0x0A68B, 0x0A68B, 0x0A68D,
    0x0A68D, 0x0A68F, 0x0A68F, 0x0A691, 0x0A691, 0x0A693, 0x0A693, 0x0A695, 0x0A695, 0x0A697, 0x0A697, 0x0A698, 0x0A699,
    0x0A69A, 0x0A69B, 0x0A69C, 0x0A69D, 0x0A69E, 0x0A69F, 0x0A6A0, 0x0A6A1, 0x0A6A2, 0x0A6A3, 0x0A6A4, 0x0A6A5, 0x0A6A6,
    0x0A6A7, 0x0A6A8, 0x0A6A9, 0x0A6AA, 0x0A6AB, 0x0A6AC, 0x0A6AD, 0x0A6AE, 0x0A6AF, 0x0A6B0, 0x0A6B1, 0x0A6B2, 0x0A6B3,
    0x0A6B4, 0x0A6B5, 0x0A6B6, 0x0A6B7, 0x0A6B8, 0x0A6B9, 0x0A6BA, 0x0A6BB, 0x0A6BC, 0x0A6BD, 0x0A6BE, 0x0A6BF, 0x0A6C0,
    0x0A6C1, 0x0A6C2, 0x0A6C3, 0x0A6C4, 0x0A6C5, 0x0A6C6, 0x0A6C7, 0x0A6C8, 0x0A6C9, 0x0A6CA, 0x0A6CB, 0x0A6CC, 0x0A6CD,
    0x0A6CE, 0x0A6CF, 0x0A6D0, 0x0A6D1, 0x0A6D2, 0x0A6D3, 0x0A6D4, 0x0A6D5, 0x0A6D6, 0x0A6D7, 0x0A6D8, 0x0A6D9, 0x0A6DA,
    0x0A6DB, 0x0A6DC, 0x0A6DD, 0x0A6DE, 0x0A6DF, 0x0A6E0, 0x0A6E1, 0x0A6E2, 0x0A6E3, 0x0A6E4, 0x0A6E5, 0x0A6E6, 0x0A6E7,
    0x0A6E8, 0x0A6E9, 0x0A6EA, 0x0A6EB, 0x0A6EC, 0x0A6ED, 0x0A6EE, 0x0A6EF, 0x0A6F0, 0x0A6F1, 0x0A6F2, 0x0A6F3, 0x0A6F4,
    0x0A6F5, 0x0A6F6, 0x0A6F7, 0x0A6F8, 0x0A6F9, 0x0A6FA, 0x0A6FB, 0x0A6FC, 0x0A6FD, 0x0A6FE, 0x0A6FF,
};

static const uint32_t nxt_unicode_block_14e[128] nxt_aligned(64) = {
    0x0A700, 0x0A701, 0x0A702, 0x0A703, 0x0A704, 0x0A705, 0x0A706, 0x0A707, 0x0A708, 0x0A709, 0x0A70A, 0x0A70B, 0x0A70C,
    0x0A70D, 0x0A70E, 0x0A70F, 0x0A710, 0x0A711, 0x0A712, 0x0A713, 0x0A714, 0x0A715, 0x0A716, 0x0A717, 0x0A718, 0x0A719,
    0x0A71A, 0x0A71B, 0x0A71C, 0x0A71D, 0x0A71E, 0x0A71F, 0x0A720, 0x0A721, 0x0A723, 0x0A723, 0x0A725, 0x0A725, 0x0A727,
    0x0A727, 0x0A729, 0x0A729, 0x0A72B, 0x0A72B, 0x0A72D, 0x0A72D, 0x0A72F, 0x0A72F, 0x0A730, 0x0A731, 0x0A733, 0x0A733,
    0x0A735, 0x0A735, 0x0A737, 0x0A737, 0x0A739, 0x0A739, 0x0A73B, 0x0A73B, 0x0A73D, 0x0A73D, 0x0A73F, 0x0A73F, 0x0A741,
    0x0A741, 0x0A743, 0x0A743, 0x0A745, 0x0A745, 0x0A747, 0x0A747, 0x0A749, 0x0A749, 0x0A74B, 0x0A74B, 0x0A74D, 0x0A74D,
    0x0A74F, 0x0A74F, 0x0A751, 0x0A751, 0x0A753, 0x0A753, 0x0A755, 0x0A755, 0x0A757, 0x0A757, 0x0A759, 0x0A759, 0x0A75B,
    0x0A75B, 0x0A75D, 0x0A75D, 0x0A75F, 0x0A75F, 0x0A761, 0x0A761, 0x0A763, 0x0A763, 0x0A765, 0x0A765, 0x0A767, 0x0A767,
    0x0A769, 0x0A769, 0x0A76B, 0x0A76B, 0x0A76D, 0x0A76D, 0x0A76F, 0x0A76F, 0x0A770, 0x0A771, 0x0A772, 0x0A773, 0x0A774,
    0x0A775, 0x0A776, 0x0A777, 0x0A778, 0x0A77A, 0x0A77A, 0x0A77C, 0x0A77C, 0x01D79, 0x0A77F, 0x0A77F,
};

static const uint32_t nxt_unicode_block_14f[128] nxt_aligned(64) = {
    0x0A781, 0x0A781, 0x0A783, 0x0A783, 0x0A785, 0x0A785, 0x0A787, 0x0A787, 0x0A788, 0x0A789, 0x0A78A, 0x0A78C, 0x0A78C,
    0x00265, 0x0A78E, 0x0A78F, 0x0A791, 0x0A791, 0x0A793, 0x0A793, 0x0A794, 0x0A795, 0x0A796, 0x0A797, 0x0A798, 0x0A799,
    0x0A79A, 0x0A79B, 0x0A79C, 0x0A79D, 0x0A79E, 0x0A79F, 0x0A7A1, 0x0A7A1, 0x0A7A3, 0x0A7A3, 0x0A7A5, 0x0A7A5, 0x0A7A7,
    0x0A7A7, 0x0A7A9, 0x0A7A9, 0x00266, 0x0A7AB, 0x0A7AC, 0x0A7AD, 0x0A7AE, 0x0A7AF, 0x0A7B0, 0x0A7B1, 0x0A7B2, 0x0A7B3,
    0x0A7B4, 0x0A7B5, 0x0A7B6, 0x0A7B7, 0x0A7B8, 0x0A7B9, 0x0A7BA, 0x0A7BB, 0x0A7BC, 0x0A7BD, 0x0A7BE, 0x0A7BF, 0x0A7C0,
    0x0A7C1, 0x0A7C2, 0x0A7C3, 0x0A7C4, 0x0A7C5, 0x0A7C6, 0x0A7C7, 0x0A7C8, 0x0A7C9, 0x0A7CA, 0x0A7CB, 0x0A7CC, 0x0A7CD,
    0x0A7CE, 0x0A7CF, 0x0A7D0, 0x0A7D1, 0x0A7D2, 0x0A7D3, 0x0A7D4, 0x0A7D5, 0x0A7D6, 0x0A7D7, 0x0A7D8, 0x0A7D9, 0x0A7DA,
    0x0A7DB, 0x0A7DC, 0x0A7DD, 0x0A7DE, 0x0A7DF, 0x0A7E0, 0x0A7E1, 0x0A7E2, 0x0A7E3, 0x0A7E4, 0x0A7E5, 0x0A7E6, 0x0A7E7,
    0x0A7E8, 0x0A7E9, 0x0A7EA, 0x0A7EB, 0x0A7EC, 0x0A7ED, 0x0A7EE, 0x0A7EF, 0x0A7F0, 0x0A7F1, 0x0A7F2, 0x0A7F3, 0x0A7F4,
    0x0A7F5, 0x0A7F6, 0x0A7F7, 0x0A7F8, 0x0A7F9, 0x0A7FA, 0x0A7FB, 0x0A7FC, 0x0A7FD, 0x0A7FE, 0x0A7FF,
};

static const uint32_t nxt_unicode_block_1fe[128] nxt_aligned(64) = {
    0x0FF00, 0x0FF01, 0x0FF02, 0x0FF03, 0x0FF04, 0x0FF05, 0x0FF06, 0x0FF07, 0x0FF08, 0x0FF09, 0x0FF0A, 0x0FF0B, 0x0FF0C,
    0x0FF0D, 0x0FF0E, 0x0FF0F, 0x0FF10, 0x0FF11, 0x0FF12, 0x0FF13, 0x0FF14, 0x0FF15, 0x0FF16, 0x0FF17, 0x0FF18, 0x0FF19,
    0x0FF1A, 0x0FF1B, 0x0FF1C, 0x0FF1D, 0x0FF1E, 0x0FF1F, 0x0FF20, 0x0FF41, 0x0FF42, 0x0FF43, 0x0FF44, 0x0FF45, 0x0FF46,
    0x0FF47, 0x0FF48, 0x0FF49, 0x0FF4A, 0x0FF4B, 0x0FF4C, 0x0FF4D, 0x0FF4E, 0x0FF4F, 0x0FF50, 0x0FF51, 0x0FF52, 0x0FF53,
    0x0FF54, 0x0FF55, 0x0FF56, 0x0FF57, 0x0FF58, 0x0FF59, 0x0FF5A, 0x0FF3B, 0x0FF3C, 0x0FF3D, 0x0FF3E, 0x0FF3F, 0x0FF40,
    0x0FF41, 0x0FF42, 0x0FF43, 0x0FF44, 0x0FF45, 0x0FF46, 0x0FF47, 0x0FF48, 0x0FF49, 0x0FF4A, 0x0FF4B, 0x0FF4C, 0x0FF4D,
    0x0FF4E, 0x0FF4F, 0x0FF50, 0x0FF51, 0x0FF52, 0x0FF53, 0x0FF54, 0x0FF55, 0x0FF56, 0x0FF57, 0x0FF58, 0x0FF59, 0x0FF5A,
    0x0FF5B, 0x0FF5C, 0x0FF5D, 0x0FF5E, 0x0FF5F, 0x0FF60, 0x0FF61, 0x0FF62, 0x0FF63, 0x0FF64, 0x0FF65, 0x0FF66, 0x0FF67,
    0x0FF68, 0x0FF69, 0x0FF6A, 0x0FF6B, 0x0FF6C, 0x0FF6D, 0x0FF6E, 0x0FF6F, 0x0FF70, 0x0FF71, 0x0FF72, 0x0FF73, 0x0FF74,
    0x0FF75, 0x0FF76, 0x0FF77, 0x0FF78, 0x0FF79, 0x0FF7A, 0x0FF7B, 0x0FF7C, 0x0FF7D, 0x0FF7E, 0x0FF7F,
};

static const uint32_t nxt_unicode_block_208[40] nxt_aligned(64) = {
    0x10428, 0x10429, 0x1042A, 0x1042B, 0x1042C, 0x1042D, 0x1042E, 0x1042F, 0x10430, 0x10431,
    0x10432, 0x10433, 0x10434, 0x10435, 0x10436, 0x10437, 0x10438, 0x10439, 0x1043A, 0x1043B,
    0x1043C, 0x1043D, 0x1043E, 0x1043F, 0x10440, 0x10441, 0x10442, 0x10443, 0x10444, 0x10445,
    0x10446, 0x10447, 0x10448, 0x10449, 0x1044A, 0x1044B, 0x1044C, 0x1044D, 0x1044E, 0x1044F,
};

static const uint32_t *nxt_unicode_blocks[] nxt_aligned(64) = {
    nxt_unicode_block_000,
    nxt_unicode_block_001,
    nxt_unicode_block_002,
    nxt_unicode_block_003,
    nxt_unicode_block_004,
    NULL,
    nxt_unicode_block_006,
    nxt_unicode_block_007,
    nxt_unicode_block_008,
    nxt_unicode_block_009,
    nxt_unicode_block_00a,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    nxt_unicode_block_021,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    nxt_unicode_block_03c,
    nxt_unicode_block_03d,
    nxt_unicode_block_03e,
    nxt_unicode_block_03f,
    NULL,
    NULL,
    nxt_unicode_block_042,
    nxt_unicode_block_043,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    nxt_unicode_block_049,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    nxt_unicode_block_058,
    nxt_unicode_block_059,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    nxt_unicode_block_14c,
    nxt_unicode_block_14d,
    nxt_unicode_block_14e,
    nxt_unicode_block_14f,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    nxt_unicode_block_1fe,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    nxt_unicode_block_208,
};
