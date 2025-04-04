

#include <iostream>
#include "detect_pattern.h"
#include "test_detect_pattern.h"

uint8_t without_rep_block[] = {

    0xc9, 0xc3, 0x53, 0xda, 0xe6, 0x8a, 0x74, 0x96, 0xa8, 0xff, 0x49, 0x2f, 0x84, 0x23, 0x88, 0xe1, 0xc5, 0xdc, 0xde,
    0xed, 0x34, 0x1c, 0x6f, 0x04, 0x9c, 0x71, 0x53, 0xa6, 0xc6, 0x33, 0x69, 0x29, 0x94, 0x41, 0xce, 0x60, 0xa1, 0x11,
    0x52, 0xa3, 0x6d, 0xe3, 0x11, 0x32, 0xf9, 0x50, 0xc7, 0x28, 0x51, 0x63, 0x77, 0x9a, 0x50, 0x33, 0x6b, 0xbc, 0xc4,
    0x5c, 0x6d, 0x66, 0xf7, 0x41, 0x5a, 0xa5, 0xc0, 0x15, 0xbf, 0x1c, 0x0c, 0xdd, 0x4b, 0x53, 0xbf, 0x88, 0x9f, 0xe3,
    0xf9, 0x1c, 0x61, 0xd8, 0xf5, 0xd7, 0xd3, 0x22, 0xab, 0xcb, 0xc8, 0xeb, 0xfd, 0x41, 0x9d, 0xb4, 0x73, 0x0d, 0x97,
    0x33, 0xe9, 0x31, 0x00, 0xa0, 0x9a, 0xea, 0xc4, 0xee, 0xe7, 0x59, 0x95, 0x83, 0x17, 0x65, 0x1c, 0x6b, 0x09, 0x3c,
    0x19, 0x22, 0x37, 0x5b, 0x68, 0x3b, 0xa5, 0x5a, 0x60, 0x71, 0xd2, 0xfe, 0xab, 0xb9, 0x0b, 0xed, 0xcd, 0x0d, 0x48,
    0x54, 0x8f, 0xbf, 0xd0, 0x5c, 0xdd, 0x2c, 0x6f, 0xa6, 0x77, 0x12, 0x5a, 0x90, 0xd4, 0x5b, 0x0d, 0xbf, 0xf1, 0xfa,
    0x88, 0xb5, 0xbf, 0xbf, 0x0a, 0xea, 0xc8, 0x07, 0x9b, 0xbf, 0xf0, 0xca, 0xe4, 0x0a, 0x8d, 0x58, 0xa5, 0x44, 0x48,
    0x43, 0xbb, 0x10, 0x09, 0x19, 0x65, 0x53, 0xb8, 0x25, 0xe3, 0xfe, 0x91, 0xe9, 0xfc, 0x0f, 0xbf, 0x15, 0xc1, 0xe8,
    0xbf, 0xb0, 0xdc, 0x45, 0x3f, 0x05, 0xb5, 0x2e, 0xb9, 0x90, 0xbf, 0x62, 0x18, 0x5e, 0xcc, 0x34, 0xcd, 0x4c, 0xb1,
    0x22, 0xf9, 0x46, 0x07, 0x1b, 0x80, 0x9b, 0x41, 0x45, 0xdb, 0xd5, 0xf4, 0xcf, 0x79, 0x7b, 0x60, 0x80, 0x79, 0x36,
    0x3f, 0x9b, 0x0b, 0x6a, 0xca, 0x47, 0xcd, 0x6c, 0x44, 0x18, 0xb4, 0x4d, 0xbf, 0x2a, 0x8a, 0x2a, 0xd4, 0x4d, 0x97,
    0x65, 0x88, 0xf7, 0x83, 0x8c, 0x21, 0xb4, 0x09, 0xc4, 0x72, 0x85, 0xd0, 0x64, 0xff, 0xa1, 0x64, 0xbf, 0x44, 0x75,
    0xbf, 0x3d, 0xc9, 0x15, 0xec, 0xd4, 0xbf, 0xd5, 0x16, 0x47, 0x69, 0xbf, 0x3a, 0x48, 0xc8, 0x55, 0xac, 0xab, 0x58,
    0xb8, 0xd5, 0x4f, 0xd5, 0x0e, 0x47, 0x6e, 0x3c, 0xbf, 0x14, 0x22, 0xcc, 0xec, 0x78, 0x71, 0xa2, 0x9d, 0xb8, 0xb0,
    0xfa, 0xaf, 0x35, 0xb6, 0x5d, 0x46, 0x60, 0xab, 0xc5, 0xfc, 0xb1, 0x92, 0x32, 0xe2, 0x1f, 0x91, 0xed, 0xbf, 0x36,
    0xe0, 0x26, 0xec, 0x80, 0xef, 0x4c, 0x72, 0xe9, 0x5d, 0xca, 0x0a, 0x4a, 0xd7, 0xe4, 0x37, 0x76, 0x74, 0xe6, 0xc1,
    0x70, 0xb9, 0x53, 0x12, 0xe9, 0x86, 0xbf, 0x50, 0xef, 0xb2, 0x24, 0x2c, 0x6f, 0xda, 0xe2, 0xb0, 0x77, 0x53, 0xa7,
    0xdc, 0x02, 0xda, 0xd7, 0x39, 0xa2, 0x93, 0xfd, 0xc3, 0x1f, 0x2f, 0xe1, 0x0f, 0xfc, 0xc6, 0xfc, 0xb7, 0x05, 0x19,
    0x80, 0x5b, 0xa5, 0xfa, 0xe6, 0x27, 0x79, 0x90, 0x9a, 0xf8, 0x85, 0x19, 0xb5, 0x10, 0xf3, 0xef, 0x59, 0xff, 0x3f,
    0x42, 0x23, 0xd0, 0x5c, 0x71, 0x93, 0xa2, 0x09, 0xec, 0xbf, 0x7c, 0x4c, 0x15, 0x00, 0xa6, 0xce, 0x48, 0x31, 0x19,
    0xa8, 0xd0, 0x70, 0xca, 0xd4, 0x72, 0x79, 0x0f, 0xbf, 0xdb, 0x67, 0x86, 0x87, 0x04, 0xca, 0xfe, 0x21, 0x02, 0xc1,
    0x33, 0x7e, 0x83, 0x0a, 0x1c, 0xb5, 0x83, 0xce, 0xd1, 0xd4, 0x7b, 0x87, 0xe2, 0xae, 0x46, 0xb7, 0xaa, 0xb3, 0x71,
    0x82, 0xbf, 0x34, 0xae, 0xff, 0xbf, 0xf3, 0xc5, 0x4c, 0x46, 0xf4, 0x47, 0xf6, 0x26, 0x3a, 0x8b, 0xe0, 0x27, 0xeb,
    0xa7, 0x07, 0xee, 0xe0, 0x73, 0x13, 0x72, 0x88, 0x41, 0x97, 0x2e, 0x97, 0xb7, 0xdb, 0x31, 0x46, 0x31, 0x03, 0xa1,
    0x13, 0xaf, 0x5c, 0xbf, 0x31, 0x73, 0x0d, 0xfb, 0xbf, 0xc1, 0x76, 0x19, 0x29, 0x49, 0xd9, 0x61, 0xb5, 0xa9, 0xa2,
    0x99, 0x2a, 0x87, 0x29, 0x7c, 0x1b, 0xdd, 0x4d, 0x41, 0x5c, 0x9a, 0xa3, 0xf5, 0xc7, 0x71, 0x4b, 0xce, 0x1e, 0x27,
    0xaf, 0x85, 0x38, 0xaf, 0x6c, 0xbd, 0xa3, 0x73, 0x9b, 0x9c, 0x9b, 0xd5, 0x5a, 0xf8, 0xf7, 0x58, 0x39, 0x72, 0x69,
    0x90, 0x15, 0x78, 0x59, 0x02, 0x2b, 0xf8, 0x48, 0x07, 0x73, 0x62, 0x80, 0x1a, 0x6e, 0x25, 0xce, 0x46, 0x17, 0x01,
    0x99, 0x50, 0x5b, 0x53, 0xaa, 0xf7, 0x00, 0xa0, 0x28, 0x1d, 0xe4, 0x1c, 0xbf, 0xfd, 0x0c, 0xbd, 0x37, 0x23, 0x1b,
    0xd8, 0xcf, 0x57, 0xaa, 0x9f, 0x0e, 0xb5, 0xf4, 0x1e, 0x60, 0x9e, 0xd9, 0x2a, 0x4a, 0x03, 0x68, 0xb4, 0x58, 0xc5,
    0xc0, 0xc5, 0x78, 0xfa, 0x9e, 0xc1, 0x54, 0xbf, 0xbf, 0xfd, 0xe9, 0xd8, 0x23, 0xa0, 0x89, 0x63, 0x68, 0x57, 0xf9,
    0x88, 0x48, 0x51, 0x1b, 0x5c, 0xf9, 0xba, 0xfe, 0xe5, 0x9f, 0x3b, 0x33, 0x7b, 0xb1, 0xb3, 0xe5, 0xd4, 0x4a, 0xa0,
    0x1a, 0x48, 0xb5, 0x11, 0x82, 0xba, 0x73, 0x2c, 0xd7, 0xfc, 0x11, 0xa9, 0x2d, 0x87, 0x06, 0xbe, 0x42, 0x43, 0xb2,
    0xe9, 0x6d, 0xa8, 0xb9, 0xee, 0x11, 0x52, 0x10, 0xc3, 0xd6, 0xbf, 0x81, 0xee, 0x65, 0x9e, 0xc3, 0xd9, 0x2e, 0x3c,
    0xab, 0x2a, 0x4d, 0xbf, 0x65, 0xa1, 0xbf, 0x9b, 0xb6, 0x32, 0xa2, 0x2f, 0x5a, 0xbf, 0xfb, 0xe8, 0xbb, 0x1e, 0x04,
    0xbf, 0xa3, 0x5f, 0x71, 0x50, 0x01, 0xed, 0x99, 0xbf, 0x90, 0x97, 0x6b, 0x55, 0x76, 0xfe, 0x32, 0xa5, 0x99, 0x29,
    0xf5, 0xbf, 0x35, 0xdf, 0x7d, 0x61, 0x40, 0x8f, 0x5a, 0x0c, 0xfa, 0xf6, 0x68, 0xb1, 0x6d, 0x7c, 0x10, 0x36, 0xfc,
    0x58, 0x4f, 0x55, 0x48, 0xc3, 0xe9, 0x00, 0xff, 0xb2, 0xc5, 0x7a, 0xf2, 0x48, 0xad, 0xa6, 0xbf, 0x4d, 0xe9, 0xf5,
    0xd7, 0x3c, 0xe5, 0xc9, 0x3a, 0x0f, 0x42, 0x8e, 0x37, 0xe3, 0x7e, 0x29, 0x3a, 0x94, 0x11, 0x73, 0x4c, 0x13, 0x25,
    0xbd, 0xb7, 0x2b, 0x46, 0x29, 0x7b, 0x7c, 0xad, 0x50, 0x83, 0x23, 0x36, 0x85, 0x21, 0x25, 0x1c, 0xaa, 0x4e, 0x08,
    0x9a, 0x06, 0x5a, 0x94, 0x45, 0x30, 0xe1, 0xd8, 0x75, 0x7a, 0x87, 0xda, 0xf1, 0x14, 0x50, 0xf8, 0xea, 0x8e, 0x4b,
    0xf4, 0xba, 0xe3, 0x1a, 0x86, 0x75, 0xd9, 0x52, 0x70, 0x58, 0xde, 0xe1, 0x47, 0x98, 0x4e, 0x73, 0x94, 0x0f, 0x37,
    0x5f, 0xab, 0x08, 0xfa, 0x0e, 0x64, 0x70, 0xc0, 0x5e, 0xfc, 0x25, 0x05, 0x76, 0x09, 0x09, 0x0c, 0xbb, 0x14, 0x77,
    0xb4, 0xb1, 0x9f, 0x1e, 0x75, 0x0f, 0xeb, 0x01, 0x16, 0x83, 0x3b, 0xb9, 0x23, 0xe6, 0x9a, 0x6f, 0xad, 0x73, 0x2a,
    0x16, 0xdd, 0x0d, 0x91, 0xf1, 0x03, 0xde, 0x1f, 0x76, 0xdc, 0x2b, 0x2f, 0x11, 0x48, 0x2d, 0x10, 0xe1, 0xd5, 0x52,
    0xa4, 0x00, 0x9e, 0xc6, 0x26, 0x54, 0xf2, 0x13, 0xea, 0x08, 0xac, 0xea, 0x80, 0x42, 0xde, 0x09, 0x88, 0x6f, 0x73,
    0xd8, 0xda, 0xd5, 0xfa, 0x7b, 0x4c, 0x99, 0x72, 0x32, 0xa4, 0x10, 0x70, 0x4c, 0x72, 0xfb, 0xd3, 0xf1, 0xda, 0x3a,
    0x8c, 0xfe, 0x18, 0x34, 0x82, 0xe6, 0x5b, 0xd2, 0x51, 0x1d, 0xd6, 0x51, 0xc0, 0x71, 0x81, 0xf7, 0x46, 0xa3, 0x5a,
    0xbf, 0xa2, 0xf2, 0x47, 0x7f, 0x43, 0xc0, 0x4f, 0x39, 0x94, 0x8d, 0x90, 0x58, 0xe9, 0x4e, 0xc2, 0x6d, 0x43, 0xbf,
    0x2d, 0xdb, 0x0d, 0x6b, 0xe9, 0x92, 0xf3, 0x38, 0xe8, 0x90, 0xc8, 0x11, 0xf2, 0x31, 0xa1, 0x62, 0x3b, 0xd3, 0x13,
    0x2e, 0xe0, 0x9e, 0x7d, 0x87, 0x89, 0x49, 0x32, 0x88, 0xf2, 0x25, 0x19, 0x12, 0x0d, 0xac, 0xbf, 0x0a,

};

uint8_t with_rep_block[] = {
    0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x42, 0x45, 0x47, 0x49, 0x4e, 0x20, 0x50, 0x47, 0x50, 0x20, 0x4d, 0x45, 0x53, 0x53,
    0x41, 0x47, 0x45, 0x2d, 0x1e, 0x47, 0x93, 0xea, 0x52, 0x62, 0x08, 0xa1, 0x0e, 0x1e, 0xee, 0xf2, 0x78, 0xf4, 0xd1,
    0x61, 0xd8, 0xbb, 0x69, 0x0c, 0x35, 0x22, 0x74, 0xef, 0x30, 0x84, 0x05, 0x81, 0x91, 0x8e, 0x34, 0x1b, 0xd8, 0xbb,
    0x69, 0x0c, 0x35, 0x22, 0x74, 0xef, 0x30, 0x84, 0x05, 0x81, 0x91, 0x8e, 0x34, 0x1b, 0xd8, 0xbb, 0x69, 0x0c, 0x35,
    0x22, 0x74, 0xef, 0x30, 0x84, 0x05, 0x81, 0x91, 0x8e, 0x34, 0x1b, 0xd8, 0xbb, 0x69, 0x0c, 0x35, 0x22, 0x74, 0xef,
    0x30, 0x84, 0x05, 0x81, 0x91, 0x8e, 0x34, 0x1b, 0xd5, 0xf2, 0x3f, 0x80, 0xe0, 0x8b, 0xa2, 0xb4, 0xe5, 0xa1, 0x60,
    0x2c, 0xea, 0x91, 0x60, 0x84, 0x66, 0x63, 0x69, 0x62, 0x4d, 0x7a, 0x39, 0x4b, 0x32, 0x32, 0x68, 0x55, 0x61, 0x68,
    0x32, 0x53, 0x7a, 0x75, 0x45, 0x39, 0x71, 0x47, 0x49, 0x72, 0x67, 0x42, 0x5a, 0x76, 0x71, 0x38, 0x78, 0x59, 0x6a,
    0x68, 0x6e, 0x4f, 0x62, 0x44, 0x51, 0x0a, 0x43, 0x71, 0x39, 0x38, 0x78, 0x65, 0x42, 0x61, 0x43, 0x31, 0x4c, 0x54,
    0x51, 0x54, 0x4e, 0x35, 0x4d, 0x68, 0x5a, 0x4d, 0x77, 0x34, 0x31, 0x36, 0x73, 0x5a, 0x33, 0x51, 0x78, 0x37, 0x35,
    0x31, 0x52, 0x42, 0x63, 0x66, 0x47, 0x34, 0x32, 0x36, 0x71, 0x4b, 0x6d, 0x6f, 0x56, 0x45, 0x51, 0x65, 0x4a, 0x37,
    0x57, 0x55, 0x5a, 0x56, 0x39, 0x6a, 0x48, 0x71, 0x48, 0x35, 0x4d, 0x58, 0x46, 0x72, 0x0a, 0x51, 0x35, 0x6b, 0x56,
    0x37, 0x73, 0x2f, 0x59, 0x33, 0x70, 0x30, 0x71, 0x68, 0x35, 0x31, 0x77, 0x65, 0x71, 0x2f, 0x68, 0x70, 0x59, 0x2f,
    0x46, 0x4e, 0x71, 0x6e, 0x2b, 0x43, 0x66, 0x4d, 0x77, 0x31, 0x31, 0x79, 0x4e, 0x49, 0x49, 0x39, 0x74, 0x56, 0x42,
    0x4f, 0x6d, 0x4e, 0x36, 0x49, 0x6d, 0x74, 0x6b, 0x48, 0x6d, 0x56, 0x59, 0x73, 0x37, 0x49, 0x39, 0x44, 0x49, 0x63,
    0x68, 0x47, 0x45, 0x0a, 0x42, 0x45, 0x4d, 0x63, 0x41, 0x32, 0x51, 0x6e, 0x34, 0x61, 0x55, 0x77, 0x52, 0x35, 0x61,
    0x64, 0x37, 0x44, 0x69, 0x74, 0x32, 0x48, 0x32, 0x4a, 0x61, 0x6c, 0x69, 0x6b, 0x6f, 0x6b, 0x67, 0x73, 0x72, 0x39,
    0x6d, 0x56, 0x66, 0x35, 0x52, 0x43, 0x35, 0x31, 0x36, 0x77, 0x33, 0x34, 0x63, 0x6e, 0x71, 0x2b, 0x34, 0x57, 0x79,
    0x4c, 0x64, 0x68, 0x72, 0x4d, 0x2f, 0x74, 0x39, 0x6f, 0x4a, 0x5a, 0x0a, 0x4d, 0x61, 0x6e, 0x7a, 0x4d, 0x51, 0x7a,
    0x7a, 0x77, 0x64, 0x38, 0x61, 0x49, 0x39, 0x48, 0x4f, 0x4f, 0x65, 0x77, 0x50, 0x33, 0x48, 0x62, 0x44, 0x66, 0x74,
    0x59, 0x6e, 0x45, 0x70, 0x6a, 0x31, 0x41, 0x59, 0x6c, 0x67, 0x6e, 0x44, 0x6c, 0x2f, 0x6c, 0x4b, 0x42, 0x37, 0x74,
    0x59, 0x61, 0x4a, 0x37, 0x51, 0x70, 0x56, 0x73, 0x74, 0x4a, 0x46, 0x4a, 0x72, 0x45, 0x7a, 0x4e, 0x6a, 0x67, 0x6d,
    0x0a, 0x42, 0x70, 0x57, 0x4b, 0x68, 0x62, 0x51, 0x76, 0x48, 0x6a, 0x58, 0x56, 0x71, 0x66, 0x78, 0x56, 0x47, 0x6e,
    0x46, 0x68, 0x71, 0x2b, 0x48, 0x54, 0x37, 0x67, 0x6c, 0x42, 0x51, 0x51, 0x71, 0x4f, 0x67, 0x38, 0x32, 0x4b, 0x2f,
    0x44, 0x49, 0x33, 0x69, 0x62, 0x46, 0x67, 0x4f, 0x76, 0x76, 0x6f, 0x44, 0x34, 0x55, 0x2f, 0x33, 0x2b, 0x73, 0x41,
    0x43, 0x31, 0x37, 0x2b, 0x53, 0x56, 0x34, 0x61, 0x0a, 0x65, 0x4a, 0x57, 0x71, 0x49, 0x64, 0x57, 0x34, 0x5a, 0x4f,
    0x35, 0x59, 0x4b, 0x4e, 0x4e, 0x59, 0x33, 0x2f, 0x4b, 0x57, 0x49, 0x2b, 0x36, 0x64, 0x6f, 0x4b, 0x68, 0x45, 0x43,
    0x37, 0x51, 0x75, 0x62, 0x49, 0x64, 0x4f, 0x41, 0x6f, 0x61, 0x6d, 0x4d, 0x61, 0x6d, 0x6f, 0x2b, 0x34, 0x39, 0x72,
    0x64, 0x30, 0x74, 0x52, 0x56, 0x52, 0x4d, 0x78, 0x76, 0x4e, 0x4f, 0x73, 0x56, 0x37, 0x54, 0x6b, 0x0a, 0x31, 0x57,
    0x48, 0x35, 0x42, 0x79, 0x6b, 0x68, 0x70, 0x75, 0x30, 0x79, 0x68, 0x5a, 0x73, 0x6a, 0x35, 0x61, 0x35, 0x68, 0x30,
    0x73, 0x42, 0x75, 0x41, 0x66, 0x4c, 0x66, 0x46, 0x6b, 0x65, 0x67, 0x74, 0x50, 0x4c, 0x63, 0x69, 0x75, 0x61, 0x6c,
    0x66, 0x4e, 0x4f, 0x42, 0x4d, 0x6f, 0x57, 0x78, 0x62, 0x55, 0x61, 0x51, 0x73, 0x70, 0x32, 0x6f, 0x31, 0x68, 0x66,
    0x42, 0x63, 0x2f, 0x61, 0x6f, 0x0a, 0x33, 0x66, 0x54, 0x52, 0x44, 0x78, 0x73, 0x6b, 0x65, 0x43, 0x6d, 0x51, 0x33,
    0x41, 0x4e, 0x2f, 0x41, 0x77, 0x76, 0x54, 0x4a, 0x52, 0x75, 0x45, 0x43, 0x79, 0x33, 0x54, 0x76, 0x38, 0x79, 0x38,
    0x44, 0x2b, 0x2b, 0x47, 0x4d, 0x6c, 0x69, 0x75, 0x65, 0x48, 0x56, 0x2f, 0x73, 0x50, 0x6b, 0x38, 0x31, 0x4a, 0x30,
    0x41, 0x2f, 0x64, 0x4d, 0x44, 0x69, 0x59, 0x68, 0x4b, 0x32, 0x2b, 0x32, 0x31, 0x0a, 0x48, 0x35, 0x59, 0x6f, 0x32,
    0x6b, 0x48, 0x70, 0x4c, 0x43, 0x51, 0x7a, 0x54, 0x4b, 0x50, 0x4f, 0x36, 0x6f, 0x61, 0x70, 0x38, 0x33, 0x31, 0x37,
    0x2b, 0x46, 0x47, 0x6b, 0x78, 0x57, 0x33, 0x6b, 0x47, 0x4f, 0x57, 0x57, 0x4e, 0x62, 0x6a, 0x56, 0x51, 0x58, 0x4f,
    0x68, 0x41, 0x36, 0x56, 0x51, 0x59, 0x41, 0x75, 0x76, 0x55, 0x2b, 0x38, 0x55, 0x57, 0x30, 0x57, 0x7a, 0x6f, 0x36,
    0x49, 0x45, 0x0a, 0x73, 0x6a, 0x47, 0x51, 0x5a, 0x48, 0x74, 0x53, 0x67, 0x32, 0x79, 0x6e, 0x4e, 0x4c, 0x33, 0x65,
    0x70, 0x70, 0x68, 0x41, 0x54, 0x36, 0x6d, 0x43, 0x79, 0x79, 0x37, 0x37, 0x34, 0x53, 0x74, 0x4d, 0x52, 0x4e, 0x57,
    0x79, 0x53, 0x46, 0x30, 0x71, 0x37, 0x78, 0x6b, 0x39, 0x50, 0x77, 0x48, 0x53, 0x79, 0x6d, 0x49, 0x5a, 0x5a, 0x4f,
    0x45, 0x56, 0x41, 0x73, 0x55, 0x78, 0x4b, 0x6b, 0x35, 0x64, 0x0a, 0x65, 0x4e, 0x55, 0x7a, 0x55, 0x77, 0x57, 0x2f,
    0x54, 0x38, 0x4d, 0x41, 0x6c, 0x51, 0x7a, 0x44, 0x6d, 0x50, 0x79, 0x75, 0x31, 0x64, 0x7a, 0x6f, 0x6b, 0x65, 0x6b,
    0x7a, 0x35, 0x65, 0x39, 0x56, 0x65, 0x48, 0x5a, 0x63, 0x57, 0x36, 0x4d, 0x64, 0x48, 0x42, 0x32, 0x6b, 0x69, 0x63,
    0x32, 0x44, 0x71, 0x6a, 0x53, 0x55, 0x67, 0x52, 0x50, 0x46, 0x4f, 0x45, 0x63, 0x58, 0x2f, 0x37, 0x62, 0x74, 0x0a,
    0x4f, 0x35, 0x6e, 0x52, 0x59, 0x47, 0x7a, 0x68, 0x53, 0x2b, 0x46, 0x38, 0x6b, 0x31, 0x57, 0x67, 0x36, 0x50, 0x34,
    0x4e, 0x53, 0x4f, 0x42, 0x53, 0x43, 0x52, 0x48, 0x2f, 0x6e, 0x36, 0x41, 0x66, 0x77, 0x39, 0x2b, 0x33, 0x73, 0x4a,
    0x2b, 0x5a, 0x53, 0x44, 0x49, 0x4c, 0x37, 0x46, 0x48, 0x45, 0x56, 0x34, 0x63, 0x4d, 0x4d, 0x44, 0x53, 0x70, 0x49,
    0x31, 0x6e, 0x6d, 0x72, 0x63, 0x58, 0x4d, 0x0a, 0x35, 0x5a, 0x77, 0x68, 0x78, 0x42, 0x6f, 0x49, 0x6b, 0x4c, 0x79,
    0x53, 0x42, 0x55, 0x66, 0x35, 0x45, 0x48, 0x55, 0x52, 0x35, 0x4d, 0x35, 0x33, 0x2b, 0x44, 0x66, 0x47, 0x50, 0x61,
    0x38, 0x65, 0x78, 0x43, 0x38, 0x59, 0x4d, 0x65, 0x4f, 0x6a, 0x75, 0x7a, 0x73, 0x3d, 0x0a, 0x3d, 0x38, 0x4f, 0x5a,
    0x39, 0x0a, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x45, 0x4e, 0x44, 0x20, 0x50, 0x47, 0x50, 0x20, 0x4d, 0x45, 0x53, 0x53,
    0x41, 0x47, 0x45, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x0a,
};

bool test_detect_pattern()
{

    if(!detect_pattern::has_byte_string_repeated_block_at_any_offset(std::span(with_rep_block), 1))
    {
        std::cerr << "error in pattern detect 1\n";
        return false;
    }
    if(detect_pattern::has_byte_string_repeated_block_at_any_offset(std::span(without_rep_block), 1))
    {
        std::cerr << "error in pattern detect 2\n";
        return false;
    }
    return true;

}
