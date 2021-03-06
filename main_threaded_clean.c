#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "immintrin.h"
#include <time.h>
#include <pthread.h>

//define necessary functions
#define F(x, y, z) ((x & y) | ((~x) & z))
#define G(x, y, z) ((x & z) | (y & (~z)))
#define H(x, y, z) (x ^ y ^ z )
#define I(x, y, z) (y ^ (x | ~z))

#define bswap_16(value) \
((((value) & 0xff) << 8) | ((value) >> 8))

#define bswap_32(value) \
(((uint32_t)bswap_16((uint16_t)((value) & 0xffff)) << 16) | \
(uint32_t)bswap_16((uint16_t)((value) >> 16)))

#define circular_shift_left(x, shift){\
  x = _mm256_setr_epi32( \
    (((uint32_t*)&x)[0] << shift) | (((uint32_t*)&x)[0] >> (32 - shift)), \
    0, \
    (((uint32_t*)&x)[2] << shift) | (((uint32_t*)&x)[2] >> (32 - shift)), \
    0, \
    (((uint32_t*)&x)[4] << shift) | (((uint32_t*)&x)[4] >> (32 - shift)), \
    0, \
    (((uint32_t*)&x)[6] << shift) | (((uint32_t*)&x)[6] >> (32 - shift)), \
    0);}

//define global variables
uint32_t hashes1, hashes2, hashes3, hashes4, hashes5, hashes6, hashes7, hashes8;
clock_t begin, end;

char char_set[52] =
        {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
         'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
         'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
         'N', 'O', 'P', 'Q', 'E', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'};

char gen_md5(uint8_t *initial_message, uint8_t *initial_message1, uint8_t *initial_message2,
             uint8_t *initial_message3, size_t initial_length)
{
    /*********************************************/
    size_t pad_len = 448 - (initial_length*8);              //pad len = 448 avail bits - initial len in bits
    size_t total_len = initial_length*8 + pad_len + 64;     //store in variable in case total_len > 512
    uint8_t* message = calloc(total_len, 1);                //generate space to hold to actual message

    memcpy(message, initial_message, initial_length);       //fill message array with actual initial message contents
    message[initial_length] = 0x80;                         //first position after message, fill with 1
    uint32_t M[total_len/32];                               //total_len/32 = (total_len / 512) * 16
    //convert array of 8 bit indices to 32 bit indices
    for(int i=0; i<total_len/32; i++)
    {
        memcpy(M + i, message + i*4, 4);
    }
    uint64_t bit_len64 = (initial_length*8);                 //determine pad for 64 bit portion
    memcpy(M + 14, &bit_len64, 8);
    /*********************************************/
    /*********************************************/
    size_t pad_len1 = 448 - (initial_length*8);             //pad len = 448 avail bits - initial len in bits
    size_t total_len1 = initial_length*8 + pad_len1 + 64;   //store in variable in case total_len > 512
    uint8_t* message1 = calloc(total_len1, 1);              //generate pad to be concatenated to actual message

    memcpy(message1, initial_message1, initial_length);     //fill message array with actual initial message contents
    message1[initial_length] = 0x80;                        //first position after message, fill with 1
    uint32_t M1[total_len1/32];                             //total_len/32 = (total_len / 512) * 16

    for(int i=0; i<total_len1/32; i++)
    {
        memcpy(M1 + i, message1 + i*4, 4);
    }
    uint64_t bit_len641 = (initial_length*8);               //determine pad for 64 bit portion
    memcpy(M1 + 14, &bit_len641, 8);
    /*********************************************/
    size_t pad_len2 = 448 - (initial_length*8);             //pad len = 448 avail bits - initial len in bits
    size_t total_len2 = initial_length*8 + pad_len2 + 64;   //store in variable in case total_len > 512
    uint8_t* message2 = calloc(total_len2, 1);              //generate pad to be concatenated to actual message

    memcpy(message2, initial_message2, initial_length);     //fill message array with actual initial message contents
    message2[initial_length] = 0x80;                        //first position after message, fill with 1
    uint32_t M2[total_len2/32];                             //total_len/32 = (total_len / 512) * 16

    for(int i=0; i<total_len2/32; i++)
    {
        memcpy(M2 + i, message2 + i*4, 4);
    }
    uint64_t bit_len642 = (initial_length*8);               //determine pad for 64 bit portion
    memcpy(M2 + 14, &bit_len642, 8);
    /*********************************************/
    size_t pad_len3 = 448 - (initial_length*8);             //pad len = 448 avail bits - initial len in bits
    size_t total_len3 = initial_length*8 + pad_len3 + 64;   //store in variable in case total_len > 512
    uint8_t* message3 = calloc(total_len3, 1);              //generate pad to be concatenated to actual message

    memcpy(message3, initial_message3, initial_length);     //fill message array with actual initial message contents
    message3[initial_length] = 0x80;                        //first position after message, fill with 1
    uint32_t M3[total_len3/32];                             //total_len/32 = (total_len / 512) * 16

    for(int i=0; i<total_len3/32; i++)
    {
        memcpy(M3 + i, message3 + i*4, 4);
    }

    uint64_t bit_len643 = (initial_length*8);                 //determine pad for 64 bit portion
    memcpy(M3 + 14, &bit_len643, 8);
    /**********************************************/
    __m256i A = _mm256_set1_epi32(0x67452301),
            B = _mm256_set1_epi32(0xEFCDAB89),
            C = _mm256_set1_epi32(0x98BADCFE),
            D = _mm256_set1_epi32(0x10325476);

    __m256i f_val, temp, a_old = A, b_old = B, c_old = C, d_old = D;

    __m256i m0= _mm256_setr_epi32( M[0], 0, M1[0], 0, M2[0], 0, M3[0], 0);
    __m256i m1= _mm256_setr_epi32( M[1], 0, M1[1], 0, M2[1], 0, M3[1], 0);
    __m256i m2= _mm256_setr_epi32( M[2], 0, M1[2], 0, M2[2], 0, M3[2], 0);
    __m256i m3= _mm256_setr_epi32( M[3], 0, M1[3], 0, M2[3], 0, M3[3], 0);
    __m256i m4= _mm256_setr_epi32( M[4], 0, M1[4], 0, M2[4], 0, M3[4], 0);
    __m256i m5= _mm256_setr_epi32( M[5], 0, M1[5], 0, M2[5], 0, M3[5], 0);
    __m256i m6= _mm256_setr_epi32( M[6], 0, M1[6], 0, M2[6], 0, M3[6], 0);
    __m256i m7= _mm256_setr_epi32( M[7], 0, M1[7], 0, M2[7], 0, M3[7], 0);
    __m256i m8= _mm256_setr_epi32( M[8], 0, M1[8], 0, M2[8], 0, M3[8], 0);
    __m256i m9= _mm256_setr_epi32( M[9], 0, M1[9], 0, M2[9], 0, M3[9], 0);
    __m256i m10= _mm256_setr_epi32(M[10], 0, M1[10], 0, M2[10], 0, M3[10], 0);
    __m256i m11= _mm256_setr_epi32(M[11], 0, M1[11], 0, M2[11], 0, M3[11], 0);
    __m256i m12= _mm256_setr_epi32(M[12], 0, M1[12], 0, M2[12], 0, M3[12], 0);
    __m256i m13= _mm256_setr_epi32(M[13], 0, M1[13], 0, M2[13], 0, M3[13], 0);
    __m256i m14= _mm256_setr_epi32(M[14], 0, M1[14], 0, M2[14], 0, M3[14], 0);
    __m256i m15= _mm256_setr_epi32(M[15], 0, M1[15], 0, M2[15], 0, M3[15], 0);

    //Round 1
    f_val = F(B, C, D); temp = D; D = C; C = B;A = A + f_val + m0 +  _mm256_set1_epi32(0xd76aa478); B = B + (circular_shift_left(A,  7)); A = temp;
    f_val = F(B, C, D); temp = D; D = C; C = B;A = A + f_val + m1 +  _mm256_set1_epi32(0xe8c7b756); B = B + (circular_shift_left(A, 12)); A = temp;
    f_val = F(B, C, D); temp = D; D = C; C = B;A = A + f_val + m2 +  _mm256_set1_epi32(0x242070db); B = B + (circular_shift_left(A, 17)); A = temp;
    f_val = F(B, C, D); temp = D; D = C; C = B;A = A + f_val + m3 +  _mm256_set1_epi32(0xc1bdceee); B = B + (circular_shift_left(A, 22)); A = temp;
    f_val = F(B, C, D); temp = D; D = C; C = B;A = A + f_val + m4 +  _mm256_set1_epi32(0xf57c0faf); B = B + (circular_shift_left(A,  7)); A = temp;
    f_val = F(B, C, D); temp = D; D = C; C = B;A = A + f_val + m5 +  _mm256_set1_epi32(0x4787c62a); B = B + (circular_shift_left(A, 12)); A = temp;
    f_val = F(B, C, D); temp = D; D = C; C = B;A = A + f_val + m6 +  _mm256_set1_epi32(0xa8304613); B = B + (circular_shift_left(A, 17)); A = temp;
    f_val = F(B, C, D); temp = D; D = C; C = B;A = A + f_val + m7 +  _mm256_set1_epi32(0xfd469501); B = B + (circular_shift_left(A, 22)); A = temp;
    f_val = F(B, C, D); temp = D; D = C; C = B;A = A + f_val + m8 +  _mm256_set1_epi32(0x698098d8); B = B + (circular_shift_left(A,  7)); A = temp;
    f_val = F(B, C, D); temp = D; D = C; C = B;A = A + f_val + m9 +  _mm256_set1_epi32(0x8b44f7af); B = B + (circular_shift_left(A, 12)); A = temp;
    f_val = F(B, C, D); temp = D; D = C; C = B;A = A + f_val + m10 + _mm256_set1_epi32(0xffff5bb1); B = B + (circular_shift_left(A, 17)); A = temp;
    f_val = F(B, C, D); temp = D; D = C; C = B;A = A + f_val + m11 + _mm256_set1_epi32(0x895cd7be); B = B + (circular_shift_left(A, 22)); A = temp;
    f_val = F(B, C, D); temp = D; D = C; C = B;A = A + f_val + m12 + _mm256_set1_epi32(0x6b901122); B = B + (circular_shift_left(A,  7)); A = temp;
    f_val = F(B, C, D); temp = D; D = C; C = B;A = A + f_val + m13 + _mm256_set1_epi32(0xfd987193); B = B + (circular_shift_left(A, 12)); A = temp;
    f_val = F(B, C, D); temp = D; D = C; C = B;A = A + f_val + m14 + _mm256_set1_epi32(0xa679438e); B = B + (circular_shift_left(A, 17)); A = temp;
    f_val = F(B, C, D); temp = D; D = C; C = B;A = A + f_val + m15 + _mm256_set1_epi32(0x49b40821); B = B + (circular_shift_left(A, 22)); A = temp;
    //Round 2
    f_val = G(B, C, D); temp = D; D = C; C = B;A = A + f_val + m1 +  _mm256_set1_epi32(0xf61e2562); B = B + (circular_shift_left(A,  5)); A = temp;
    f_val = G(B, C, D); temp = D; D = C; C = B;A = A + f_val + m6 +  _mm256_set1_epi32(0xc040b340); B = B + (circular_shift_left(A,  9)); A = temp;
    f_val = G(B, C, D); temp = D; D = C; C = B;A = A + f_val + m11 + _mm256_set1_epi32(0x265e5a51); B = B + (circular_shift_left(A, 14)); A = temp;
    f_val = G(B, C, D); temp = D; D = C; C = B;A = A + f_val + m0 +  _mm256_set1_epi32(0xe9b6c7aa); B = B + (circular_shift_left(A, 20)); A = temp;
    f_val = G(B, C, D); temp = D; D = C; C = B;A = A + f_val + m5 +  _mm256_set1_epi32(0xd62f105d); B = B + (circular_shift_left(A,  5)); A = temp;
    f_val = G(B, C, D); temp = D; D = C; C = B;A = A + f_val + m10 + _mm256_set1_epi32(0x02441453); B = B + (circular_shift_left(A,  9)); A = temp;
    f_val = G(B, C, D); temp = D; D = C; C = B;A = A + f_val + m15 + _mm256_set1_epi32(0xd8a1e681); B = B + (circular_shift_left(A, 14)); A = temp;
    f_val = G(B, C, D); temp = D; D = C; C = B;A = A + f_val + m4 +  _mm256_set1_epi32(0xe7d3fbc8); B = B + (circular_shift_left(A, 20)); A = temp;
    f_val = G(B, C, D); temp = D; D = C; C = B;A = A + f_val + m9 +  _mm256_set1_epi32(0x21e1cde6); B = B + (circular_shift_left(A,  5)); A = temp;
    f_val = G(B, C, D); temp = D; D = C; C = B;A = A + f_val + m14 + _mm256_set1_epi32(0xc33707d6); B = B + (circular_shift_left(A,  9)); A = temp;
    f_val = G(B, C, D); temp = D; D = C; C = B;A = A + f_val + m3 +  _mm256_set1_epi32(0xf4d50d87); B = B + (circular_shift_left(A, 14)); A = temp;
    f_val = G(B, C, D); temp = D; D = C; C = B;A = A + f_val + m8 +  _mm256_set1_epi32(0x455a14ed); B = B + (circular_shift_left(A, 20)); A = temp;
    f_val = G(B, C, D); temp = D; D = C; C = B;A = A + f_val + m13 + _mm256_set1_epi32(0xa9e3e905); B = B + (circular_shift_left(A,  5)); A = temp;
    f_val = G(B, C, D); temp = D; D = C; C = B;A = A + f_val + m2 +  _mm256_set1_epi32(0xfcefa3f8); B = B + (circular_shift_left(A,  9)); A = temp;
    f_val = G(B, C, D); temp = D; D = C; C = B;A = A + f_val + m7 +  _mm256_set1_epi32(0x676f02d9); B = B + (circular_shift_left(A, 14)); A = temp;
    f_val = G(B, C, D); temp = D; D = C; C = B;A = A + f_val + m12 + _mm256_set1_epi32(0x8d2a4c8a); B = B + (circular_shift_left(A, 20)); A = temp;
    //round 3
    f_val = H(B, C, D); temp = D; D = C; C = B;A = A + f_val + m5 +  _mm256_set1_epi32(0xfffa3942); B = B + (circular_shift_left(A,  4)); A = temp;
    f_val = H(B, C, D); temp = D; D = C; C = B;A = A + f_val + m8 +  _mm256_set1_epi32(0x8771f681); B = B + (circular_shift_left(A, 11)); A = temp;
    f_val = H(B, C, D); temp = D; D = C; C = B;A = A + f_val + m11 + _mm256_set1_epi32(0x6d9d6122); B = B + (circular_shift_left(A, 16)); A = temp;
    f_val = H(B, C, D); temp = D; D = C; C = B;A = A + f_val + m14 + _mm256_set1_epi32(0xfde5380c); B = B + (circular_shift_left(A, 23)); A = temp;
    f_val = H(B, C, D); temp = D; D = C; C = B;A = A + f_val + m1 +  _mm256_set1_epi32(0xa4beea44); B = B + (circular_shift_left(A,  4)); A = temp;
    f_val = H(B, C, D); temp = D; D = C; C = B;A = A + f_val + m4 +  _mm256_set1_epi32(0x4bdecfa9); B = B + (circular_shift_left(A, 11)); A = temp;
    f_val = H(B, C, D); temp = D; D = C; C = B;A = A + f_val + m7 +  _mm256_set1_epi32(0xf6bb4b60); B = B + (circular_shift_left(A, 16)); A = temp;
    f_val = H(B, C, D); temp = D; D = C; C = B;A = A + f_val + m10 + _mm256_set1_epi32(0xbebfbc70); B = B + (circular_shift_left(A, 23)); A = temp;
    f_val = H(B, C, D); temp = D; D = C; C = B;A = A + f_val + m13 + _mm256_set1_epi32(0x289b7ec6); B = B + (circular_shift_left(A,  4)); A = temp;
    f_val = H(B, C, D); temp = D; D = C; C = B;A = A + f_val + m0 +  _mm256_set1_epi32(0xeaa127fa); B = B + (circular_shift_left(A, 11)); A = temp;
    f_val = H(B, C, D); temp = D; D = C; C = B;A = A + f_val + m3 +  _mm256_set1_epi32(0xd4ef3085); B = B + (circular_shift_left(A, 16)); A = temp;
    f_val = H(B, C, D); temp = D; D = C; C = B;A = A + f_val + m6 +  _mm256_set1_epi32(0x04881d05); B = B + (circular_shift_left(A, 23)); A = temp;
    f_val = H(B, C, D); temp = D; D = C; C = B;A = A + f_val + m9 +  _mm256_set1_epi32(0xd9d4d039); B = B + (circular_shift_left(A,  4)); A = temp;
    f_val = H(B, C, D); temp = D; D = C; C = B;A = A + f_val + m12 + _mm256_set1_epi32(0xe6db99e5); B = B + (circular_shift_left(A, 11)); A = temp;
    f_val = H(B, C, D); temp = D; D = C; C = B;A = A + f_val + m15 + _mm256_set1_epi32(0x1fa27cf8); B = B + (circular_shift_left(A, 16)); A = temp;
    f_val = H(B, C, D); temp = D; D = C; C = B;A = A + f_val + m2 +  _mm256_set1_epi32(0xc4ac5665); B = B + (circular_shift_left(A, 23)); A = temp;
    //Round 4
    f_val = I(B, C, D); temp = D; D = C; C = B;A = A + f_val + m0 +  _mm256_set1_epi32(0xf4292244); B = B + (circular_shift_left(A,  6)); A = temp;
    f_val = I(B, C, D); temp = D; D = C; C = B;A = A + f_val + m7 +  _mm256_set1_epi32(0x432aff97); B = B + (circular_shift_left(A, 10)); A = temp;
    f_val = I(B, C, D); temp = D; D = C; C = B;A = A + f_val + m14 + _mm256_set1_epi32(0xab9423a7); B = B + (circular_shift_left(A, 15)); A = temp;
    f_val = I(B, C, D); temp = D; D = C; C = B;A = A + f_val + m5 +  _mm256_set1_epi32(0xfc93a039); B = B + (circular_shift_left(A, 21)); A = temp;
    f_val = I(B, C, D); temp = D; D = C; C = B;A = A + f_val + m12 + _mm256_set1_epi32(0x655b59c3); B = B + (circular_shift_left(A,  6)); A = temp;
    f_val = I(B, C, D); temp = D; D = C; C = B;A = A + f_val + m3 +  _mm256_set1_epi32(0x8f0ccc92); B = B + (circular_shift_left(A, 10)); A = temp;
    f_val = I(B, C, D); temp = D; D = C; C = B;A = A + f_val + m10 + _mm256_set1_epi32(0xffeff47d); B = B + (circular_shift_left(A, 15)); A = temp;
    f_val = I(B, C, D); temp = D; D = C; C = B;A = A + f_val + m1 +  _mm256_set1_epi32(0x85845dd1); B = B + (circular_shift_left(A, 21)); A = temp;
    f_val = I(B, C, D); temp = D; D = C; C = B;A = A + f_val + m8 +  _mm256_set1_epi32(0x6fa87e4f); B = B + (circular_shift_left(A,  6)); A = temp;
    f_val = I(B, C, D); temp = D; D = C; C = B;A = A + f_val + m15 + _mm256_set1_epi32(0xfe2ce6e0); B = B + (circular_shift_left(A, 10)); A = temp;
    f_val = I(B, C, D); temp = D; D = C; C = B;A = A + f_val + m6 +  _mm256_set1_epi32(0xa3014314); B = B + (circular_shift_left(A, 15)); A = temp;
    f_val = I(B, C, D); temp = D; D = C; C = B;A = A + f_val + m13 + _mm256_set1_epi32(0x4e0811a1); B = B + (circular_shift_left(A, 21)); A = temp;
    f_val = I(B, C, D); temp = D; D = C; C = B;A = A + f_val + m4 +  _mm256_set1_epi32(0xf7537e82); B = B + (circular_shift_left(A,  6)); A = temp;
    f_val = I(B, C, D); temp = D; D = C; C = B;A = A + f_val + m11 + _mm256_set1_epi32(0xbd3af235); B = B + (circular_shift_left(A, 10)); A = temp;
    f_val = I(B, C, D); temp = D; D = C; C = B;A = A + f_val + m2 +  _mm256_set1_epi32(0x2ad7d2bb); B = B + (circular_shift_left(A, 15)); A = temp;
    f_val = I(B, C, D); temp = D; D = C; C = B;A = A + f_val + m9 +  _mm256_set1_epi32(0xeb86d391); B = B + (circular_shift_left(A, 21)); A = temp;

    A+=a_old; B+=b_old; C+=c_old; D+=d_old;

    uint32_t * fA = (uint32_t*)&A;
    uint32_t * fB = (uint32_t*)&B;
    uint32_t * fC = (uint32_t*)&C;
    uint32_t * fD = (uint32_t*)&D;

    uint32_t A1 = fA[0];
    uint32_t A2 = fA[2];
    uint32_t A3 = fA[4];
    uint32_t A4 = fA[6];

    uint32_t B1 = fB[0];
    uint32_t B2 = fB[2];
    uint32_t B3 = fB[4];
    uint32_t B4 = fB[6];

    uint32_t C1 = fC[0];
    uint32_t C2 = fC[2];
    uint32_t C3 = fC[4];
    uint32_t C4 = fC[6];

    uint32_t D1 = fD[0];
    uint32_t D2 = fD[2];
    uint32_t D3 = fD[4];
    uint32_t D4 = fD[6];
    //now unscramble the message -> change endian type back
    A1 = bswap_32(A1);
    B1 = bswap_32(B1);
    C1 = bswap_32(C1);
    D1 = bswap_32(D1);
    /******************************************/
    A2 = bswap_32(A2);
    B2 = bswap_32(B2);
    C2 = bswap_32(C2);
    D2 = bswap_32(D2);
    /******************************************/
    A3 = bswap_32(A3);
    B3 = bswap_32(B3);
    C3 = bswap_32(C3);
    D3 = bswap_32(D3);
    /******************************************/
    A4 = bswap_32(A4);
    B4 = bswap_32(B4);
    C4 = bswap_32(C4);
    D4 = bswap_32(D4);
    /******************************************/

    //4c467321dd2d571a787706eb4466a09d ZZZZZZ
    if((A1== 0x4c467321) && (B1 == 0xdd2d571a) && (C1 == 0x787706eb) && (D1 == 0x4466a09d)){
        free(message);
        free(message1);
        free(message2);
        free(message3);
        printf("Hash cracked! Message: %s\n", initial_message);

        return 0;
    }
    else if((A2== 0x4c467321) && (B2 == 0xdd2d571a) && (C2 == 0x787706eb) && (D2 == 0x4466a09d)){
        free(message);
        free(message1);
        free(message2);
        free(message3);
        printf("Hash cracked! Message: %s\n", initial_message1);

        return 0;
    }
    else if((A3== 0x4c467321) && (B3 == 0xdd2d571a) && (C3== 0x787706eb) && (D3 == 0x4466a09d)){
        free(message);
        free(message1);
        free(message2);
        free(message3);
        printf("Hash cracked! Message: %s\n", initial_message2);

        return 0;
    }
    else if((A4== 0x4c467321) && (B4 == 0xdd2d571a) && (C4 == 0x787706eb) && (D4 == 0x4466a09d)){
        free(message);
        free(message1);
        free(message2);
        free(message3);
        printf("Hash cracked! Message: %s\n", initial_message3);

        return 0;
    }
    else{
        free(message);
        free(message1);
        free(message2);
        free(message3);
        return 1;
    }


}


uint32_t hashSetter(uint32_t hash1,uint32_t hash2,uint32_t hash3, uint32_t hash4,
                    uint32_t hash5, uint32_t hash6, uint32_t hash7, uint32_t hash8)
{
    return hash1 + hash2 + hash3 + hash4 + hash5 + hash6 + hash7 +hash8;
}

int passwords(int start, int end, int len) {
    uint32_t hashes = 0;
    struct {
        char p5, p4, p3, p2, p1, p0, p_null;
    } p, p1, p2, p3;
    unsigned char *plaintext = (unsigned char *) &p;
    unsigned char *plaintext1 = (unsigned char *) &p1;
    unsigned char *plaintext2 = (unsigned char *) &p2;
    unsigned char *plaintext3 = (unsigned char *) &p3;
    memset(&p, 0, sizeof(p));
    int a, b, c, d, e, f, g, h, i, j = 0;
    for (a = start; a < end; a += 4) {
        p.p5 = char_set[a];
        p1.p5 = char_set[a + 1];
        p2.p5 = char_set[a + 2];
        p3.p5 = char_set[a + 3];
        for (b = start; b < end; b += 4) {
            p.p4 = char_set[b];
            p1.p4 = char_set[b + 1];
            p2.p4 = char_set[b + 2];
            p3.p4 = char_set[b + 3];
            for (c = start; c < end; c += 4) {
                p.p3 = char_set[c];
                p1.p3 = char_set[c + 1];
                p2.p3 = char_set[c + 2];
                p3.p3 = char_set[c + 3];
                for (d = start; d < end; d += 4) {
                    p.p2 = char_set[d];
                    p1.p2 = char_set[d + 1];
                    p2.p2 = char_set[d + 2];
                    p3.p2 = char_set[d + 3];
                    for (e = start; e < end; e += 4) {
                        p.p1 = char_set[e];
                        p1.p1 = char_set[e + 1];
                        p2.p1 = char_set[e + 2];
                        p3.p1 = char_set[e + 3];
                        for (f = start; f < end; f += 4) {
                            p.p0 = char_set[f];
                            p1.p0 = char_set[f + 1];
                            p2.p0 = char_set[f + 2];
                            p3.p0 = char_set[f + 3];
                            hashes++;
                            size_t msg_len = strlen(plaintext);
                            if (gen_md5(plaintext, plaintext1, plaintext2, plaintext3, msg_len) == 0) {
                                clock_t final = clock();
                                printf("Hash Completed in: %f\n", ((double)(final - begin)/CLOCKS_PER_SEC));
                                return hashes;
                            }
                            //printf("test: %s\n", plaintext);
                        }
                    }
                }
            }
        }
    }
    return hashes;
}

void *thread_1(){
    hashes1 = passwords(0,6,10);
    pthread_exit(NULL);
}
void *thread_2(){
    hashes2 = passwords(6,12,10);
    pthread_exit(NULL);
}
void *thread_3(){
    hashes3 = passwords(12,18,10);
    pthread_exit(NULL);
}
void *thread_4(){
    hashes4 = passwords(18,24,10);
    pthread_exit(NULL);
}
void *thread_5(){
    hashes5 = passwords(24,30,10);
    pthread_exit(NULL);
}
void *thread_6(){
    hashes6 = passwords(30,36,10);
    pthread_exit(NULL);
}
void *thread_7(){
    hashes7 = passwords(36,42,10);
    pthread_exit(NULL);
}
void *thread_8(){
    hashes8 = passwords(42,53,10);
    pthread_exit(NULL);
}

int main()//int argc, char* argv[])
{
    pthread_t thread1, thread2, thread3, thread4,thread5, thread6, thread7, thread8;
    begin = clock();
    (void) pthread_create(&thread1, NULL, thread_1, NULL);
    (void) pthread_create(&thread2, NULL, thread_2, NULL);
    (void) pthread_create(&thread3, NULL, thread_3, NULL);
    (void) pthread_create(&thread4, NULL, thread_4, NULL);
    (void) pthread_create(&thread5, NULL, thread_5, NULL);
    (void) pthread_create(&thread6, NULL, thread_6, NULL);
    (void) pthread_create(&thread7, NULL, thread_7, NULL);
    (void) pthread_create(&thread8, NULL, thread_8, NULL);

    (void) pthread_join(thread1, NULL);
    (void) pthread_join(thread2, NULL);
    (void) pthread_join(thread3, NULL);
    (void) pthread_join(thread4, NULL);
    (void) pthread_join(thread5, NULL);
    (void) pthread_join(thread6, NULL);
    (void) pthread_join(thread7, NULL);
    (void) pthread_join(thread8, NULL);

    end = clock();
    int hashes = hashSetter(hashes1,hashes2, hashes3, hashes4, hashes5, hashes6, hashes7, hashes8);

    printf("Time to completion: %f\n", ((double)(end - begin)/CLOCKS_PER_SEC));
    printf("Hashes per second: %f\n", (hashes*8*4)/((double)(end - begin)/CLOCKS_PER_SEC)); // ((double)(end - begin)/CLOCKS_PER_SEC));

    return 0;
}
