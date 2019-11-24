/* XMRig
 * Copyright 2010      Jeff Garzik <jgarzik@pobox.com>
 * Copyright 2012-2014 pooler      <pooler@litecoinpool.org>
 * Copyright 2014      Lucas Jones <https://github.com/lucasjones>
 * Copyright 2014-2016 Wolf9466    <https://github.com/OhGodAPet>
 * Copyright 2016      Jay D Dee   <jayddee246@gmail.com>
 * Copyright 2017-2019 XMR-Stak    <https://github.com/fireice-uk>, <https://github.com/psychocrypt>
 * Copyright 2018      Lee Clagett <https://github.com/vtnerd>
 * Copyright 2018-2019 SChernykh   <https://github.com/SChernykh>
 * Copyright 2016-2019 XMRig       <https://github.com/xmrig>, <support@xmrig.com>
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef XMRIG_CRYPTONIGHT_X86_H
#define XMRIG_CRYPTONIGHT_X86_H


#ifdef __GNUC__
#   include <x86intrin.h>
#else
#   include <intrin.h>
#   define __restrict__ __restrict
#endif


#include "backend/cpu/Cpu.h"
#include "crypto/cn/CnAlgo.h"
#include "crypto/cn/CryptoNight_monero.h"
#include "crypto/cn/CryptoNight.h"
#include "crypto/cn/soft_aes.h"
#include "crypto/common/keccak.h"


extern "C"
{
#include "crypto/cn/c_groestl.h"
#include "crypto/cn/c_blake256.h"
#include "crypto/cn/c_jh.h"
#include "crypto/cn/c_skein.h"
}

#ifndef FORCEINLINE
#ifdef __GNUC__
#define FORCEINLINE __attribute__((always_inline)) inline
#elif _MSC_VER
#define FORCEINLINE __forceinline
#else
#define FORCEINLINE inline
#endif
#endif

#ifndef UNREACHABLE_CODE
#ifdef __GNUC__
#define UNREACHABLE_CODE __builtin_unreachable()
#elif _MSC_VER
#define UNREACHABLE_CODE __assume(false)
#else
#define UNREACHABLE_CODE
#endif
#endif


static inline void do_blake_hash(const uint8_t *input, size_t len, uint8_t *output) {
    blake256_hash(output, input, len);
}


static inline void do_groestl_hash(const uint8_t *input, size_t len, uint8_t *output) {
    groestl(input, len * 8, output);
}


static inline void do_jh_hash(const uint8_t *input, size_t len, uint8_t *output) {
    jh_hash(32 * 8, input, 8 * len, output);
}


static inline void do_skein_hash(const uint8_t *input, size_t len, uint8_t *output) {
    xmr_skein(input, output);
}


void (* const extra_hashes[4])(const uint8_t *, size_t, uint8_t *) = {do_blake_hash, do_groestl_hash, do_jh_hash, do_skein_hash};


#if defined(__x86_64__) || defined(_M_AMD64)
#   ifdef __GNUC__
static inline uint64_t __umul128(uint64_t a, uint64_t b, uint64_t* hi)
{
    unsigned __int128 r = (unsigned __int128) a * (unsigned __int128) b;
    *hi = r >> 64;
    return (uint64_t) r;
}
#   else
    #define __umul128 _umul128
#   endif
#elif defined(__i386__) || defined(_M_IX86)
static inline int64_t _mm_cvtsi128_si64(__m128i a)
{
    return ((uint64_t)(uint32_t)_mm_cvtsi128_si32(a) | ((uint64_t)(uint32_t)_mm_cvtsi128_si32(_mm_srli_si128(a, 4)) << 32));
}

static inline __m128i _mm_cvtsi64_si128(int64_t a) {
    return _mm_set_epi64x(0, a);
}

static inline uint64_t __umul128(uint64_t multiplier, uint64_t multiplicand, uint64_t *product_hi) {
    // multiplier   = ab = a * 2^32 + b
    // multiplicand = cd = c * 2^32 + d
    // ab * cd = a * c * 2^64 + (a * d + b * c) * 2^32 + b * d
    uint64_t a = multiplier >> 32;
    uint64_t b = multiplier & 0xFFFFFFFF;
    uint64_t c = multiplicand >> 32;
    uint64_t d = multiplicand & 0xFFFFFFFF;

    //uint64_t ac = a * c;
    uint64_t ad = a * d;
    //uint64_t bc = b * c;
    uint64_t bd = b * d;

    uint64_t adbc = ad + (b * c);
    uint64_t adbc_carry = adbc < ad ? 1 : 0;

    // multiplier * multiplicand = product_hi * 2^64 + product_lo
    uint64_t product_lo = bd + (adbc << 32);
    uint64_t product_lo_carry = product_lo < bd ? 1 : 0;
    *product_hi = (a * c) + (adbc >> 32) + (adbc_carry << 32) + product_lo_carry;

    return product_lo;
}
#endif


// This will shift and xor tmp1 into itself as 4 32-bit vals such as
// sl_xor(a1 a2 a3 a4) = a1 (a2^a1) (a3^a2^a1) (a4^a3^a2^a1)
static inline __m128i sl_xor(__m128i tmp1)
{
    __m128i tmp4;
    tmp4 = _mm_slli_si128(tmp1, 0x04);
    tmp1 = _mm_xor_si128(tmp1, tmp4);
    tmp4 = _mm_slli_si128(tmp4, 0x04);
    tmp1 = _mm_xor_si128(tmp1, tmp4);
    tmp4 = _mm_slli_si128(tmp4, 0x04);
    tmp1 = _mm_xor_si128(tmp1, tmp4);
    return tmp1;
}


template<uint8_t rcon>
static inline void aes_genkey_sub(__m128i* xout0, __m128i* xout2)
{
    __m128i xout1 = _mm_aeskeygenassist_si128(*xout2, rcon);
    xout1  = _mm_shuffle_epi32(xout1, 0xFF); // see PSHUFD, set all elems to 4th elem
    *xout0 = sl_xor(*xout0);
    *xout0 = _mm_xor_si128(*xout0, xout1);
    xout1  = _mm_aeskeygenassist_si128(*xout0, 0x00);
    xout1  = _mm_shuffle_epi32(xout1, 0xAA); // see PSHUFD, set all elems to 3rd elem
    *xout2 = sl_xor(*xout2);
    *xout2 = _mm_xor_si128(*xout2, xout1);
}


template<uint8_t rcon>
static inline void soft_aes_genkey_sub(__m128i* xout0, __m128i* xout2)
{
    __m128i xout1 = soft_aeskeygenassist<rcon>(*xout2);
    xout1  = _mm_shuffle_epi32(xout1, 0xFF); // see PSHUFD, set all elems to 4th elem
    *xout0 = sl_xor(*xout0);
    *xout0 = _mm_xor_si128(*xout0, xout1);
    xout1  = soft_aeskeygenassist<0x00>(*xout0);
    xout1  = _mm_shuffle_epi32(xout1, 0xAA); // see PSHUFD, set all elems to 3rd elem
    *xout2 = sl_xor(*xout2);
    *xout2 = _mm_xor_si128(*xout2, xout1);
}


template<bool SOFT_AES>
static inline void aes_genkey(const __m128i* memory, __m128i* k0, __m128i* k1, __m128i* k2, __m128i* k3, __m128i* k4, __m128i* k5, __m128i* k6, __m128i* k7, __m128i* k8, __m128i* k9)
{
    __m128i xout0 = _mm_load_si128(memory);
    __m128i xout2 = _mm_load_si128(memory + 1);
    *k0 = xout0;
    *k1 = xout2;

    SOFT_AES ? soft_aes_genkey_sub<0x01>(&xout0, &xout2) : aes_genkey_sub<0x01>(&xout0, &xout2);
    *k2 = xout0;
    *k3 = xout2;

    SOFT_AES ? soft_aes_genkey_sub<0x02>(&xout0, &xout2) : aes_genkey_sub<0x02>(&xout0, &xout2);
    *k4 = xout0;
    *k5 = xout2;

    SOFT_AES ? soft_aes_genkey_sub<0x04>(&xout0, &xout2) : aes_genkey_sub<0x04>(&xout0, &xout2);
    *k6 = xout0;
    *k7 = xout2;

    SOFT_AES ? soft_aes_genkey_sub<0x08>(&xout0, &xout2) : aes_genkey_sub<0x08>(&xout0, &xout2);
    *k8 = xout0;
    *k9 = xout2;
}


static FORCEINLINE void soft_aesenc(void* __restrict ptr, const void* __restrict key, const uint32_t* __restrict t)
{
    uint32_t x0 = ((const uint32_t*)(ptr))[0];
    uint32_t x1 = ((const uint32_t*)(ptr))[1];
    uint32_t x2 = ((const uint32_t*)(ptr))[2];
    uint32_t x3 = ((const uint32_t*)(ptr))[3];

    uint32_t y0 = t[x0 & 0xff]; x0 >>= 8;
    uint32_t y1 = t[x1 & 0xff]; x1 >>= 8;
    uint32_t y2 = t[x2 & 0xff]; x2 >>= 8;
    uint32_t y3 = t[x3 & 0xff]; x3 >>= 8;
    t += 256;

    y0 ^= t[x1 & 0xff]; x1 >>= 8;
    y1 ^= t[x2 & 0xff]; x2 >>= 8;
    y2 ^= t[x3 & 0xff]; x3 >>= 8;
    y3 ^= t[x0 & 0xff]; x0 >>= 8;
    t += 256;

    y0 ^= t[x2 & 0xff]; x2 >>= 8;
    y1 ^= t[x3 & 0xff]; x3 >>= 8;
    y2 ^= t[x0 & 0xff]; x0 >>= 8;
    y3 ^= t[x1 & 0xff]; x1 >>= 8;
    t += 256;

    y0 ^= t[x3];
    y1 ^= t[x0];
    y2 ^= t[x1];
    y3 ^= t[x2];

    ((uint32_t*)ptr)[0] = y0 ^ ((uint32_t*)key)[0];
    ((uint32_t*)ptr)[1] = y1 ^ ((uint32_t*)key)[1];
    ((uint32_t*)ptr)[2] = y2 ^ ((uint32_t*)key)[2];
    ((uint32_t*)ptr)[3] = y3 ^ ((uint32_t*)key)[3];
}

static FORCEINLINE __m128i soft_aesenc(const void* __restrict ptr, const __m128i key, const uint32_t* __restrict t)
{
    uint32_t x0 = ((const uint32_t*)(ptr))[0];
    uint32_t x1 = ((const uint32_t*)(ptr))[1];
    uint32_t x2 = ((const uint32_t*)(ptr))[2];
    uint32_t x3 = ((const uint32_t*)(ptr))[3];

    uint32_t y0 = t[x0 & 0xff]; x0 >>= 8;
    uint32_t y1 = t[x1 & 0xff]; x1 >>= 8;
    uint32_t y2 = t[x2 & 0xff]; x2 >>= 8;
    uint32_t y3 = t[x3 & 0xff]; x3 >>= 8;
    t += 256;

    y0 ^= t[x1 & 0xff]; x1 >>= 8;
    y1 ^= t[x2 & 0xff]; x2 >>= 8;
    y2 ^= t[x3 & 0xff]; x3 >>= 8;
    y3 ^= t[x0 & 0xff]; x0 >>= 8;
    t += 256;

    y0 ^= t[x2 & 0xff]; x2 >>= 8;
    y1 ^= t[x3 & 0xff]; x3 >>= 8;
    y2 ^= t[x0 & 0xff]; x0 >>= 8;
    y3 ^= t[x1 & 0xff]; x1 >>= 8;

    y0 ^= t[x3 + 256];
    y1 ^= t[x0 + 256];
    y2 ^= t[x1 + 256];
    y3 ^= t[x2 + 256];

    return _mm_xor_si128(_mm_set_epi32(y3, y2, y1, y0), key);
}

template<bool SOFT_AES>
void aes_round(__m128i key, __m128i* x0, __m128i* x1, __m128i* x2, __m128i* x3, __m128i* x4, __m128i* x5, __m128i* x6, __m128i* x7);

template<>
NOINLINE void aes_round<true>(__m128i key, __m128i* x0, __m128i* x1, __m128i* x2, __m128i* x3, __m128i* x4, __m128i* x5, __m128i* x6, __m128i* x7)
{
    *x0 = soft_aesenc((uint32_t*)x0, key, (const uint32_t*)saes_table);
    *x1 = soft_aesenc((uint32_t*)x1, key, (const uint32_t*)saes_table);
    *x2 = soft_aesenc((uint32_t*)x2, key, (const uint32_t*)saes_table);
    *x3 = soft_aesenc((uint32_t*)x3, key, (const uint32_t*)saes_table);
    *x4 = soft_aesenc((uint32_t*)x4, key, (const uint32_t*)saes_table);
    *x5 = soft_aesenc((uint32_t*)x5, key, (const uint32_t*)saes_table);
    *x6 = soft_aesenc((uint32_t*)x6, key, (const uint32_t*)saes_table);
    *x7 = soft_aesenc((uint32_t*)x7, key, (const uint32_t*)saes_table);
}

template<>
FORCEINLINE void aes_round<false>(__m128i key, __m128i* x0, __m128i* x1, __m128i* x2, __m128i* x3, __m128i* x4, __m128i* x5, __m128i* x6, __m128i* x7)
{
    *x0 = _mm_aesenc_si128(*x0, key);
    *x1 = _mm_aesenc_si128(*x1, key);
    *x2 = _mm_aesenc_si128(*x2, key);
    *x3 = _mm_aesenc_si128(*x3, key);
    *x4 = _mm_aesenc_si128(*x4, key);
    *x5 = _mm_aesenc_si128(*x5, key);
    *x6 = _mm_aesenc_si128(*x6, key);
    *x7 = _mm_aesenc_si128(*x7, key);
}

namespace xmrig {


template<bool SOFT_AES>
static inline void cn_explode_scratchpad(const __m128i *input, __m128i *output)
{
    constexpr CnAlgo props;

    __m128i xin0, xin1, xin2, xin3, xin4, xin5, xin6, xin7;
    __m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9;

    aes_genkey<SOFT_AES>(input, &k0, &k1, &k2, &k3, &k4, &k5, &k6, &k7, &k8, &k9);

    xin0 = _mm_load_si128(input + 4);
    xin1 = _mm_load_si128(input + 5);
    xin2 = _mm_load_si128(input + 6);
    xin3 = _mm_load_si128(input + 7);
    xin4 = _mm_load_si128(input + 8);
    xin5 = _mm_load_si128(input + 9);
    xin6 = _mm_load_si128(input + 10);
    xin7 = _mm_load_si128(input + 11);

    for (size_t i = 0; i < props.memory() / sizeof(__m128i); i += 8) {
        aes_round<SOFT_AES>(k0, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k1, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k2, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k3, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k4, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k5, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k6, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k7, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k8, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
        aes_round<SOFT_AES>(k9, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);

        _mm_store_si128(output + i + 0, xin0);
        _mm_store_si128(output + i + 1, xin1);
        _mm_store_si128(output + i + 2, xin2);
        _mm_store_si128(output + i + 3, xin3);
        _mm_store_si128(output + i + 4, xin4);
        _mm_store_si128(output + i + 5, xin5);
        _mm_store_si128(output + i + 6, xin6);
        _mm_store_si128(output + i + 7, xin7);
    }
}


template<bool SOFT_AES>
static inline void cn_implode_scratchpad(const __m128i *input, __m128i *output)
{
    constexpr CnAlgo props;

    __m128i xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7;
    __m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9;

    aes_genkey<SOFT_AES>(output + 2, &k0, &k1, &k2, &k3, &k4, &k5, &k6, &k7, &k8, &k9);

    xout0 = _mm_load_si128(output + 4);
    xout1 = _mm_load_si128(output + 5);
    xout2 = _mm_load_si128(output + 6);
    xout3 = _mm_load_si128(output + 7);
    xout4 = _mm_load_si128(output + 8);
    xout5 = _mm_load_si128(output + 9);
    xout6 = _mm_load_si128(output + 10);
    xout7 = _mm_load_si128(output + 11);

    for (size_t i = 0; i < props.memory() / sizeof(__m128i); i += 8) {
        xout0 = _mm_xor_si128(_mm_load_si128(input + i + 0), xout0);
        xout1 = _mm_xor_si128(_mm_load_si128(input + i + 1), xout1);
        xout2 = _mm_xor_si128(_mm_load_si128(input + i + 2), xout2);
        xout3 = _mm_xor_si128(_mm_load_si128(input + i + 3), xout3);
        xout4 = _mm_xor_si128(_mm_load_si128(input + i + 4), xout4);
        xout5 = _mm_xor_si128(_mm_load_si128(input + i + 5), xout5);
        xout6 = _mm_xor_si128(_mm_load_si128(input + i + 6), xout6);
        xout7 = _mm_xor_si128(_mm_load_si128(input + i + 7), xout7);

        aes_round<SOFT_AES>(k0, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k1, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k2, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k3, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k4, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k5, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k6, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k7, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k8, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
        aes_round<SOFT_AES>(k9, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
    }

    _mm_store_si128(output + 4, xout0);
    _mm_store_si128(output + 5, xout1);
    _mm_store_si128(output + 6, xout2);
    _mm_store_si128(output + 7, xout3);
    _mm_store_si128(output + 8, xout4);
    _mm_store_si128(output + 9, xout5);
    _mm_store_si128(output + 10, xout6);
    _mm_store_si128(output + 11, xout7);
}


} /* namespace xmrig */


static inline __m128i aes_round_tweak_div(const __m128i &in, const __m128i &key)
{
    alignas(16) uint32_t k[4];
    alignas(16) uint32_t x[4];

    _mm_store_si128((__m128i*) k, key);
    _mm_store_si128((__m128i*) x, _mm_xor_si128(in, _mm_set_epi64x(0xffffffffffffffff, 0xffffffffffffffff)));

    #define BYTE(p, i) ((unsigned char*)&x[p])[i]
    k[0] ^= saes_table[0][BYTE(0, 0)] ^ saes_table[1][BYTE(1, 1)] ^ saes_table[2][BYTE(2, 2)] ^ saes_table[3][BYTE(3, 3)];
    x[0] ^= k[0];
    k[1] ^= saes_table[0][BYTE(1, 0)] ^ saes_table[1][BYTE(2, 1)] ^ saes_table[2][BYTE(3, 2)] ^ saes_table[3][BYTE(0, 3)];
    x[1] ^= k[1];
    k[2] ^= saes_table[0][BYTE(2, 0)] ^ saes_table[1][BYTE(3, 1)] ^ saes_table[2][BYTE(0, 2)] ^ saes_table[3][BYTE(1, 3)];
    x[2] ^= k[2];
    k[3] ^= saes_table[0][BYTE(3, 0)] ^ saes_table[1][BYTE(0, 1)] ^ saes_table[2][BYTE(1, 2)] ^ saes_table[3][BYTE(2, 3)];
    #undef BYTE

    return _mm_load_si128((__m128i*)k);
}


static inline __m128i int_sqrt_v2(const uint64_t n0)
{
    __m128d x = _mm_castsi128_pd(_mm_add_epi64(_mm_cvtsi64_si128(n0 >> 12), _mm_set_epi64x(0, 1023ULL << 52)));
    x = _mm_sqrt_sd(_mm_setzero_pd(), x);
    uint64_t r = static_cast<uint64_t>(_mm_cvtsi128_si64(_mm_castpd_si128(x)));

    const uint64_t s = r >> 20;
    r >>= 19;

    uint64_t x2 = (s - (1022ULL << 32)) * (r - s - (1022ULL << 32) + 1);
#   if (defined(_MSC_VER) || __GNUC__ > 7 || (__GNUC__ == 7 && __GNUC_MINOR__ > 1)) && (defined(__x86_64__) || defined(_M_AMD64))
    _addcarry_u64(_subborrow_u64(0, x2, n0, (unsigned long long int*)&x2), r, 0, (unsigned long long int*)&r);
#   else
    if (x2 < n0) ++r;
#   endif

    return _mm_cvtsi64_si128(r);
}

namespace xmrig {


static inline void cryptonight_monero_tweak(uint64_t *mem_out, const uint8_t *l, uint64_t idx, __m128i ax0, __m128i bx0, __m128i bx1, __m128i& cx)
{
    constexpr CnAlgo props;

    VARIANT2_SHUFFLE(l, idx, ax0, bx0, bx1, cx, 0);
    _mm_store_si128(reinterpret_cast<__m128i *>(mem_out), _mm_xor_si128(bx0, cx));
}


template<bool SOFT_AES>
inline void cryptonight_single_hash(const uint8_t *__restrict__ input, size_t size, uint8_t *__restrict__ output, cryptonight_ctx **__restrict__ ctx, uint64_t height, uint64_t extra_iters)
{
    constexpr CnAlgo props;
    constexpr size_t MASK        = props.mask();

    uint32_t iters = (props.iterations() + extra_iters) >> 1;

    keccak(input, size, ctx[0]->state);
    cn_explode_scratchpad<SOFT_AES>(reinterpret_cast<const __m128i *>(ctx[0]->state), reinterpret_cast<__m128i *>(ctx[0]->memory));

    uint64_t *h0 = reinterpret_cast<uint64_t*>(ctx[0]->state);
    uint8_t *l0   = ctx[0]->memory;

    VARIANT2_INIT(0);
    VARIANT2_SET_ROUNDING_MODE();

    uint64_t al0  = h0[0] ^ h0[4];
    uint64_t ah0  = h0[1] ^ h0[5];
    uint64_t idx0 = al0;
    __m128i bx0   = _mm_set_epi64x(static_cast<int64_t>(h0[3] ^ h0[7]), static_cast<int64_t>(h0[2] ^ h0[6]));
    __m128i bx1   = _mm_set_epi64x(static_cast<int64_t>(h0[9] ^ h0[11]), static_cast<int64_t>(h0[8] ^ h0[10]));

    for (size_t i = 0; i < iters; i++) {
        __m128i cx;
        if (!SOFT_AES) {
            cx = _mm_load_si128(reinterpret_cast<const __m128i *>(&l0[idx0 & MASK]));
        }

        const __m128i ax0 = _mm_set_epi64x(static_cast<int64_t>(ah0), static_cast<int64_t>(al0));
        if (SOFT_AES) {
            cx = soft_aesenc(&l0[idx0 & MASK], ax0, reinterpret_cast<const uint32_t*>(saes_table));
        }
        else {
            cx = _mm_aesenc_si128(cx, ax0);
        }

        cryptonight_monero_tweak(reinterpret_cast<uint64_t*>(&l0[idx0 & MASK]), l0, idx0 & MASK, ax0, bx0, bx1, cx);

        idx0 = static_cast<uint64_t>(_mm_cvtsi128_si64(cx));

        uint64_t hi, lo, cl, ch;
        cl = (reinterpret_cast<uint64_t*>(&l0[idx0 & MASK]))[0];
        ch = (reinterpret_cast<uint64_t*>(&l0[idx0 & MASK]))[1];

        VARIANT2_INTEGER_MATH(0, cl, cx);

        lo = __umul128(idx0, cl, &hi);

        VARIANT2_SHUFFLE2(l0, idx0 & MASK, ax0, bx0, bx1, hi, lo, 0);

        al0 += hi;
        ah0 += lo;

        reinterpret_cast<uint64_t*>(&l0[idx0 & MASK])[0] = al0;
        reinterpret_cast<uint64_t*>(&l0[idx0 & MASK])[1] = ah0;

        al0 ^= cl;
        ah0 ^= ch;
        idx0 = al0;
        bx1 = bx0;

        bx0 = cx;
    }

    cn_implode_scratchpad<SOFT_AES>(reinterpret_cast<const __m128i *>(ctx[0]->memory), reinterpret_cast<__m128i *>(ctx[0]->state));
    keccakf(h0, 24);
    extra_hashes[ctx[0]->state[0] & 3](ctx[0]->state, 200, output);
}


} /* namespace xmrig */

namespace xmrig {


template<bool SOFT_AES>
inline void cryptonight_double_hash(const uint8_t *__restrict__ input, size_t size, uint8_t *__restrict__ output, cryptonight_ctx **__restrict__ ctx, uint64_t height, uint64_t extra_iters)
{
    constexpr CnAlgo props;
    constexpr size_t MASK        = props.mask();

    uint32_t iters = (props.iterations() + extra_iters) >> 1;

    keccak(input,        size, ctx[0]->state);
    keccak(input + size, size, ctx[1]->state);

    uint8_t *l0  = ctx[0]->memory;
    uint8_t *l1  = ctx[1]->memory;
    uint64_t *h0 = reinterpret_cast<uint64_t*>(ctx[0]->state);
    uint64_t *h1 = reinterpret_cast<uint64_t*>(ctx[1]->state);

    VARIANT2_INIT(0);
    VARIANT2_INIT(1);
    VARIANT2_SET_ROUNDING_MODE();

    cn_explode_scratchpad<SOFT_AES>(reinterpret_cast<const __m128i *>(h0), reinterpret_cast<__m128i *>(l0));
    cn_explode_scratchpad<SOFT_AES>(reinterpret_cast<const __m128i *>(h1), reinterpret_cast<__m128i *>(l1));

    uint64_t al0 = h0[0] ^ h0[4];
    uint64_t al1 = h1[0] ^ h1[4];
    uint64_t ah0 = h0[1] ^ h0[5];
    uint64_t ah1 = h1[1] ^ h1[5];

    __m128i bx00 = _mm_set_epi64x(h0[3] ^ h0[7], h0[2] ^ h0[6]);
    __m128i bx01 = _mm_set_epi64x(h0[9] ^ h0[11], h0[8] ^ h0[10]);
    __m128i bx10 = _mm_set_epi64x(h1[3] ^ h1[7], h1[2] ^ h1[6]);
    __m128i bx11 = _mm_set_epi64x(h1[9] ^ h1[11], h1[8] ^ h1[10]);

    uint64_t idx0 = al0;
    uint64_t idx1 = al1;

    for (size_t i = 0; i < iters; i++) {
        __m128i cx0, cx1;
        if (!SOFT_AES) {
            cx0 = _mm_load_si128(reinterpret_cast<const __m128i *>(&l0[idx0 & MASK]));
            cx1 = _mm_load_si128(reinterpret_cast<const __m128i *>(&l1[idx1 & MASK]));
        }

        const __m128i ax0 = _mm_set_epi64x(ah0, al0);
        const __m128i ax1 = _mm_set_epi64x(ah1, al1);
        if (SOFT_AES) {
            cx0 = soft_aesenc(&l0[idx0 & MASK], ax0, reinterpret_cast<const uint32_t*>(saes_table));
            cx1 = soft_aesenc(&l1[idx1 & MASK], ax1, reinterpret_cast<const uint32_t*>(saes_table));
        }
        else {
            cx0 = _mm_aesenc_si128(cx0, ax0);
            cx1 = _mm_aesenc_si128(cx1, ax1);
        }

        cryptonight_monero_tweak((uint64_t*)&l0[idx0 & MASK], l0, idx0 & MASK, ax0, bx00, bx01, cx0);
        cryptonight_monero_tweak((uint64_t*)&l1[idx1 & MASK], l1, idx1 & MASK, ax1, bx10, bx11, cx1);

        idx0 = _mm_cvtsi128_si64(cx0);
        idx1 = _mm_cvtsi128_si64(cx1);

        uint64_t hi, lo, cl, ch;
        cl = ((uint64_t*) &l0[idx0 & MASK])[0];
        ch = ((uint64_t*) &l0[idx0 & MASK])[1];

        VARIANT2_INTEGER_MATH(0, cl, cx0);

        lo = __umul128(idx0, cl, &hi);

        VARIANT2_SHUFFLE2(l0, idx0 & MASK, ax0, bx00, bx01, hi, lo, 0);

        al0 += hi;
        ah0 += lo;

        ((uint64_t*)&l0[idx0 & MASK])[0] = al0;
        ((uint64_t*) &l0[idx0 & MASK])[1] = ah0;

        al0 ^= cl;
        ah0 ^= ch;
        idx0 = al0;

        cl = ((uint64_t*) &l1[idx1 & MASK])[0];
        ch = ((uint64_t*) &l1[idx1 & MASK])[1];

        VARIANT2_INTEGER_MATH(1, cl, cx1);

        lo = __umul128(idx1, cl, &hi);

        VARIANT2_SHUFFLE2(l1, idx1 & MASK, ax1, bx10, bx11, hi, lo, 0);

        al1 += hi;
        ah1 += lo;

        ((uint64_t*)&l1[idx1 & MASK])[0] = al1;
        ((uint64_t*)&l1[idx1 & MASK])[1] = ah1;

        al1 ^= cl;
        ah1 ^= ch;
        idx1 = al1;

        bx01 = bx00;
        bx11 = bx10;

        bx00 = cx0;
        bx10 = cx1;
    }

    cn_implode_scratchpad<SOFT_AES>(reinterpret_cast<const __m128i *>(l0), reinterpret_cast<__m128i *>(h0));
    cn_implode_scratchpad<SOFT_AES>(reinterpret_cast<const __m128i *>(l1), reinterpret_cast<__m128i *>(h1));

    keccakf(h0, 24);
    keccakf(h1, 24);

    extra_hashes[ctx[0]->state[0] & 3](ctx[0]->state, 200, output);
    extra_hashes[ctx[1]->state[0] & 3](ctx[1]->state, 200, output + 32);
}


#define CN_STEP1(a, b0, b1, c, l, ptr, idx)           \
    ptr = reinterpret_cast<__m128i*>(&l[idx & MASK]); \
    c = _mm_load_si128(ptr);


#define CN_STEP2(a, b0, b1, c, l, ptr, idx)                                             \
    if (SOFT_AES) {                                                                \
        c = soft_aesenc(&c, a, (const uint32_t*)saes_table);                            \
    } else {                                                                            \
        c = _mm_aesenc_si128(c, a);                                                     \
    }                                                                                   \
    cryptonight_monero_tweak((uint64_t*)ptr, l, idx & MASK, a, b0, b1, c);


#define CN_STEP3(part, a, b0, b1, c, l, ptr, idx)     \
    idx = _mm_cvtsi128_si64(c);                       \
    ptr = reinterpret_cast<__m128i*>(&l[idx & MASK]); \
    uint64_t cl##part = ((uint64_t*)ptr)[0];          \
    uint64_t ch##part = ((uint64_t*)ptr)[1];


#define CN_STEP4(part, a, b0, b1, c, l, mc, ptr, idx)                                                       \
    VARIANT2_INTEGER_MATH(part, cl##part, c);                                                           \
    lo = __umul128(idx, cl##part, &hi);                                                                     \
    VARIANT2_SHUFFLE2(l, idx & MASK, a, b0, b1, hi, lo, 0);           \
    a = _mm_add_epi64(a, _mm_set_epi64x(lo, hi));                                                           \
                                                                                                            \
    _mm_store_si128(ptr, a);                                                                            \
                                                                                                            \
    a = _mm_xor_si128(a, _mm_set_epi64x(ch##part, cl##part));                                               \
    idx = _mm_cvtsi128_si64(a);                                                                             \
    b1 = b0;                                                                                            \
    b0 = c;


#define CONST_INIT(ctx, n)                                                                       \
    __m128i division_result_xmm_##n;                                                             \
    __m128i sqrt_result_xmm_##n;                                                                 \
    division_result_xmm_##n = _mm_cvtsi64_si128(h##n[12]);                                   \
    sqrt_result_xmm_##n = _mm_cvtsi64_si128(h##n[13]);                                       \
    __m128i ax##n = _mm_set_epi64x(h##n[1] ^ h##n[5], h##n[0] ^ h##n[4]);                        \
    __m128i bx##n##0 = _mm_set_epi64x(h##n[3] ^ h##n[7], h##n[2] ^ h##n[6]);                     \
    __m128i bx##n##1 = _mm_set_epi64x(h##n[9] ^ h##n[11], h##n[8] ^ h##n[10]);                   \
    __m128i cx##n = _mm_setzero_si128();


template<bool SOFT_AES>
inline void cryptonight_triple_hash(const uint8_t *__restrict__ input, size_t size, uint8_t *__restrict__ output, cryptonight_ctx **__restrict__ ctx, uint64_t height, uint64_t extra_iters)
{
    constexpr CnAlgo props;
    constexpr size_t MASK        = props.mask();

    uint32_t iters = (props.iterations() + extra_iters) >> 1;

    for (size_t i = 0; i < 3; i++) {
        keccak(input + size * i, size, ctx[i]->state);
        cn_explode_scratchpad<SOFT_AES>(reinterpret_cast<const __m128i*>(ctx[i]->state), reinterpret_cast<__m128i*>(ctx[i]->memory));
    }

    uint8_t* l0  = ctx[0]->memory;
    uint8_t* l1  = ctx[1]->memory;
    uint8_t* l2  = ctx[2]->memory;
    uint64_t* h0 = reinterpret_cast<uint64_t*>(ctx[0]->state);
    uint64_t* h1 = reinterpret_cast<uint64_t*>(ctx[1]->state);
    uint64_t* h2 = reinterpret_cast<uint64_t*>(ctx[2]->state);

    CONST_INIT(ctx[0], 0);
    CONST_INIT(ctx[1], 1);
    CONST_INIT(ctx[2], 2);
    VARIANT2_SET_ROUNDING_MODE();

    uint64_t idx0, idx1, idx2;
    idx0 = _mm_cvtsi128_si64(ax0);
    idx1 = _mm_cvtsi128_si64(ax1);
    idx2 = _mm_cvtsi128_si64(ax2);

    for (size_t i = 0; i < iters; i++) {
        uint64_t hi, lo;
        __m128i *ptr0, *ptr1, *ptr2;

        CN_STEP1(ax0, bx00, bx01, cx0, l0, ptr0, idx0);
        CN_STEP1(ax1, bx10, bx11, cx1, l1, ptr1, idx1);
        CN_STEP1(ax2, bx20, bx21, cx2, l2, ptr2, idx2);

        CN_STEP2(ax0, bx00, bx01, cx0, l0, ptr0, idx0);
        CN_STEP2(ax1, bx10, bx11, cx1, l1, ptr1, idx1);
        CN_STEP2(ax2, bx20, bx21, cx2, l2, ptr2, idx2);

        CN_STEP3(0, ax0, bx00, bx01, cx0, l0, ptr0, idx0);
        CN_STEP3(1, ax1, bx10, bx11, cx1, l1, ptr1, idx1);
        CN_STEP3(2, ax2, bx20, bx21, cx2, l2, ptr2, idx2);

        CN_STEP4(0, ax0, bx00, bx01, cx0, l0, mc0, ptr0, idx0);
        CN_STEP4(1, ax1, bx10, bx11, cx1, l1, mc1, ptr1, idx1);
        CN_STEP4(2, ax2, bx20, bx21, cx2, l2, mc2, ptr2, idx2);
    }

    for (size_t i = 0; i < 3; i++) {
        cn_implode_scratchpad<SOFT_AES>(reinterpret_cast<const __m128i*>(ctx[i]->memory), reinterpret_cast<__m128i*>(ctx[i]->state));
        keccakf(reinterpret_cast<uint64_t*>(ctx[i]->state), 24);
        extra_hashes[ctx[i]->state[0] & 3](ctx[i]->state, 200, output + 32 * i);
    }
}


template<bool SOFT_AES>
inline void cryptonight_quad_hash(const uint8_t *__restrict__ input, size_t size, uint8_t *__restrict__ output, cryptonight_ctx **__restrict__ ctx, uint64_t height, uint64_t extra_iters)
{
    constexpr CnAlgo props;
    constexpr size_t MASK        = props.mask();

    uint32_t iters = (props.iterations() + extra_iters) >> 1;

    for (size_t i = 0; i < 4; i++) {
        keccak(input + size * i, size, ctx[i]->state);
        cn_explode_scratchpad<SOFT_AES>(reinterpret_cast<const __m128i*>(ctx[i]->state), reinterpret_cast<__m128i*>(ctx[i]->memory));
    }

    uint8_t* l0  = ctx[0]->memory;
    uint8_t* l1  = ctx[1]->memory;
    uint8_t* l2  = ctx[2]->memory;
    uint8_t* l3  = ctx[3]->memory;
    uint64_t* h0 = reinterpret_cast<uint64_t*>(ctx[0]->state);
    uint64_t* h1 = reinterpret_cast<uint64_t*>(ctx[1]->state);
    uint64_t* h2 = reinterpret_cast<uint64_t*>(ctx[2]->state);
    uint64_t* h3 = reinterpret_cast<uint64_t*>(ctx[3]->state);

    CONST_INIT(ctx[0], 0);
    CONST_INIT(ctx[1], 1);
    CONST_INIT(ctx[2], 2);
    CONST_INIT(ctx[3], 3);
    VARIANT2_SET_ROUNDING_MODE();

    uint64_t idx0, idx1, idx2, idx3;
    idx0 = _mm_cvtsi128_si64(ax0);
    idx1 = _mm_cvtsi128_si64(ax1);
    idx2 = _mm_cvtsi128_si64(ax2);
    idx3 = _mm_cvtsi128_si64(ax3);

    for (size_t i = 0; i < iters; i++) {
        uint64_t hi, lo;
        __m128i *ptr0, *ptr1, *ptr2, *ptr3;

        CN_STEP1(ax0, bx00, bx01, cx0, l0, ptr0, idx0);
        CN_STEP1(ax1, bx10, bx11, cx1, l1, ptr1, idx1);
        CN_STEP1(ax2, bx20, bx21, cx2, l2, ptr2, idx2);
        CN_STEP1(ax3, bx30, bx31, cx3, l3, ptr3, idx3);

        CN_STEP2(ax0, bx00, bx01, cx0, l0, ptr0, idx0);
        CN_STEP2(ax1, bx10, bx11, cx1, l1, ptr1, idx1);
        CN_STEP2(ax2, bx20, bx21, cx2, l2, ptr2, idx2);
        CN_STEP2(ax3, bx30, bx31, cx3, l3, ptr3, idx3);

        CN_STEP3(0, ax0, bx00, bx01, cx0, l0, ptr0, idx0);
        CN_STEP3(1, ax1, bx10, bx11, cx1, l1, ptr1, idx1);
        CN_STEP3(2, ax2, bx20, bx21, cx2, l2, ptr2, idx2);
        CN_STEP3(3, ax3, bx30, bx31, cx3, l3, ptr3, idx3);

        CN_STEP4(0, ax0, bx00, bx01, cx0, l0, mc0, ptr0, idx0);
        CN_STEP4(1, ax1, bx10, bx11, cx1, l1, mc1, ptr1, idx1);
        CN_STEP4(2, ax2, bx20, bx21, cx2, l2, mc2, ptr2, idx2);
        CN_STEP4(3, ax3, bx30, bx31, cx3, l3, mc3, ptr3, idx3);
    }

    for (size_t i = 0; i < 4; i++) {
        cn_implode_scratchpad<SOFT_AES>(reinterpret_cast<const __m128i*>(ctx[i]->memory), reinterpret_cast<__m128i*>(ctx[i]->state));
        keccakf(reinterpret_cast<uint64_t*>(ctx[i]->state), 24);
        extra_hashes[ctx[i]->state[0] & 3](ctx[i]->state, 200, output + 32 * i);
    }
}


template<bool SOFT_AES>
inline void cryptonight_penta_hash(const uint8_t *__restrict__ input, size_t size, uint8_t *__restrict__ output, cryptonight_ctx **__restrict__ ctx, uint64_t height, uint64_t extra_iters)
{
    constexpr CnAlgo props;
    constexpr size_t MASK        = props.mask();

    uint32_t iters = (props.iterations() + extra_iters) >> 1;

    for (size_t i = 0; i < 5; i++) {
        keccak(input + size * i, size, ctx[i]->state);
        cn_explode_scratchpad<SOFT_AES>(reinterpret_cast<const __m128i*>(ctx[i]->state), reinterpret_cast<__m128i*>(ctx[i]->memory));
    }

    uint8_t* l0  = ctx[0]->memory;
    uint8_t* l1  = ctx[1]->memory;
    uint8_t* l2  = ctx[2]->memory;
    uint8_t* l3  = ctx[3]->memory;
    uint8_t* l4  = ctx[4]->memory;
    uint64_t* h0 = reinterpret_cast<uint64_t*>(ctx[0]->state);
    uint64_t* h1 = reinterpret_cast<uint64_t*>(ctx[1]->state);
    uint64_t* h2 = reinterpret_cast<uint64_t*>(ctx[2]->state);
    uint64_t* h3 = reinterpret_cast<uint64_t*>(ctx[3]->state);
    uint64_t* h4 = reinterpret_cast<uint64_t*>(ctx[4]->state);

    CONST_INIT(ctx[0], 0);
    CONST_INIT(ctx[1], 1);
    CONST_INIT(ctx[2], 2);
    CONST_INIT(ctx[3], 3);
    CONST_INIT(ctx[4], 4);
    VARIANT2_SET_ROUNDING_MODE();

    uint64_t idx0, idx1, idx2, idx3, idx4;
    idx0 = _mm_cvtsi128_si64(ax0);
    idx1 = _mm_cvtsi128_si64(ax1);
    idx2 = _mm_cvtsi128_si64(ax2);
    idx3 = _mm_cvtsi128_si64(ax3);
    idx4 = _mm_cvtsi128_si64(ax4);

    for (size_t i = 0; i < iters; i++) {
        uint64_t hi, lo;
        __m128i *ptr0, *ptr1, *ptr2, *ptr3, *ptr4;

        CN_STEP1(ax0, bx00, bx01, cx0, l0, ptr0, idx0);
        CN_STEP1(ax1, bx10, bx11, cx1, l1, ptr1, idx1);
        CN_STEP1(ax2, bx20, bx21, cx2, l2, ptr2, idx2);
        CN_STEP1(ax3, bx30, bx31, cx3, l3, ptr3, idx3);
        CN_STEP1(ax4, bx40, bx41, cx4, l4, ptr4, idx4);

        CN_STEP2(ax0, bx00, bx01, cx0, l0, ptr0, idx0);
        CN_STEP2(ax1, bx10, bx11, cx1, l1, ptr1, idx1);
        CN_STEP2(ax2, bx20, bx21, cx2, l2, ptr2, idx2);
        CN_STEP2(ax3, bx30, bx31, cx3, l3, ptr3, idx3);
        CN_STEP2(ax4, bx40, bx41, cx4, l4, ptr4, idx4);

        CN_STEP3(0, ax0, bx00, bx01, cx0, l0, ptr0, idx0);
        CN_STEP3(1, ax1, bx10, bx11, cx1, l1, ptr1, idx1);
        CN_STEP3(2, ax2, bx20, bx21, cx2, l2, ptr2, idx2);
        CN_STEP3(3, ax3, bx30, bx31, cx3, l3, ptr3, idx3);
        CN_STEP3(4, ax4, bx40, bx41, cx4, l4, ptr4, idx4);

        CN_STEP4(0, ax0, bx00, bx01, cx0, l0, mc0, ptr0, idx0);
        CN_STEP4(1, ax1, bx10, bx11, cx1, l1, mc1, ptr1, idx1);
        CN_STEP4(2, ax2, bx20, bx21, cx2, l2, mc2, ptr2, idx2);
        CN_STEP4(3, ax3, bx30, bx31, cx3, l3, mc3, ptr3, idx3);
        CN_STEP4(4, ax4, bx40, bx41, cx4, l4, mc4, ptr4, idx4);
    }

    for (size_t i = 0; i < 5; i++) {
        cn_implode_scratchpad<SOFT_AES>(reinterpret_cast<const __m128i*>(ctx[i]->memory), reinterpret_cast<__m128i*>(ctx[i]->state));
        keccakf(reinterpret_cast<uint64_t*>(ctx[i]->state), 24);
        extra_hashes[ctx[i]->state[0] & 3](ctx[i]->state, 200, output + 32 * i);
    }
}


} /* namespace xmrig */


#endif /* XMRIG_CRYPTONIGHT_X86_H */
