/* XMRig
 * Copyright 2010      Jeff Garzik <jgarzik@pobox.com>
 * Copyright 2012-2014 pooler      <pooler@litecoinpool.org>
 * Copyright 2014      Lucas Jones <https://github.com/lucasjones>
 * Copyright 2014-2016 Wolf9466    <https://github.com/OhGodAPet>
 * Copyright 2016      Jay D Dee   <jayddee246@gmail.com>
 * Copyright 2017-2018 XMR-Stak    <https://github.com/fireice-uk>, <https://github.com/psychocrypt>
 * Copyright 2018      Lee Clagett <https://github.com/vtnerd>
 * Copyright 2018      SChernykh   <https://github.com/SChernykh>
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

#ifndef XMRIG_CRYPTONIGHT_MONERO_H
#define XMRIG_CRYPTONIGHT_MONERO_H

#include <fenv.h>
#include <math.h>

// VARIANT ALTERATIONS
#   define VARIANT2_INIT(part) \
    __m128i division_result_xmm_##part = _mm_cvtsi64_si128(static_cast<int64_t>(h##part[12])); \
    __m128i sqrt_result_xmm_##part     = _mm_cvtsi64_si128(static_cast<int64_t>(h##part[13]));

#ifdef _MSC_VER
#   define VARIANT2_SET_ROUNDING_MODE() _control87(RC_DOWN, MCW_RC);
#else
#   define VARIANT2_SET_ROUNDING_MODE() fesetround(FE_DOWNWARD);
#endif

#   define VARIANT2_INTEGER_MATH(part, cl, cx) \
    do { \
        const uint64_t sqrt_result = static_cast<uint64_t>(_mm_cvtsi128_si64(sqrt_result_xmm_##part)); \
        const uint64_t cx_0 = _mm_cvtsi128_si64(cx); \
        cl ^= static_cast<uint64_t>(_mm_cvtsi128_si64(division_result_xmm_##part)) ^ (sqrt_result << 32); \
        const uint32_t d = static_cast<uint32_t>(cx_0 + (sqrt_result << 1)) | 0x80000001UL; \
        const uint64_t cx_1 = _mm_cvtsi128_si64(_mm_srli_si128(cx, 8)); \
        const uint64_t division_result = static_cast<uint32_t>(cx_1 / d) + ((cx_1 % d) << 32); \
        division_result_xmm_##part = _mm_cvtsi64_si128(static_cast<int64_t>(division_result)); \
        sqrt_result_xmm_##part = int_sqrt_v2(cx_0 + division_result); \
    } while (0)

#   define VARIANT2_SHUFFLE(base_ptr, offset, _a, _b, _b1, _c, reverse) \
    do { \
        const __m128i chunk1 = _mm_load_si128((__m128i *)((base_ptr) + ((offset) ^ (reverse ? 0x30 : 0x10)))); \
        const __m128i chunk2 = _mm_load_si128((__m128i *)((base_ptr) + ((offset) ^ 0x20))); \
        const __m128i chunk3 = _mm_load_si128((__m128i *)((base_ptr) + ((offset) ^ (reverse ? 0x10 : 0x30)))); \
        _mm_store_si128((__m128i *)((base_ptr) + ((offset) ^ 0x10)), _mm_add_epi64(chunk3, _b1)); \
        _mm_store_si128((__m128i *)((base_ptr) + ((offset) ^ 0x20)), _mm_add_epi64(chunk1, _b)); \
        _mm_store_si128((__m128i *)((base_ptr) + ((offset) ^ 0x30)), _mm_add_epi64(chunk2, _a)); \
    } while (0)

#   define VARIANT2_SHUFFLE2(base_ptr, offset, _a, _b, _b1, hi, lo, reverse) \
    do { \
        const __m128i chunk1 = _mm_xor_si128(_mm_load_si128((__m128i *)((base_ptr) + ((offset) ^ 0x10))), _mm_set_epi64x(lo, hi)); \
        const __m128i chunk2 = _mm_load_si128((__m128i *)((base_ptr) + ((offset) ^ 0x20))); \
        hi ^= ((uint64_t*)((base_ptr) + ((offset) ^ 0x20)))[0]; \
        lo ^= ((uint64_t*)((base_ptr) + ((offset) ^ 0x20)))[1]; \
        const __m128i chunk3 = _mm_load_si128((__m128i *)((base_ptr) + ((offset) ^ 0x30))); \
        if (reverse) { \
            _mm_store_si128((__m128i *)((base_ptr) + ((offset) ^ 0x10)), _mm_add_epi64(chunk1, _b1)); \
            _mm_store_si128((__m128i *)((base_ptr) + ((offset) ^ 0x20)), _mm_add_epi64(chunk3, _b)); \
        } else { \
            _mm_store_si128((__m128i *)((base_ptr) + ((offset) ^ 0x10)), _mm_add_epi64(chunk3, _b1)); \
            _mm_store_si128((__m128i *)((base_ptr) + ((offset) ^ 0x20)), _mm_add_epi64(chunk1, _b)); \
        } \
        _mm_store_si128((__m128i *)((base_ptr) + ((offset) ^ 0x30)), _mm_add_epi64(chunk2, _a)); \
    } while (0)

#define SWAP32LE(x) x
#define SWAP64LE(x) x
#define hash_extra_blake(data, length, hash) blake256_hash((uint8_t*)(hash), (uint8_t*)(data), (length))

#ifndef NOINLINE
#ifdef __GNUC__
#define NOINLINE __attribute__ ((noinline))
#elif _MSC_VER
#define NOINLINE __declspec(noinline)
#else
#define NOINLINE
#endif
#endif

#endif /* XMRIG_CRYPTONIGHT_MONERO_H */
