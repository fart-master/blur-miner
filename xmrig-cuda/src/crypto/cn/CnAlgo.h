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

#ifndef XMRIG_CN_ALGO_H
#define XMRIG_CN_ALGO_H


#include <cstddef>
#include <cstdint>


#include "crypto/common/Algorithm.h"

namespace xmrig
{
    class CnAlgo
    {
        public:
            constexpr CnAlgo() {};

            constexpr inline Algorithm::Id base() const  { return Algorithm::CN_2; }
            constexpr inline size_t memory() const       { return CN_MEMORY; }
            constexpr inline uint32_t iterations() const { return CN_ITER; }
            constexpr inline uint32_t mask() const       { return static_cast<uint32_t>(((memory() - 1) / 16) * 16); }

            constexpr const static size_t           CN_MEMORY           = 0x100000;
            constexpr const static uint32_t         CN_ITER             = 0x40000;
            constexpr const static size_t           CN_MASK             = static_cast<uint32_t>(((CN_MEMORY - 1) / 16) * 16);
            constexpr const static uint32_t         CN_MAX_INTENSITY    = 5;
    };

} /* namespace xmrig */


#endif /* XMRIG_CN_ALGO_H */
