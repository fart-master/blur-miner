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

#include <cstdio>


#include "backend/cpu/Cpu.h"
#include "crypto/cn/CnHash.h"
#include "crypto/common/VirtualMemory.h"
#include "crypto/cn/CryptoNight_x86.h"

static const xmrig::CnHash cnHash;

xmrig::CnHash::CnHash()
{
    m_map[AV_SINGLE][Assembly::NONE]      = cryptonight_single_hash<false>;
    m_map[AV_SINGLE_SOFT][Assembly::NONE] = cryptonight_single_hash<true>;
    m_map[AV_DOUBLE][Assembly::NONE]      = cryptonight_double_hash<false>;
    m_map[AV_DOUBLE_SOFT][Assembly::NONE] = cryptonight_double_hash<true>;
    m_map[AV_TRIPLE][Assembly::NONE]      = cryptonight_triple_hash<false>;
    m_map[AV_TRIPLE_SOFT][Assembly::NONE] = cryptonight_triple_hash<true>;
    m_map[AV_QUAD][Assembly::NONE]        = cryptonight_quad_hash<false>;
    m_map[AV_QUAD_SOFT][Assembly::NONE]   = cryptonight_quad_hash<true>;
    m_map[AV_PENTA][Assembly::NONE]       = cryptonight_penta_hash<false>;
    m_map[AV_PENTA_SOFT][Assembly::NONE]  = cryptonight_penta_hash<true>;
}

xmrig::cn_hash_fun xmrig::CnHash::fn(AlgoVariant av, Assembly::Id assembly)
{
    return cnHash.m_map[av][Assembly::NONE];
}
