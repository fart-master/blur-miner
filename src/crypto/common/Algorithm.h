/* XMRig
 * Copyright 2010      Jeff Garzik <jgarzik@pobox.com>
 * Copyright 2012-2014 pooler      <pooler@litecoinpool.org>
 * Copyright 2014      Lucas Jones <https://github.com/lucasjones>
 * Copyright 2014-2016 Wolf9466    <https://github.com/OhGodAPet>
 * Copyright 2016      Jay D Dee   <jayddee246@gmail.com>
 * Copyright 2017-2018 XMR-Stak    <https://github.com/fireice-uk>, <https://github.com/psychocrypt>
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

#ifndef XMRIG_ALGORITHM_H
#define XMRIG_ALGORITHM_H


#include <vector>


#include "rapidjson/fwd.h"


namespace xmrig {


class Algorithm
{
public:
    // Changes in following file is required if this enum changed:
    //
    // src/backend/opencl/cl/cn/algorithm.cl
    //
    enum Id : int {
        INVALID = -1,
		CN_0,
        CN_1,
        CN_2,
        CN_BLUR,
        MAX
    };

    inline Algorithm() = default;

    inline const char *name() const                   { return "cn/blur"; }
    inline Id id() const                              { return m_id; }

    inline bool operator!=(Algorithm::Id id) const        { return m_id != id; }
    inline bool operator!=(const Algorithm &other) const  { return m_id != other.m_id; }
    inline bool operator==(Algorithm::Id id) const        { return m_id == id; }
    inline bool operator==(const Algorithm &other) const  { return m_id == other.m_id; }
    inline operator Algorithm::Id() const                 { return m_id; }

    rapidjson::Value toJSON() const;
    size_t l3() const;
    uint32_t maxIntensity() const;

    static Id parse();

private:
    Id m_id = CN_BLUR;
};


using Algorithms = std::vector<Algorithm>;


} /* namespace xmrig */


#endif /* XMRIG_ALGORITHM_H */
