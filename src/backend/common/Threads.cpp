/* XMRig
 * Copyright 2010      Jeff Garzik <jgarzik@pobox.com>
 * Copyright 2012-2014 pooler      <pooler@litecoinpool.org>
 * Copyright 2014      Lucas Jones <https://github.com/lucasjones>
 * Copyright 2014-2016 Wolf9466    <https://github.com/OhGodAPet>
 * Copyright 2016      Jay D Dee   <jayddee246@gmail.com>
 * Copyright 2017-2018 XMR-Stak    <https://github.com/fireice-uk>, <https://github.com/psychocrypt>
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


#include "backend/common/Threads.h"
#include "backend/cpu/CpuThreads.h"
#include "crypto/cn/CnAlgo.h"
#include "rapidjson/document.h"


#ifdef XMRIG_FEATURE_OPENCL
#   include "backend/opencl/OclThreads.h"
#endif


#ifdef XMRIG_FEATURE_CUDA
#   include "backend/cuda/CudaThreads.h"
#endif

template <class T>
size_t xmrig::Threads<T>::read(const rapidjson::Value &value)
{
    using namespace rapidjson;

    for (auto &member : value.GetObject()) {
        if (member.value.IsArray() || member.value.IsObject()) {
            T threads(member.value);

            if (!threads.isEmpty()) {
                move(member.name.GetString(), std::move(threads));
            }
        }
    }
    for (auto &member : value.GetObject()) {
        if (member.value.IsArray() || member.value.IsObject()) {
            continue;
        }
    }

    return m_profiles.size();
}

template <class T>
void xmrig::Threads<T>::toJSON(rapidjson::Value &out, rapidjson::Document &doc) const
{
    using namespace rapidjson;
    auto &allocator = doc.GetAllocator();

    if (has())
    {
        auto &ct = get();
        out.AddMember("cn/blur", ct.toJSON(doc), allocator);
    }   
}


namespace xmrig {

template class Threads<CpuThreads>;

#ifdef XMRIG_FEATURE_OPENCL
template class Threads<OclThreads>;
#endif

#ifdef XMRIG_FEATURE_CUDA
template class Threads<CudaThreads>;
#endif

} // namespace xmrig
