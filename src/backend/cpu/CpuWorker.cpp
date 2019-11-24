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


#include <cassert>
#include <thread>


#include "backend/cpu/CpuWorker.h"
#include "core/Miner.h"
#include "crypto/cn/CnCtx.h"
#include "crypto/common/Nonce.h"
#include "crypto/common/VirtualMemory.h"
#include "net/JobResults.h"
#include "backend/common/VarInt.h"


namespace xmrig {

static constexpr uint32_t kReserveCount = 32768;

} // namespace xmrig



template<size_t N>
xmrig::CpuWorker<N>::CpuWorker(size_t id, const CpuLaunchData &data) :
    Worker(id, data.affinity, data.priority),
    m_assembly(data.assembly),
    m_hwAES(data.hwAES),
    m_av(data.av()),
    m_miner(data.miner),
    m_ctx()
{
    m_memory = new VirtualMemory(CnAlgo::CN_MEMORY * N, data.hugePages, true, m_node);
}


template<size_t N>
xmrig::CpuWorker<N>::~CpuWorker()
{
    CnCtx::release(m_ctx, N);
    delete m_memory;
}

template<size_t N>
bool xmrig::CpuWorker<N>::selfTest()
{
    return true;
}


template<size_t N>
void xmrig::CpuWorker<N>::start()
{
    while (Nonce::sequence(Nonce::CPU) > 0) {
        if (Nonce::isPaused()) {
            do {
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
            }
            while (Nonce::isPaused() && Nonce::sequence(Nonce::CPU) > 0);

            if (Nonce::sequence(Nonce::CPU) == 0) {
                break;
            }

            consumeJob();
        }

        while (!Nonce::isOutdated(Nonce::CPU, m_job.sequence())) {
            if ((m_count & 0x7) == 0) {
                storeStats();
            }

            const Job &job = m_job.currentJob();

            fn()(m_job.blob(), job.size(), m_hash, m_ctx, job.height(), job.extraIters());

            for (size_t i = 0; i < N; ++i) {
                if (*reinterpret_cast<uint64_t*>(m_hash + (i * 32) + 24) < job.target()) {
                    JobResults::submit(job, *m_job.nonce(i), m_hash + (i * 32));
                }
            }

            m_job.nextRound(kReserveCount, 1);
            m_count += N;

            std::this_thread::yield();
        }

        consumeJob();
    }
}

template<size_t N>
void xmrig::CpuWorker<N>::allocateCnCtx()
{
    if (m_ctx[0] == nullptr) {
        CnCtx::create(m_ctx, m_memory->scratchpad(), CnAlgo::CN_MEMORY, N);
    }
}


template<size_t N>
void xmrig::CpuWorker<N>::consumeJob()
{
    if (Nonce::sequence(Nonce::CPU) == 0) {
        return;
    }

    m_job.add(m_miner->job(), kReserveCount, Nonce::CPU);

    allocateCnCtx();
}


namespace xmrig {

template class CpuWorker<1>;
template class CpuWorker<2>;
template class CpuWorker<3>;
template class CpuWorker<4>;
template class CpuWorker<5>;
template class CpuWorker<6>;

} // namespace xmrig

