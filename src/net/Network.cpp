/* XMRig
 * Copyright 2010      Jeff Garzik <jgarzik@pobox.com>
 * Copyright 2012-2014 pooler      <pooler@litecoinpool.org>
 * Copyright 2014      Lucas Jones <https://github.com/lucasjones>
 * Copyright 2014-2016 Wolf9466    <https://github.com/OhGodAPet>
 * Copyright 2016      Jay D Dee   <jayddee246@gmail.com>
 * Copyright 2017-2018 XMR-Stak    <https://github.com/fireice-uk>, <https://github.com/psychocrypt>
 * Copyright 2018-2019 SChernykh   <https://github.com/SChernykh>
 * Copyright 2019      Howard Chu  <https://github.com/hyc>
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

#ifdef _MSC_VER
#pragma warning(disable:4244)
#endif

#include <algorithm>
#include <cinttypes>
#include <ctime>
#include <iterator>
#include <memory>


#include "backend/common/Tags.h"
#include "base/io/log/Log.h"
#include "base/net/stratum/Client.h"
#include "base/net/stratum/SubmitResult.h"
#include "base/tools/Chrono.h"
#include "base/tools/Timer.h"
#include "core/config/Config.h"
#include "core/Controller.h"
#include "core/Miner.h"
#include "net/JobResult.h"
#include "net/JobResults.h"
#include "net/Network.h"
#include "net/strategies/DonateStrategy.h"
#include "rapidjson/document.h"


#ifdef XMRIG_FEATURE_API
#   include "base/api/Api.h"
#   include "base/api/interfaces/IApiRequest.h"
#endif


namespace xmrig {


static const char *tag = BLUE_BG_BOLD(WHITE_BOLD_S " net ");


} // namespace xmrig



const char *xmrig::net_tag()
{
    return tag;
}


xmrig::Network::Network(Controller *controller) :
    m_controller(controller),
    m_donate(nullptr),
    m_timer(nullptr)
{
    JobResults::setListener(this, controller->config()->cpu().isHwAES());
    controller->addListener(this);

#   ifdef XMRIG_FEATURE_API
    controller->api()->addListener(this);
#   endif

    const Pools &pools = controller->config()->pools();
    m_strategy = pools.createStrategy(this);

    m_timer = new Timer(this, kTickInterval, kTickInterval);
}


xmrig::Network::~Network()
{
    JobResults::stop();

    delete m_timer;
    delete m_donate;
    delete m_strategy;
}


void xmrig::Network::connect()
{
    m_strategy->connect();
}


void xmrig::Network::onActive(IStrategy *strategy, IClient *client)
{
    m_state.onActive(client);

    const char *tlsVersion = client->tlsVersion();
    LOG_INFO("%s " WHITE_BOLD("use %s ") CYAN_BOLD("%s:%d ") GREEN_BOLD("%s") " " BLACK_BOLD("%s"),
             tag, client->mode(), client->pool().host().data(), client->pool().port(), tlsVersion ? tlsVersion : "", client->ip().data());

    const char *fingerprint = client->tlsFingerprint();
    if (fingerprint != nullptr) {
        LOG_INFO("%s " BLACK_BOLD("fingerprint (SHA-256): \"%s\""), tag, fingerprint);
    }
}


void xmrig::Network::onConfigChanged(Config *config, Config *previousConfig)
{
    if (config->pools() == previousConfig->pools() || !config->pools().active()) {
        return;
    }

    m_strategy->stop();

    config->pools().print();

    delete m_strategy;
    m_strategy = config->pools().createStrategy(this);
    connect();
}


void xmrig::Network::onJob(IStrategy *strategy, IClient *client, const Job &job)
{
    setJob(client, job);
}


void xmrig::Network::onJobResult(const JobResult &result)
{
    m_strategy->submit(result);
}


void xmrig::Network::onLogin(IStrategy *, IClient *client, rapidjson::Document &doc, rapidjson::Value &params)
{
    using namespace rapidjson;
    auto &allocator = doc.GetAllocator();
    params.AddMember("algo", "cn/blur", allocator);
}


void xmrig::Network::onPause(IStrategy *strategy)
{
    if (!m_strategy->isActive()) {
        LOG_ERR("%s " RED("no active pools, stop mining"), tag);
        m_state.stop();

        return m_controller->miner()->pause();
    }
}


void xmrig::Network::onResultAccepted(IStrategy *, IClient *, const SubmitResult &result, const char *error)
{
    m_state.add(result, error);

    if (error) {
        LOG_INFO("%s " RED_BOLD("rejected") " (%" PRId64 "/%" PRId64 ") diff " WHITE_BOLD("%" PRIu64) " " RED("\"%s\"") " " BLACK_BOLD("(%" PRIu64 " ms)"),
                 backend_tag(result.backend), m_state.accepted, m_state.rejected, result.diff, error, result.elapsed);
    }
    else {
        LOG_INFO("%s " GREEN_BOLD("accepted") " (%" PRId64 "/%" PRId64 ") diff " WHITE_BOLD("%" PRIu64) " " BLACK_BOLD("(%" PRIu64 " ms)"),
                 backend_tag(result.backend), m_state.accepted, m_state.rejected, result.diff, result.elapsed);
    }
}


#ifdef XMRIG_FEATURE_API
void xmrig::Network::onRequest(IApiRequest &request)
{
    if (request.type() == IApiRequest::REQ_SUMMARY) {
        request.accept();

        getResults(request.reply(), request.doc(), request.version());
        getConnection(request.reply(), request.doc(), request.version());
    }
}
#endif


void xmrig::Network::setJob(IClient *client, const Job &job)
{
    if (job.height()) {
        LOG_INFO("%s " MAGENTA_BOLD("new job") " from " WHITE_BOLD("%s:%d") " diff " WHITE_BOLD("%" PRIu64) " height " WHITE_BOLD("%" PRIu64),
                 tag, client->pool().host().data(), client->pool().port(), job.diff(), job.height());
    }
    else {
        LOG_INFO("%s " MAGENTA_BOLD("new job") " from " WHITE_BOLD("%s:%d") " diff " WHITE_BOLD("%" PRIu64),
                 tag, client->pool().host().data(), client->pool().port(), job.diff());
    }

    m_state.diff = job.diff();
    m_controller->miner()->setJob(job);
}


void xmrig::Network::tick()
{
    const uint64_t now = Chrono::steadyMSecs();

    m_strategy->tick(now);

    if (m_donate) {
        m_donate->tick(now);
    }
}


#ifdef XMRIG_FEATURE_API
void xmrig::Network::getConnection(rapidjson::Value &reply, rapidjson::Document &doc, int version) const
{
    using namespace rapidjson;
    auto &allocator = doc.GetAllocator();

    Value connection(kObjectType);
    connection.AddMember("pool",            StringRef(m_state.pool), allocator);
    connection.AddMember("ip",              m_state.ip().toJSON(), allocator);
    connection.AddMember("uptime",          m_state.connectionTime(), allocator);
    connection.AddMember("ping",            m_state.latency(), allocator);
    connection.AddMember("failures",        m_state.failures, allocator);
    connection.AddMember("tls",             m_state.tls().toJSON(), allocator);
    connection.AddMember("tls-fingerprint", m_state.fingerprint().toJSON(), allocator);

    if (version == 1) {
        connection.AddMember("error_log", Value(kArrayType), allocator);
    }

    reply.AddMember("connection", connection, allocator);
}


void xmrig::Network::getResults(rapidjson::Value &reply, rapidjson::Document &doc, int version) const
{
    using namespace rapidjson;
    auto &allocator = doc.GetAllocator();

    Value results(kObjectType);

    results.AddMember("diff_current",  m_state.diff, allocator);
    results.AddMember("shares_good",   m_state.accepted, allocator);
    results.AddMember("shares_total",  m_state.accepted + m_state.rejected, allocator);
    results.AddMember("avg_time",      m_state.avgTime(), allocator);
    results.AddMember("hashes_total",  m_state.total, allocator);

    Value best(kArrayType);
    for (uint64_t i : m_state.topDiff) {
        best.PushBack(i, allocator);
    }

    results.AddMember("best", best, allocator);

    if (version == 1) {
        results.AddMember("error_log", Value(kArrayType), allocator);
    }

    reply.AddMember("results", results, allocator);
}
#endif
