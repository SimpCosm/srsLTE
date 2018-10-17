/**
 *
 * \section COPYRIGHT
 *
 * Copyright 2013-2015 Software Radio Systems Limited
 *
 * \section LICENSE
 *
 * This file is part of the srsUE library.
 *
 * srsUE is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * srsUE is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * A copy of the GNU Affero General Public License can be found in
 * the LICENSE file in the top-level directory of this distribution
 * and at http://www.gnu.org/licenses/.
 *
 */

#include "srsue/hdr/ue.h"
#include "srslte/srslte.h"
#include <pthread.h>
#include <iostream>
#include <string>
#include <algorithm>
#include <iterator>

using namespace srslte;

namespace srsue{

ue::ue()
    :started(false)
{
}

ue::~ue()
{
  if (usim) {
    delete usim;
  }
}

bool ue::init(all_args_t *args_) {
  args = args_;

  if (!args->log.filename.compare("stdout")) {
    logger = &logger_stdout;
  } else {
    logger_file.init(args->log.filename, args->log.file_max_size);
    logger_file.log("\n\n");
    logger_file.log(get_build_string().c_str());
    logger = &logger_file;
  }

  rf_log.init("RF  ", logger);

  rlc_log.init("RLC ", logger);
  pdcp_log.init("PDCP", logger);
  rrc_log.init("RRC ", logger);
  nas_log.init("NAS ", logger);
  gw_log.init("GW  ", logger);
  usim_log.init("USIM", logger);

  pool_log.init("POOL", logger);
  pool_log.set_level(srslte::LOG_LEVEL_ERROR);
  byte_buffer_pool::get_instance()->set_log(&pool_log);

  // Init logs
  rlc_log.set_level(level(args->log.rlc_level));
  pdcp_log.set_level(level(args->log.pdcp_level));
  rrc_log.set_level(level(args->log.rrc_level));
  nas_log.set_level(level(args->log.nas_level));
  gw_log.set_level(level(args->log.gw_level));
  usim_log.set_level(level(args->log.usim_level));

  rlc_log.set_hex_limit(args->log.rlc_hex_limit);
  pdcp_log.set_hex_limit(args->log.pdcp_hex_limit);
  rrc_log.set_hex_limit(args->log.rrc_hex_limit);
  nas_log.set_hex_limit(args->log.nas_hex_limit);
  gw_log.set_hex_limit(args->log.gw_hex_limit);
  usim_log.set_hex_limit(args->log.usim_hex_limit);

  // Set up pcap and trace
  if(args->pcap.nas_enable) {
    nas_pcap.open(args->pcap.nas_filename.c_str());
    nas.start_pcap(&nas_pcap);
  }

  // Init layers

  // Init USIM first to allow early exit in case reader couldn't be found
  usim = usim_base::get_instance(&args->usim, &usim_log);
  if (usim->init(&args->usim, &usim_log)) {
    usim_log.console("Failed to initialize USIM.\n");
    return false;
  }


  srslte_nas_config_t nas_cfg(1, args->nas.apn_name, args->nas.apn_user, args->nas.apn_pass, args->nas.force_imsi_attach); /* RB_ID_SRB1 */
  nas.init(usim, &rrc, &gw, &nas_log, nas_cfg);
  gw.init(&nas, &gw_log, 3 /* RB_ID_DRB1 */);
  gw.set_netmask(args->expert.ip_netmask);
  rrc.init(&nas, usim, &gw, &rrc_log, args->rrc.enb_addr, args->rrc.enb_port, args->rrc.ue_bind_addr, args->rrc.ue_bind_port);

  // Get current band from provided EARFCN
  args->rrc.supported_bands[0] = srslte_band_get_band(args->rf.dl_earfcn);
  args->rrc.nof_supported_bands = 1;
  args->rrc.ue_category = atoi(args->ue_category_str.c_str());
  rrc.set_args(&args->rrc);

  // Currently EARFCN list is set to only one frequency as indicated in ue.conf
  std::vector<uint32_t> earfcn_list;
  earfcn_list.push_back(args->rf.dl_earfcn);

  started = true;
  return true;
}

void ue::stop()
{
  if(started)
  {
    usim->stop();
    nas.stop();
    rrc.stop();

    // Caution here order of stop is very important to avoid locks


    // Stop RLC and PDCP before GW to avoid locking on queue
    gw.stop();

    usleep(1e5);
    if(args->pcap.nas_enable) {
       nas_pcap.close();
    }
    started = false;
  }
}

bool ue::attach() {
  return nas.attach_request();
}

bool ue::deattach() {
  return nas.deattach_request();
}

bool ue::is_attached()
{
  return rrc.is_connected();
}

void ue::print_pool() {
  byte_buffer_pool::get_instance()->print_all_buffers();
}

bool ue::get_metrics(ue_metrics_t &m)
{
  bzero(&m, sizeof(ue_metrics_t));
  m.rf = rf_metrics;
  bzero(&rf_metrics, sizeof(rf_metrics_t));
  rf_metrics.rf_error = false; // Reset error flag

  if(EMM_STATE_REGISTERED == nas.get_state()) {
    if(RRC_STATE_CONNECTED == rrc.get_state()) {
      gw.get_metrics(m.gw);
      return true;
    }
  }
  return false;
}

srsue::rrc* ue::get_rrc() {
  return &rrc;
}
} // namespace srsue
