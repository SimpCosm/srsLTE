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

/******************************************************************************
 * File:        ue_base.h
 * Description: Base class for UEs.
 *****************************************************************************/

#ifndef SRSUE_UE_BASE_H
#define SRSUE_UE_BASE_H

#include <stdarg.h>
#include <string>
#include <pthread.h>
#include "upper/usim.h"
#include "upper/rrc.h"
#include "upper/nas.h"
#include "srslte/interfaces/ue_interfaces.h"

#include "srslte/common/logger.h"
#include "srslte/common/log_filter.h"

namespace srsue {

/*******************************************************************************
  UE Parameters
*******************************************************************************/

typedef struct {
  bool          enable;
  std::string   filename;
  bool          nas_enable;
  std::string   nas_filename;
}pcap_args_t;

typedef struct {
  std::string   rrc_level;
  std::string   gw_level;
  std::string   nas_level;
  std::string   usim_level;
  std::string   all_level;
  int           rrc_hex_limit;
  int           gw_hex_limit;
  int           nas_hex_limit;
  int           usim_hex_limit;
  int           all_hex_limit;
  int           file_max_size;
  std::string   filename;
}log_args_t;

typedef struct {
  bool          enable;
}gui_args_t;

typedef struct {
  std::string   ip_netmask;
  bool          pregenerate_signals;
  bool          print_buffer_state;
  int           mbms_service;
}expert_args_t;

typedef struct {
  pcap_args_t   pcap;
  log_args_t    log;
  gui_args_t    gui;
  usim_args_t   usim;
  rrc_args_t    rrc;
  std::string   ue_category_str;
  nas_args_t    nas;
  expert_args_t expert;
}all_args_t;

typedef enum {
  LTE = 0,
  SRSUE_INSTANCE_TYPE_NITEMS
} srsue_instance_type_t;
static const char srsue_instance_type_text[SRSUE_INSTANCE_TYPE_NITEMS][10] = { "LTE" };


/*******************************************************************************
  Main UE class
*******************************************************************************/

class ue_base
    :public ue_interface
{
public:
  ue_base();
  virtual ~ue_base();

  static ue_base* get_instance(srsue_instance_type_t type);

  void cleanup(void);

  virtual bool init(all_args_t *args_) = 0;
  virtual void stop() = 0;
  virtual bool attach() = 0;
  virtual bool deattach() = 0;
  virtual bool is_attached() = 0;

  virtual void print_pool() = 0;

  virtual srsue::rrc* get_rrc() = 0;

  srslte::LOG_LEVEL_ENUM level(std::string l);

  std::string get_build_mode();
  std::string get_build_info();
  std::string get_build_string();

private:
  srslte::byte_buffer_pool *pool;
};

} // namespace srsue

#endif // SRSUE_UE_BASE_H

