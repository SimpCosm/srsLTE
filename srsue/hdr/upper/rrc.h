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

#ifndef SRSUE_RRC_H
#define SRSUE_RRC_H

#include "pthread.h"

#include "rrc_common.h"
#include "srslte/common/buffer_pool.h"
#include "srslte/common/log.h"
#include "srslte/common/common.h"
#include "srslte/interfaces/ue_interfaces.h"
#include "srslte/common/security.h"
#include "srslte/common/threads.h"
#include "srslte/common/block_queue.h"

#include <math.h>
#include <map>
#include <queue>

#define SRSUE_UL_ATTACH     0x01
#define SRSUE_UL_NORMAL     0x02
#define SRSUE_UL_DATA       0x03

#define SRSUE_DL_NORMAL     0x02
#define SRSUE_DL_DATA       0x03

typedef struct {
  uint32_t                      ue_category;
  uint32_t                      feature_group;
  uint8_t                       supported_bands[LIBLTE_RRC_BAND_N_ITEMS];
  uint32_t                      nof_supported_bands;
  std::string                   enb_addr;
  uint32_t                      enb_port;
  std::string                   ue_bind_addr;
  uint32_t                      ue_bind_port;
  std::string                   ue_gate_addr;
  uint32_t                      ue_gate_port;
}rrc_args_t;

using srslte::byte_buffer_t;

namespace srsue {

class rrc
  :public rrc_interface_nas
  ,public rrc_interface_gw
  ,public thread
{
public:
  rrc();
  ~rrc();

  void init(nas_interface_rrc *nas_,
            usim_interface_rrc *usim_,
            gw_interface_rrc   *gw_,
            srslte::log *rrc_log_,
            std::string enb_addr,
            uint32_t enb_port,
            std::string ue_bind_addr,
            uint32_t ue_bind_port,
            std::string ue_gate_ip_addr,
            uint32_t ue_gate_port);

  void stop();

  rrc_state_t get_state();
  void set_args(rrc_args_t *args);

  // Timeout callback interface
  void liblte_rrc_log(char *str);


  // NAS interface
  void write_sdu(uint32_t lcid, byte_buffer_t *sdu);
  void enable_capabilities();
  uint16_t get_mcc();
  uint16_t get_mnc();
  int plmn_search(found_plmn_t found_plmns[MAX_FOUND_PLMNS]);
  void plmn_select(LIBLTE_RRC_PLMN_IDENTITY_STRUCT plmn_id);
  bool connection_request(LIBLTE_RRC_CON_REQ_EST_CAUSE_ENUM cause,
                          srslte::byte_buffer_t *dedicatedInfoNAS);
  void set_ue_idenity(LIBLTE_RRC_S_TMSI_STRUCT s_tmsi);

  // GW interface
  bool is_connected(); // this is also NAS interface

  // Socket interface
  int                   sockfd;
  struct sockaddr_in    enb_addr;
  struct sockaddr_in    ue_addr;
  struct sockaddr_in    ue_gate_addr;

  typedef struct {
      uint8_t                               type;
      uint8_t                               lcid;
      LIBLTE_RRC_CON_REQ_EST_CAUSE_ENUM     cause;
      srslte::byte_buffer_t*                pdu;
  }rrc_pdu;

  srslte::block_queue<rrc_pdu> pdu_queue;

  void send_uplink();
  void recv_downlink();
  void send_attach(rrc_pdu pdu);
  void send_signaling(rrc_pdu pdu);
  void send_data(rrc_pdu pdu);
  void handle_signaling(srslte::byte_buffer_t *sdu);
  void handle_paging(srslte::byte_buffer_t *sdu);
  void handle_data(srslte::byte_buffer_t *sdu);
  void append_head(rrc_pdu pdu);

  void write_pdu_pcch(byte_buffer_t *pdu);
  void write_pdu_mch(uint32_t lcid, srslte::byte_buffer_t *pdu);

  found_plmn_t  plmns;
  uint8_t    imsi[16];

private:

  typedef struct {
    enum {
      STOP
    } command;
    byte_buffer_t *pdu;
  } cmd_msg_t;

  bool running;
  srslte::block_queue<cmd_msg_t> cmd_q;
  void run_thread();

  void process_pcch(byte_buffer_t *pdu);

  srslte::byte_buffer_pool *pool;
  srslte::log *rrc_log;
  nas_interface_rrc *nas;
  usim_interface_rrc *usim;
  gw_interface_rrc    *gw;

  pthread_mutex_t mutex;

  rrc_state_t state;
  LIBLTE_RRC_S_TMSI_STRUCT ueIdentity;
  bool ueIdentity_configured;

  rrc_args_t args;

  srslte::bit_buffer_t  bit_buf;

  uint8_t k_rrc_enc[32];
  uint8_t k_rrc_int[32];
  uint8_t k_up_enc[32];
  uint8_t k_up_int[32];   // Not used: only for relay nodes (3GPP 33.401 Annex A.7)

  srslte::CIPHERING_ALGORITHM_ID_ENUM cipher_algo;
  srslte::INTEGRITY_ALGORITHM_ID_ENUM integ_algo;

  // Radio bearers
  typedef enum{
    RB_ID_SRB0 = 0,
    RB_ID_SRB1,
    RB_ID_SRB2,
    RB_ID_DRB1,
    RB_ID_DRB2,
    RB_ID_DRB3,
    RB_ID_DRB4,
    RB_ID_DRB5,
    RB_ID_DRB6,
    RB_ID_DRB7,
    RB_ID_DRB8,
    RB_ID_MAX
  } rb_id_t;

  static const std::string rb_id_str[];

  std::string get_rb_name(uint32_t lcid)
  {
    if (lcid < RB_ID_MAX) {
      return rb_id_str[lcid];
    } else {
      return "INVALID_RB";
    }
  }

  bool initiated;
  bool go_idle;
  bool go_rlf;


  LIBLTE_RRC_PLMN_IDENTITY_STRUCT selected_plmn_id;
  bool plmn_is_selected;

  bool security_is_activated;

  // Helpers
  void          rrc_connection_release();
  void          leave_connected();

};

} // namespace srsue


#endif // SRSUE_RRC_H
