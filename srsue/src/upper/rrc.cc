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

#include <sys/types.h>
#include <sys/socket.h>

#include <unistd.h>
#include <iostream>
#include <sstream>
#include <stdlib.h>
#include <time.h>
#include <inttypes.h> // for printing uint64_t
#include <srslte/asn1/liblte_rrc.h>
#include "srsue/hdr/upper/rrc.h"
#include "srslte/asn1/liblte_rrc.h"
#include "srslte/common/security.h"
#include "srslte/common/bcd_helpers.h"

using namespace srslte;

namespace srsue {

/*******************************************************************************
  Base functions
*******************************************************************************/

rrc::rrc()
    :imsi("001010123456789")
{
  initiated = false;
  running = false;
  go_idle = false;
  go_rlf  = false;

  plmns.plmn_id.mcc = 61441;
  plmns.plmn_id.mnc = 65281;
  plmns.tac = 0x01;
}

rrc::~rrc()
{
}

static void liblte_rrc_handler(void *ctx, char *str) {
  rrc *r = (rrc *) ctx;
  r->liblte_rrc_log(str);
}

void rrc::liblte_rrc_log(char *str) {
  if (rrc_log) {
    rrc_log->warning("[ASN]: %s\n", str);
  } else {
    printf("[ASN]: %s\n", str);
  }
}

void rrc::init(nas_interface_rrc *nas_,
               usim_interface_rrc *usim_,
               gw_interface_rrc *gw_,
               srslte::log *rrc_log_,
               std::string enb_ip_addr,
               uint32_t enb_port,
               std::string ue_bind_addr,
               uint32_t ue_bind_port,
               std::string ue_gate_ip_addr,
               uint32_t ue_gate_port)
{
  pool = byte_buffer_pool::get_instance();
  nas = nas_;
  usim = usim_;
  gw = gw_;
  rrc_log = rrc_log_;

  state = RRC_STATE_IDLE;
  plmn_is_selected = false;
  security_is_activated = false;

  pthread_mutex_init(&mutex, NULL);

  args.ue_category = SRSLTE_UE_CATEGORY;
  args.supported_bands[0] = 7;
  args.nof_supported_bands = 1;
  args.feature_group = 0xe6041000;

  ueIdentity_configured = false;

  // Register logging handler with liblte_rrc
  liblte_rrc_log_register_handler(this, liblte_rrc_handler);

  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    rrc_log->error("init socket failed\n");
  }

  bzero(&enb_addr, sizeof(enb_addr));
  enb_addr.sin_family = AF_INET;
  enb_addr.sin_addr.s_addr = inet_addr(enb_ip_addr.c_str());
  enb_addr.sin_port = htons(enb_port);

  bzero(&ue_gate_addr, sizeof(ue_gate_addr));
  ue_gate_addr.sin_family = AF_INET;
  ue_gate_addr.sin_addr.s_addr = inet_addr(ue_gate_ip_addr.c_str());
  ue_gate_addr.sin_port = htons(ue_gate_port);

  bzero(&ue_addr, sizeof(ue_addr));
  ue_addr.sin_family = AF_INET;
  ue_addr.sin_addr.s_addr = inet_addr(ue_bind_addr.c_str());
  ue_addr.sin_port = htons(ue_bind_port);

  if (bind(sockfd, (struct sockaddr*)&ue_addr, sizeof(ue_addr)) < 0) {
    rrc_log->error("bind ue addr failed\n");
  }

  srand(time(NULL));

  running = true;
  start();
  initiated = true;
}

void rrc::stop() {
  running = false;
  cmd_msg_t msg;
  msg.command = cmd_msg_t::STOP;
  cmd_q.push(msg);
  wait_thread_finish();
}

rrc_state_t rrc::get_state() {
  return state;
}

bool rrc::is_connected() {
  return (RRC_STATE_CONNECTED == state);
}


void rrc::set_args(rrc_args_t *args) {
  memcpy(&this->args, args, sizeof(rrc_args_t));
}

/*
 * Low priority thread to run functions that can not be executed from main thread
 */
void rrc::run_thread() {
  while(running) {
    cmd_msg_t msg = cmd_q.wait_pop();
    switch(msg.command) {
      case cmd_msg_t::STOP:
        return;
      case cmd_msg_t::PCCH:
        process_pcch(msg.pdu);
        break;
    }
  }
}


/*******************************************************************************
*
*
*
* NAS interface: PLMN search and RRC connection establishment
*
*
*
*******************************************************************************/

uint16_t rrc::get_mcc() {
  return 61441;
}

uint16_t rrc::get_mnc() {
  return 65281;
}

/* NAS interface to search for available PLMNs.
 * Pretend we only have one plmn
 */
int rrc::plmn_search(found_plmn_t found_plmns[MAX_FOUND_PLMNS])
{
    rrc_log->info("Starting PLMN search\n");
    memcpy(found_plmns, &plmns, sizeof(found_plmn_t));
    return 1;
}

/* This is the NAS interface. When NAS requests to select a PLMN we have to
 * connect to either register or because there is pending higher layer traffic.
 */
void rrc::plmn_select(LIBLTE_RRC_PLMN_IDENTITY_STRUCT plmn_id) {
  plmn_is_selected = true;
  selected_plmn_id = plmn_id;

  rrc_log->info("PLMN Selected %s\n", plmn_id_to_string(plmn_id).c_str());
}

/* 5.3.3.2 Initiation of RRC Connection Establishment procedure
 *
 * Higher layers request establishment of RRC connection while UE is in RRC_IDLE
 *
 * This procedure selects a suitable cell for transmission of RRCConnectionRequest and configures
 * it. Sends connectionRequest message and returns if message transmitted successfully.
 * It does not wait until completition of Connection Establishment procedure
 */
bool rrc::connection_request(LIBLTE_RRC_CON_REQ_EST_CAUSE_ENUM cause,
                             srslte::byte_buffer_t *dedicatedInfoNAS)
{
  if (!plmn_is_selected) {
    rrc_log->error("Trying to connect but PLMN not selected.\n");
    return false;
  }

  // Pretend that rrc connection already setup
  pthread_mutex_lock(&mutex);

  state = RRC_STATE_CONNECTED;
  rrc_log->info("RRC connection already setup\n");
  send_ul_info_transfer(cause, dedicatedInfoNAS);

  pthread_mutex_unlock(&mutex);

  return true;
}

void rrc::set_ue_idenity(LIBLTE_RRC_S_TMSI_STRUCT s_tmsi) {
  ueIdentity_configured = true;
  ueIdentity = s_tmsi;
  rrc_log->info("Set ue-Identity to 0x%x:0x%x\n", ueIdentity.mmec, ueIdentity.m_tmsi);
}


/*******************************************************************************
*
*
*
* Connection Control: Establishment, Reconfiguration, Reestablishment and Release
*
*
*
*******************************************************************************/

void rrc::send_ul_info_transfer(LIBLTE_RRC_CON_REQ_EST_CAUSE_ENUM cause, byte_buffer_t *nas_msg) {
  rrc_log->debug("Preparing RX Info Transfer\n");

  // not using rrc packet format anymore, just send it via socket.
  rrc_pdu p = {SRSUE_UL_ATTACH, RB_ID_SRB0, cause, nas_msg};
  pdu_queue.push(p);

}

/* Actions upon reception of RRCConnectionRelease 5.3.8.3 */
void rrc::rrc_connection_release() {
  // Save idleModeMobilityControlInfo, etc.
  rrc_log->console("Received RRC Connection Release\n");
  go_idle = true;
}

/* Actions upon leaving RRC_CONNECTED 5.3.12 */
void rrc::leave_connected()
{
  rrc_log->console("RRC IDLE\n");
  rrc_log->info("Leaving RRC_CONNECTED state\n");
  state = RRC_STATE_IDLE;
  security_is_activated = false;
}

/*******************************************************************************
*
*
*
* Reception of Paging messages
*
*
*
*******************************************************************************/
void rrc::write_pdu_pcch(byte_buffer_t *pdu) {
  cmd_msg_t msg;
  msg.pdu = pdu;
  msg.command = cmd_msg_t::PCCH;
  cmd_q.push(msg);
}

void rrc::process_pcch(byte_buffer_t *pdu) {
  if (pdu->N_bytes > 0 && pdu->N_bytes < SRSLTE_MAX_BUFFER_SIZE_BITS) {
    rrc_log->info_hex(pdu->msg, pdu->N_bytes, "PCCH message received %d bytes\n", pdu->N_bytes);
    rrc_log->info("PCCH message Stack latency: %ld us\n", pdu->get_latency_us());

    LIBLTE_RRC_PCCH_MSG_STRUCT pcch_msg;
    ZERO_OBJECT(pcch_msg);
    srslte_bit_unpack_vector(pdu->msg, bit_buf.msg, pdu->N_bytes * 8);
    bit_buf.N_bits = pdu->N_bytes * 8;
    pool->deallocate(pdu);
    liblte_rrc_unpack_pcch_msg((LIBLTE_BIT_MSG_STRUCT *) &bit_buf, &pcch_msg);

    if (pcch_msg.paging_record_list_size > LIBLTE_RRC_MAX_PAGE_REC) {
      pcch_msg.paging_record_list_size = LIBLTE_RRC_MAX_PAGE_REC;
    }

    if (!ueIdentity_configured) {
      rrc_log->warning("Received paging message but no ue-Identity is configured\n");
      return;
    }
    LIBLTE_RRC_S_TMSI_STRUCT *s_tmsi_paged;
    for (uint32_t i = 0; i < pcch_msg.paging_record_list_size; i++) {
      s_tmsi_paged = &pcch_msg.paging_record_list[i].ue_identity.s_tmsi;
      rrc_log->info("Received paging (%d/%d) for UE %x:%x\n", i + 1, pcch_msg.paging_record_list_size,
                    pcch_msg.paging_record_list[i].ue_identity.s_tmsi.mmec,
                    pcch_msg.paging_record_list[i].ue_identity.s_tmsi.m_tmsi);
      if (ueIdentity.mmec == s_tmsi_paged->mmec && ueIdentity.m_tmsi == s_tmsi_paged->m_tmsi) {
        if (RRC_STATE_IDLE == state) {
          rrc_log->info("S-TMSI match in paging message\n");
          rrc_log->console("S-TMSI match in paging message\n");
          nas->paging(s_tmsi_paged);
        } else {
          rrc_log->warning("Received paging while in CONNECT\n");
        }
      } else {
        rrc_log->info("Received paging for unknown identity\n");
      }
    }
  }
}


void rrc::write_pdu_mch(uint32_t lcid, srslte::byte_buffer_t *pdu)
{
  if (pdu->N_bytes > 0 && pdu->N_bytes < SRSLTE_MAX_BUFFER_SIZE_BITS) {
    rrc_log->info_hex(pdu->msg, pdu->N_bytes, "MCH message received %d bytes on lcid:%d\n", pdu->N_bytes, lcid);
    rrc_log->info("MCH message Stack latency: %ld us\n", pdu->get_latency_us());
    //TODO: handle MCCH notifications and update MCCH

  }

    pool->deallocate(pdu);
}

/*******************************************************************************
*
*
*
* Packet processing
*
*
*******************************************************************************/

void rrc::write_sdu(uint32_t lcid, byte_buffer_t *sdu) {

  if (state == RRC_STATE_IDLE) {
    rrc_log->warning("Received ULInformationTransfer SDU when in IDLE\n");
    return;
  }
  rrc_log->info_hex(sdu->msg, sdu->N_bytes, "TX %s SDU", get_rb_name(lcid).c_str());
  LIBLTE_RRC_CON_REQ_EST_CAUSE_ENUM cause = LIBLTE_RRC_CON_REQ_EST_CAUSE_MO_SIGNALLING;     //TODO
  if (lcid >= 3) {
      rrc_pdu p = {SRSUE_UL_DATA, lcid, cause, sdu};
      pdu_queue.push(p);
  } else {
      rrc_pdu p = {SRSUE_UL_NORMAL, lcid, cause, sdu};
      pdu_queue.push(p);
  }
}



/*******************************************************************************
*
*
*
* Capabilities Message
*
*
*
*******************************************************************************/
void rrc::enable_capabilities() {
  // Do Nothing...
}

const std::string rrc::rb_id_str[] = {"SRB0", "SRB1", "SRB2",
                                      "DRB1", "DRB2", "DRB3",
                                      "DRB4", "DRB5", "DRB6",
                                      "DRB7", "DRB8"};


/*******************************************************************************
 *
 * Socket Interface to Send or Receive NAS Info
 *
 *
 *******************************************************************************/
void rrc::send_uplink() {
    rrc_pdu pdu = pdu_queue.wait_pop();
    switch (pdu.type) {
        case SRSUE_UL_ATTACH:
            printf("send attach request\n");
            send_attach(pdu);
            break;
        case SRSUE_UL_NORMAL:
            printf("send normal request\n");
            send_signaling(pdu);
            break;
        case SRSUE_UL_DATA:
            send_data(pdu);
            break;
        default:
            rrc_log->error("Invalid Type: 0x%x\n", pdu.type);
            break;
    }
}

void rrc::recv_downlink() {
    srslte::byte_buffer_t *sdu = pool->allocate();
    sdu->msg -= 18;
    ssize_t len = read(sockfd, sdu->msg, SRSLTE_MAX_BUFFER_SIZE_BYTES);
    uint8_t type = sdu->msg[0];
    sdu->msg ++;
    sdu->N_bytes = len-1;
    switch (type) {
        case SRSUE_DL_NORMAL:
            handle_signaling(sdu);
            break;
        case SRSUE_DL_DATA:
            handle_data(sdu);
            break;
        case SRSUE_DL_PAGING:
            handle_paging(sdu);
        default:
            rrc_log->warning("Unknown PDU Type: 0x%x\n", sdu->msg[0]);
            break;
    }
}

void rrc::append_head(rrc_pdu pdu) {
    pdu.pdu->msg -= 4;
    memcpy(pdu.pdu->msg, &pdu.cause, 4);
    pdu.pdu->msg -= 2;
    memcpy(pdu.pdu->msg, &pdu.lcid, 2);
    pdu.pdu->msg -= 15;
    memcpy(pdu.pdu->msg, imsi, 15);
    pdu.pdu->msg -= 2;
    memcpy(pdu.pdu->msg, &ue_addr.sin_port, 2);
    pdu.pdu->msg -= 4;
    memcpy(pdu.pdu->msg, &ue_addr.sin_addr, 4);
    pdu.pdu->msg -= 1;
    pdu.pdu->N_bytes += 4 + 2 + 15 + 2 + 4 + 1;
}

void rrc::send_attach(rrc_pdu pdu) {
    append_head(pdu);
    pdu.pdu->msg[0] = pdu.type;

    ssize_t send_len = sendto(sockfd, pdu.pdu->msg, pdu.pdu->N_bytes, 0, (struct sockaddr*)&enb_addr, sizeof(struct sockaddr));
    if ((uint32_t)send_len != pdu.pdu->N_bytes) {
        rrc_log->warning("Send Signaling, short of bytes, expected to send:%d, sent:%d\n", pdu.pdu->N_bytes, (int)send_len);
    }
    return ;
}

void rrc::send_signaling(rrc_pdu pdu) {
    append_head(pdu);
    pdu.pdu->msg[0] = SRSUE_UL_NORMAL;
    ssize_t send_len = sendto(sockfd, pdu.pdu->msg, pdu.pdu->N_bytes, 0, (struct sockaddr*)&enb_addr, sizeof(struct sockaddr));
    if ((uint32_t)send_len != pdu.pdu->N_bytes) {
        rrc_log->warning("Send Signaling, short of bytes, expected to send:%d, sent:%d\n", pdu.pdu->N_bytes, (int)send_len);
    }
    return ;
}

void rrc::send_data(rrc_pdu pdu) {
    append_head(pdu);
    pdu.pdu->msg[0] = SRSUE_UL_DATA;
    ssize_t send_len = sendto(sockfd, pdu.pdu->msg, pdu.pdu->N_bytes, 0, (struct sockaddr*)&enb_addr, sizeof(struct sockaddr));
    if ((uint32_t)send_len != pdu.pdu->N_bytes) {
        rrc_log->warning("Send Data, short of bytes, expected to send:%d, sent:%d\n", pdu.pdu->N_bytes, (int)send_len);
    }
    printf("send_len: %d\n", send_len);
    return ;
}

void rrc::handle_signaling(srslte::byte_buffer_t *sdu) {
    uint8_t recv_imsi[15];
    memcpy(recv_imsi, sdu->msg, 15);
    sdu->msg += 15;
    uint16_t recv_lcid;
    memcpy(&recv_lcid, sdu->msg, 2);
    sdu->msg += 2;
    sdu->N_bytes -= 15 + 2;
    nas->write_pdu(recv_lcid, sdu);
}

void rrc::handle_data(srslte::byte_buffer_t *sdu) {
    printf("send data to ue gate\n");
    sdu->msg += 15 + 2 + 28;
    sdu->N_bytes -= 15 + 2 + 28;
    ssize_t send_len = sendto(sockfd, sdu->msg,sdu->N_bytes, 0, (struct sockaddr*)&ue_gate_addr, sizeof(struct sockaddr));
    if ((uint32_t)send_len != sdu->N_bytes) {
        rrc_log->warning("Send Data, short of bytes, expected to send:%d, sent:%d\n", sdu->N_bytes, (int)send_len);
    }
    printf("send_len: %d\n", send_len);
    return ;
}

void rrc::handle_paging(srslte::byte_buffer_t *sdu) {
    uint8_t recv_imsi[15];
    memcpy(recv_imsi, sdu->msg, 15);
    sdu->msg += 15;
    uint16_t recv_lcid;
    memcpy(&recv_lcid, sdu->msg, 2);
    sdu->msg -= 2;
    sdu->N_bytes -= 15 + 2;
    write_pdu_pcch(sdu);
}

} // namespace srsue
