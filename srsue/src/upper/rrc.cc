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

const static uint32_t NOF_REQUIRED_SIBS = 4;
const static uint32_t required_sibs[NOF_REQUIRED_SIBS] = {0,1,2,12}; // SIB1, SIB2, SIB3 and SIB13 (eMBMS)

/*******************************************************************************
  Base functions
*******************************************************************************/

rrc::rrc()
  :state(RRC_STATE_IDLE)
  ,drb_up(false)
  ,serving_cell(NULL)
{
  serving_cell = new cell_t();
  neighbour_cells.reserve(NOF_NEIGHBOUR_CELLS);
  initiated = false;
  running = false;
  go_idle = false;
  go_rlf  = false;
}

rrc::~rrc()
{
  if (serving_cell) {
    delete(serving_cell);
  }

  std::vector<cell_t*>::iterator it;
  for (it = neighbour_cells.begin(); it != neighbour_cells.end(); ++it) {
    delete(*it);
  }
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
void rrc::print_mbms()
{
  if(rrc_log) {
    if(serving_cell->has_mcch) {
      LIBLTE_RRC_MCCH_MSG_STRUCT msg;
      memcpy(&msg, &serving_cell->mcch, sizeof(LIBLTE_RRC_MCCH_MSG_STRUCT));
      std::stringstream ss;
      for(uint32_t i=0;i<msg.pmch_infolist_r9_size; i++){
        ss << "PMCH: " << i << std::endl;
        LIBLTE_RRC_PMCH_INFO_R9_STRUCT *pmch = &msg.pmch_infolist_r9[i];
        for(uint32_t j=0;j<pmch->mbms_sessioninfolist_r9_size; j++) {
          LIBLTE_RRC_MBMS_SESSION_INFO_R9_STRUCT *sess = &pmch->mbms_sessioninfolist_r9[j];
          ss << "  Service ID: " << sess->tmgi_r9.serviceid_r9;
          if(sess->sessionid_r9_present) {
            ss << ", Session ID: " << (uint32_t)sess->sessionid_r9;
          }
          if(sess->tmgi_r9.plmn_id_explicit) {
            std::string tmp;
            if(mcc_to_string(sess->tmgi_r9.plmn_id_r9.mcc, &tmp)) {
              ss << ", MCC: " << tmp;
            }
            if(mnc_to_string(sess->tmgi_r9.plmn_id_r9.mnc, &tmp)) {
              ss << ", MNC: " << tmp;
            }
          } else {
            ss << ", PLMN index: " << (uint32_t)sess->tmgi_r9.plmn_index_r9;
          }
          ss << ", LCID: " << (uint32_t)sess->logicalchannelid_r9;
          ss << std::endl;
        }
      }
      //rrc_log->console(ss.str());
      std::cout << ss.str();
    } else {
      rrc_log->console("MCCH not available for current cell\n");
    }
  }
}

bool rrc::mbms_service_start(uint32_t serv, uint32_t port)
{
  bool ret = false;

  if(serving_cell->has_mcch) {
    LIBLTE_RRC_MCCH_MSG_STRUCT msg;
    memcpy(&msg, &serving_cell->mcch, sizeof(LIBLTE_RRC_MCCH_MSG_STRUCT));
    for(uint32_t i=0;i<msg.pmch_infolist_r9_size; i++){
      LIBLTE_RRC_PMCH_INFO_R9_STRUCT *pmch = &msg.pmch_infolist_r9[i];
      for(uint32_t j=0;j<pmch->mbms_sessioninfolist_r9_size; j++) {
        LIBLTE_RRC_MBMS_SESSION_INFO_R9_STRUCT *sess = &pmch->mbms_sessioninfolist_r9[j];
        if(serv == sess->tmgi_r9.serviceid_r9) {
          rrc_log->console("MBMS service started. Service id:%d, port: %d\n", serv, port);
          ret = true;
          add_mrb(sess->logicalchannelid_r9, port);
        }
      }
    }
  }
  return ret;
}


void rrc::init(nas_interface_rrc *nas_,
               usim_interface_rrc *usim_,
               gw_interface_rrc *gw_,
               srslte::log *rrc_log_) {
  pool = byte_buffer_pool::get_instance();
  nas = nas_;
  usim = usim_;
  gw = gw_;
  rrc_log = rrc_log_;

  // Use MAC timers
  state = RRC_STATE_IDLE;
  plmn_is_selected = false;

  security_is_activated = false;

  pthread_mutex_init(&mutex, NULL);

  args.ue_category = SRSLTE_UE_CATEGORY;
  args.supported_bands[0] = 7;
  args.nof_supported_bands = 1;
  args.feature_group = 0xe6041000;

  dedicatedInfoNAS = NULL;
  ueIdentity_configured = false;

  transaction_id = 0;

  // Register logging handler with liblte_rrc
  liblte_rrc_log_register_handler(this, liblte_rrc_handler);

  cell_clean_cnt = 0;

  ho_start = false;

  pending_mob_reconf = false;

  if (!init_socket()) {
    rrc_log->warning("init socket failed\n");
  }

  // measurements.init(this);
  // set seed for rand (used in attach)
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

bool rrc::init_socket()
{
  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0)
  {
    rrc_log->error("init socket failed\n");
    return false;
  }

  // TODO parameters read from config file.
  bzero(&enb_addr, sizeof(enb_addr));
  enb_addr.sin_family = AF_INET;
  enb_addr.sin_addr.s_addr = inet_addr("127.0.1.1");
  enb_addr.sin_port = htons(8000);

  bzero(&ue_addr, sizeof(ue_addr));
  ue_addr.sin_family = AF_INET;
  ue_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
  ue_addr.sin_port = htons(6259);

  if (bind(sockfd, (struct sockaddr*)&ue_addr, sizeof(ue_addr)) < 0) {
    rrc_log->error("bind ue addr failed\n");
  }

  return true;
}

struct sockaddr_in rrc::get_addr() {
    return enb_addr;
}

rrc_state_t rrc::get_state() {
  return state;
}

bool rrc::is_connected() {
  return (RRC_STATE_CONNECTED == state);
}

bool rrc::have_drb() {
  return drb_up;
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
  return serving_cell->get_mcc();
}

uint16_t rrc::get_mnc() {
  return serving_cell->get_mnc();
}

/* NAS interface to search for available PLMNs.
 * It goes through all known frequencies, synchronizes and receives SIB1 for each to extract PLMN.
 * The function is blocking and waits until all frequencies have been
 * searched and PLMNs are obtained.
 *
 * This function is thread-safe with connection_request()
 */
int rrc::plmn_search(found_plmn_t found_plmns[MAX_FOUND_PLMNS])
{
  // Mutex with connect
  pthread_mutex_lock(&mutex);

  rrc_log->info("Starting PLMN search\n");
  uint32_t nof_plmns = 0;
  phy_interface_rrc::cell_search_ret_t ret;
  do {
    ret = cell_search();
    if (ret.found == phy_interface_rrc::cell_search_ret_t::CELL_FOUND) {
      if (serving_cell->has_sib1()) {
        // Save PLMN and TAC to NAS
        for (uint32_t i = 0; i < serving_cell->nof_plmns(); i++) {
          if (nof_plmns < MAX_FOUND_PLMNS) {
            found_plmns[nof_plmns].plmn_id = serving_cell->get_plmn(i);
            found_plmns[nof_plmns].tac = serving_cell->get_tac();
            nof_plmns++;
          } else {
            rrc_log->error("No more space for plmns (%d)\n", nof_plmns);
          }
        }
      } else {
        rrc_log->error("SIB1 not acquired\n");
      }
    }
  } while (ret.last_freq == phy_interface_rrc::cell_search_ret_t::MORE_FREQS &&
           ret.found     != phy_interface_rrc::cell_search_ret_t::ERROR);

  // Process all pending measurements before returning
  // process_phy_meas();

  pthread_mutex_unlock(&mutex);

  if (ret.found == phy_interface_rrc::cell_search_ret_t::ERROR) {
    return -1;
  } else {
    return nof_plmns;
  }
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

  if (state != RRC_STATE_IDLE) {
    rrc_log->warning("Requested RRC connection establishment while not in IDLE\n");
    return false;
  }

/*TODO: houmin set barring ?
  if (timers.get(t302)->is_running()) {
    rrc_log->info("Requested RRC connection establishment while T302 is running\n");
    nas->set_barring(nas_interface_rrc::BARRING_MO_DATA);
    return false;
  }
*/

  bool ret = false;

  pthread_mutex_lock(&mutex);

  rrc_log->info("Initiation of Connection establishment procedure\n");

  // Perform cell selection & reselection for the selected PLMN
  cs_ret_t cs_ret = cell_selection();

  // .. and SI acquisition
  // if (phy->cell_is_camping()) {
  if (true) {

    // CCCH configuration applied already at start
    // timeAlignmentCommon applied in configure_serving_cell

    rrc_log->info("Configuring serving cell...\n");
    if (configure_serving_cell()) {
      // Send connectionRequest message to lower layers
      send_con_request(cause);

      // Save dedicatedInfoNAS SDU
      if (this->dedicatedInfoNAS) {
        rrc_log->warning("Received a new dedicatedInfoNAS SDU but there was one still in queue. Removing it\n");
        pool->deallocate(this->dedicatedInfoNAS);
      }
      this->dedicatedInfoNAS = dedicatedInfoNAS;

      /*TODO still wait
      // Wait until t300 stops due to RRCConnectionSetup/Reject or expiry
      while (timers.get(t300)->is_running()) {
        usleep(1000);
        printf("wait until t300 stops\n");
      }
      */

      if (state == RRC_STATE_CONNECTED) {
        // Received ConnectionSetup
        ret = true;
      // } else if (timers.get(t300)->is_expired()) {
      } else if (true) {
        // T300 is expired: 5.3.3.6
        rrc_log->info("Timer T300 expired: ConnectionRequest timed out\n");
        // rlc->reestablish();
      } else {
        // T300 is stopped but RRC not Connected is because received Reject: Section 5.3.3.8
        rrc_log->info("Timer T300 stopped: Received ConnectionReject\n");
      }

    } else {
      rrc_log->error("Configuring serving cell\n");
    }
  } else {
    switch(cs_ret) {
      case SAME_CELL:
        rrc_log->warning("Did not reselect cell but serving cell is out-of-sync.\n");
        serving_cell->in_sync = false;
      break;
      case CHANGED_CELL:
        rrc_log->warning("Selected a new cell but could not camp on. Setting out-of-sync.\n");
        serving_cell->in_sync = false;
        break;
      default:
        rrc_log->warning("Could not find any suitable cell to connect\n");
    }
  }

  if (!ret) {
    rrc_log->warning("Could not estblish connection. Deallocating dedicatedInfoNAS PDU\n");
    pool->deallocate(this->dedicatedInfoNAS);
    this->dedicatedInfoNAS = NULL;
  }

  pthread_mutex_unlock(&mutex);
  return ret;
}

void rrc::set_ue_idenity(LIBLTE_RRC_S_TMSI_STRUCT s_tmsi) {
  ueIdentity_configured = true;
  ueIdentity = s_tmsi;
  rrc_log->info("Set ue-Identity to 0x%x:0x%x\n", ueIdentity.mmec, ueIdentity.m_tmsi);
}

/* Retrieves all required SIB or configures them if already retrieved before
 */
bool rrc::configure_serving_cell() {
/* FIXME: comment by houmin
  if (!phy->cell_is_camping()) {
    rrc_log->error("Trying to configure Cell while not camping on it\n");
    return false;
  }
  serving_cell->has_mcch = false;
  // Obtain the SIBs if not available or apply the configuration if available
  for (uint32_t i = 0; i < NOF_REQUIRED_SIBS; i++) {
    if (!serving_cell->has_sib(required_sibs[i])) {
      rrc_log->info("Cell has no SIB%d. Obtaining SIB%d\n", required_sibs[i]+1, required_sibs[i]+1);
      if (!si_acquire(required_sibs[i])) {
        rrc_log->info("Timeout while acquiring SIB%d\n", required_sibs[i]+1);
        if (required_sibs[i] < 2) {
          return false;
        }
      }
    } else {
      rrc_log->info("Cell has SIB%d\n", required_sibs[i]+1);
      switch(required_sibs[i]) {
        case 1:
          apply_sib2_configs(serving_cell->sib2ptr());
          break;
        case 12:
          apply_sib13_configs(serving_cell->sib13ptr());
          break;
      }
    }
  }
*/
  return true;
}

/*******************************************************************************
*
*
*
* System Information Acquisition procedure
*
*
*
*******************************************************************************/


// Determine SI messages scheduling as in 36.331 5.2.3 Acquisition of an SI message
uint32_t rrc::sib_start_tti(uint32_t tti, uint32_t period, uint32_t offset, uint32_t sf) {
  return (period*10*(1+tti/(period*10))+(offset*10)+sf)%10240; // the 1 means next opportunity
}

/* Implemnets the SI acquisition procedure
 * Configures the MAC/PHY scheduling to retrieve SI messages. The function is blocking and will not
 * return until SIB is correctly received or timeout
 */
/*
bool rrc::si_acquire(uint32_t sib_index)
{
  uint32_t tti;
  uint32_t si_win_start=0, si_win_len=0;
  uint16_t period;
  uint32_t sched_index;
  uint32_t x, sf, offset;

  uint32_t last_win_start = 0;
  uint32_t timeout = 0;

  while(timeout < SIB_SEARCH_TIMEOUT_MS && !serving_cell->has_sib(sib_index)) {

    bool instruct_phy = false;

    if (sib_index == 0) {

      // Instruct MAC to look for SIB1
      tti = mac->get_current_tti();
      si_win_start = sib_start_tti(tti, 2, 0, 5);
      if (last_win_start == 0 ||
          (srslte_tti_interval(tti, last_win_start) >= 20 && srslte_tti_interval(tti, last_win_start) < 1000)) {

        last_win_start = si_win_start;
        si_win_len = 1;
        instruct_phy = true;
      }
      period = 20;
      sched_index = 0;
    } else {
      // Instruct MAC to look for SIB2..13
      if (serving_cell->has_sib1()) {

        LIBLTE_RRC_SYS_INFO_BLOCK_TYPE_1_STRUCT *sib1 = serving_cell->sib1ptr();

        // SIB2 scheduling
        if (sib_index == 1) {
          period      = liblte_rrc_si_periodicity_num[sib1->sched_info[0].si_periodicity];
          sched_index = 0;
        } else {
          // SIB3+ scheduling Section 5.2.3
          if (sib_index >= 2) {
            bool found = false;
            for (uint32_t i=0;i<sib1->N_sched_info && !found;i++) {
              for (uint32_t j=0;j<sib1->sched_info[i].N_sib_mapping_info && !found;j++) {
                if ((uint32_t) sib1->sched_info[i].sib_mapping_info[j].sib_type == sib_index - 2) {
                  period      = liblte_rrc_si_periodicity_num[sib1->sched_info[i].si_periodicity];
                  sched_index = i;
                  found       = true;
                }
              }
            }
            if (!found) {
              rrc_log->info("Could not find SIB%d scheduling in SIB1\n", sib_index+1);
              return false;
            }
          }
        }
        si_win_len   = liblte_rrc_si_window_length_num[sib1->si_window_length];
        x            = sched_index*si_win_len;
        sf           = x%10;
        offset       = x/10;

        tti          = mac->get_current_tti();
        si_win_start = sib_start_tti(tti, period, offset, sf);
        si_win_len = liblte_rrc_si_window_length_num[sib1->si_window_length];

        if (last_win_start == 0 ||
            (srslte_tti_interval(tti, last_win_start) > period*5 && srslte_tti_interval(tti, last_win_start) < 1000))
        {
          last_win_start = si_win_start;
          instruct_phy = true;
        }
      } else {
        rrc_log->error("Trying to receive SIB%d but SIB1 not received\n", sib_index+1);
      }
    }

    // Instruct MAC to decode SIB
    if (instruct_phy && !serving_cell->has_sib(sib_index)) {
      mac->bcch_start_rx(si_win_start, si_win_len);
      rrc_log->info("Instructed MAC to search for SIB%d, win_start=%d, win_len=%d, period=%d, sched_index=%d\n",
                    sib_index+1, si_win_start, si_win_len, period, sched_index);
    }
    usleep(1000);
    timeout++;
  }
  return serving_cell->has_sib(sib_index);
}
*/

/*******************************************************************************
*
*
*
* Cell selection, reselection and neighbour cell database management
*
*
*
*******************************************************************************/

/* Searches for a cell in the current frequency and retrieves SIB1 if not retrieved yet
 */
phy_interface_rrc::cell_search_ret_t rrc::cell_search()
{
  phy_interface_rrc::phy_cell_t new_cell;
  new_cell.earfcn = 3400;
  new_cell.cell.id = 1;

  // phy_interface_rrc::cell_search_ret_t ret = phy->cell_search(&new_cell);
  phy_interface_rrc::cell_search_ret_t ret;
  ret.found = phy_interface_rrc::cell_search_ret_t::CELL_FOUND;
  ret.last_freq = phy_interface_rrc::cell_search_ret_t::NO_MORE_FREQS;

  LIBLTE_RRC_SYS_INFO_BLOCK_TYPE_1_STRUCT *sib1 = new LIBLTE_RRC_SYS_INFO_BLOCK_TYPE_1_STRUCT;

  switch(ret.found) {
    case phy_interface_rrc::cell_search_ret_t::CELL_FOUND:
      rrc_log->info("Cell found in this frequency. Setting new serving cell...\n");

      // Create cell with NaN RSRP. Will be updated by new_phy_meas() during SIB search.
      if (!add_neighbour_cell(new_cell, NAN)) {
        rrc_log->info("No more space for neighbour cells\n");
        break;
      }
      set_serving_cell(new_cell);
      sib1->N_plmn_ids = 1;
      sib1->tracking_area_code = 1;
      sib1->plmn_id[0].id.mcc = 61441;
      sib1->plmn_id[0].id.mnc = 65281;
      serving_cell->set_sib1(sib1);

      // if (phy->cell_is_camping()) {
      if (true) {
        if (!serving_cell->has_sib1()) {
          rrc_log->info("Cell has no SIB1. Obtaining SIB1\n");
          //  if (!si_acquire(0)) {
          if (false) {
            rrc_log->error("Timeout while acquiring SIB1\n");
          }
        } else {
          rrc_log->info("Cell has SIB1\n");
        }
      } else {
        rrc_log->warning("Could not camp on found cell. Trying next one...\n");
      }
      break;
    case phy_interface_rrc::cell_search_ret_t::CELL_NOT_FOUND:
      rrc_log->info("No cells found.\n");
      break;
    case phy_interface_rrc::cell_search_ret_t::ERROR:
      rrc_log->error("In cell search. Finishing PLMN search\n");
      break;
  }
  return ret;
}

/* Cell selection procedure 36.304 5.2.3
 * Select the best cell to camp on among the list of known cells
 */
rrc::cs_ret_t rrc::cell_selection()
{
/* FIXME: comment by houmin
  // Neighbour cells are sorted in descending order of RSRP
  for (uint32_t i = 0; i < neighbour_cells.size(); i++) {
    if (//TODO: CHECK that PLMN matches. Currently we don't receive SIB1 of neighbour cells
        // neighbour_cells[i]->plmn_equals(selected_plmn_id) &&
        neighbour_cells[i]->in_sync) // matches S criteria
    {
      // If currently connected, verify cell selection criteria
      if (!serving_cell->in_sync ||
          (cell_selection_criteria(neighbour_cells[i]->get_rsrp())  &&
              neighbour_cells[i]->get_rsrp() > serving_cell->get_rsrp() + 5))
      {
        // Try to select Cell
        set_serving_cell(i);
        rrc_log->info("Selected cell idx=%d, PCI=%d, EARFCN=%d\n",
                      i, serving_cell->get_pci(), serving_cell->get_earfcn());
        rrc_log->console("Selected cell PCI=%d, EARFCN=%d\n",
                         serving_cell->get_pci(), serving_cell->get_earfcn());

        if (phy->cell_select(&serving_cell->phy_cell)) {
          if (configure_serving_cell()) {
            rrc_log->info("Selected and configured cell successfully\n");
            return CHANGED_CELL;
          } else {
            rrc_log->error("While configuring serving cell\n");
          }
        } else {
          serving_cell->in_sync = false;
          rrc_log->warning("Could not camp on selected cell\n");
        }
      }
    }
  }
*/
  if (serving_cell->in_sync) {
    /* FIXME: comment by houmin
    // if (!phy->cell_is_camping()) {
    if (false) {
      rrc_log->info("Serving cell is in-sync but not camping. Selecting it...\n");
      if (phy->cell_select(&serving_cell->phy_cell)) {
        rrc_log->info("Selected serving cell OK.\n");
      } else {
        serving_cell->in_sync = false;
        rrc_log->error("Could not camp on serving cell.\n");
      }
    }
    */
    return SAME_CELL;
  }
  // If can not find any suitable cell, search again
  rrc_log->info("Cell selection and reselection in IDLE did not find any suitable cell. Searching again\n");
  // If can not camp on any cell, search again for new cells
  phy_interface_rrc::cell_search_ret_t ret = cell_search();

  return (ret.found == phy_interface_rrc::cell_search_ret_t::CELL_FOUND)?CHANGED_CELL:NO_CELL;
}

// Cell selection criteria Section 5.2.3.2 of 36.304
bool rrc::cell_selection_criteria(float rsrp, float rsrq)
{
  if (get_srxlev(rsrp) > 0 || !serving_cell->has_sib3()) {
    return true;
  } else {
    return false;
  }
}

float rrc::get_srxlev(float Qrxlevmeas) {
  // TODO: Do max power limitation
  float Pcompensation = 0;
  return Qrxlevmeas - (cell_resel_cfg.Qrxlevmin + cell_resel_cfg.Qrxlevminoffset) - Pcompensation;
}

float rrc::get_squal(float Qqualmeas) {
  return Qqualmeas - (cell_resel_cfg.Qqualmin + cell_resel_cfg.Qqualminoffset);
}

// Cell reselection in IDLE Section 5.2.4 of 36.304
void rrc::cell_reselection(float rsrp, float rsrq)
{
//TODO
}

// Set new serving cell
void rrc::set_serving_cell(phy_interface_rrc::phy_cell_t phy_cell) {
  int cell_idx = find_neighbour_cell(phy_cell.earfcn, phy_cell.cell.id);
  if (cell_idx >= 0) {
    set_serving_cell(cell_idx);
  } else {
    rrc_log->error("Setting serving cell: Unkonwn cell with earfcn=%d, PCI=%d\n", phy_cell.earfcn, phy_cell.cell.id);
  }
}

// Set new serving cell
void rrc::set_serving_cell(uint32_t cell_idx) {

  if (cell_idx < neighbour_cells.size())
  {
    // Remove future serving cell from neighbours to make space for current serving cell
    cell_t *new_serving_cell = neighbour_cells[cell_idx];
    if (!new_serving_cell) {
      rrc_log->error("Setting serving cell. Index %d is empty\n", cell_idx);
      return;
    }
    neighbour_cells.erase(std::remove(neighbour_cells.begin(), neighbour_cells.end(), neighbour_cells[cell_idx]), neighbour_cells.end());

    // Move serving cell to neighbours list
    if (serving_cell->is_valid()) {
      // Make sure it does not exist already
      int serving_idx = find_neighbour_cell(serving_cell->get_earfcn(), serving_cell->get_pci());
      if (serving_idx >= 0 && (uint32_t) serving_idx < neighbour_cells.size()) {
        printf("Error serving cell is already in the neighbour list. Removing it\n");
        neighbour_cells.erase(std::remove(neighbour_cells.begin(), neighbour_cells.end(), neighbour_cells[serving_idx]), neighbour_cells.end());
      }
      // If not in the list, add it to the list of neighbours (sorted inside the function)
      if (!add_neighbour_cell(serving_cell)) {
        rrc_log->info("Serving cell not added to list of neighbours. Worse than current neighbours\n");
      }
    }

    // Set new serving cell
    serving_cell = new_serving_cell;

    rrc_log->info("Setting serving cell idx=%d, earfcn=%d, PCI=%d, nof_neighbours=%lu\n",
                  cell_idx, serving_cell->get_earfcn(), serving_cell->get_pci(), neighbour_cells.size());

  } else {
    rrc_log->error("Setting invalid serving cell idx %d\n", cell_idx);
  }
}

bool sort_rsrp(cell_t *u1, cell_t *u2) {
  return u1->greater(u2);
}

void rrc::delete_neighbour(uint32_t cell_idx) {
  delete neighbour_cells[cell_idx];
  neighbour_cells.erase(std::remove(neighbour_cells.begin(), neighbour_cells.end(), neighbour_cells[cell_idx]), neighbour_cells.end());
}

std::vector<cell_t*>::iterator rrc::delete_neighbour(std::vector<cell_t*>::iterator it) {
  delete (*it);
  return neighbour_cells.erase(it);
}

/* Called by main RRC thread to remove neighbours from which measurements have not been received in a while
 */
void rrc::clean_neighbours()
{
  struct timeval now;
  gettimeofday(&now, NULL);

  std::vector<cell_t*>::iterator it = neighbour_cells.begin();
  while(it != neighbour_cells.end()) {
    if ((*it)->timeout_secs(now) > NEIGHBOUR_TIMEOUT) {
      rrc_log->info("Neighbour PCI=%d timed out. Deleting\n", (*it)->get_pci());
      it = delete_neighbour(it);
    } else {
      ++it;
    }
  }
}

// Sort neighbour cells by decreasing order of RSRP
void rrc::sort_neighbour_cells()
{
  // Remove out-of-sync cells
  std::vector<cell_t*>::iterator it = neighbour_cells.begin();
  while(it != neighbour_cells.end()) {
    if ((*it)->in_sync == false) {
      rrc_log->info("Neighbour PCI=%d is out-of-sync. Deleting\n", (*it)->get_pci());
      it = delete_neighbour(it);
    } else {
      ++it;
    }
  }

  std::sort(neighbour_cells.begin(), neighbour_cells.end(), sort_rsrp);

  if (neighbour_cells.size() > 0) {
    char ordered[512];
    int n=0;
    n += snprintf(ordered, 512, "[pci=%d, rsrp=%.2f", neighbour_cells[0]->phy_cell.cell.id, neighbour_cells[0]->get_rsrp());
    for (uint32_t i=1;i<neighbour_cells.size();i++) {
      n += snprintf(&ordered[n], 512-n, " | pci=%d, rsrp=%.2f", neighbour_cells[i]->get_pci(), neighbour_cells[i]->get_rsrp());
    }
    rrc_log->info("Neighbours: %s]\n", ordered);
  } else {
    rrc_log->info("Neighbours: Empty\n");
  }
}

bool rrc::add_neighbour_cell(cell_t *new_cell) {
  bool ret = false;
  if (neighbour_cells.size() < NOF_NEIGHBOUR_CELLS) {
    ret = true;
  } else if (new_cell->greater(neighbour_cells[neighbour_cells.size()-1])) {
    // Replace old one by new one
    delete_neighbour(neighbour_cells.size()-1);
    ret = true;
  }
  if (ret) {
    neighbour_cells.push_back(new_cell);
  }
  rrc_log->info("Added neighbour cell EARFCN=%d, PCI=%d, nof_neighbours=%zd\n",
                new_cell->get_earfcn(), new_cell->get_pci(), neighbour_cells.size());
  sort_neighbour_cells();
  return ret;
}

// If only neighbour PCI is provided, copy full cell from serving cell
bool rrc::add_neighbour_cell(uint32_t earfcn, uint32_t pci, float rsrp) {
  phy_interface_rrc::phy_cell_t phy_cell;
  phy_cell = serving_cell->phy_cell;
  phy_cell.earfcn = earfcn;
  phy_cell.cell.id = pci;
  return add_neighbour_cell(phy_cell, rsrp);
}

bool rrc::add_neighbour_cell(phy_interface_rrc::phy_cell_t phy_cell, float rsrp) {
  if (phy_cell.earfcn == 0) {
    phy_cell.earfcn = serving_cell->get_earfcn();
  }

  // First check if already exists
  int cell_idx = find_neighbour_cell(phy_cell.earfcn, phy_cell.cell.id);

  rrc_log->info("Adding PCI=%d, earfcn=%d, cell_idx=%d\n", phy_cell.cell.id, phy_cell.earfcn, cell_idx);

  // If exists, update RSRP if provided, sort again and return
  if (cell_idx >= 0 && isnormal(rsrp)) {
    neighbour_cells[cell_idx]->set_rsrp(rsrp);
    sort_neighbour_cells();
    return true;
  }

  // If not, create a new one
  cell_t *new_cell = new cell_t(phy_cell, rsrp);

  return add_neighbour_cell(new_cell);
}

int rrc::find_neighbour_cell(uint32_t earfcn, uint32_t pci) {
  for (uint32_t i = 0; i < neighbour_cells.size(); i++) {
    if (neighbour_cells[i]->equals(earfcn, pci)) {
      return (int) i;
    }
  }
  return -1;
}


/*******************************************************************************
*
*
*
* Other functions
*
*
*
*******************************************************************************/

/* Detection of radio link failure (5.3.11.3)
 * Upon T310 expiry, RA problem or RLC max retx
 */
void rrc::radio_link_failure() {
  // TODO: Generate and store failure report
  rrc_log->warning("Detected Radio-Link Failure\n");
  rrc_log->console("Warning: Detected Radio-Link Failure\n");
  if (state == RRC_STATE_CONNECTED) {
    go_rlf = true;
  }
}

void rrc::max_retx_attempted() {
  //TODO: Handle the radio link failure
  rrc_log->warning("Max RLC reTx attempted\n");
  radio_link_failure();
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

void rrc::send_con_request(LIBLTE_RRC_CON_REQ_EST_CAUSE_ENUM cause) {
  rrc_log->debug("Preparing RRC Connection Request\n");
  bzero(&ul_ccch_msg, sizeof(LIBLTE_RRC_UL_CCCH_MSG_STRUCT));

  // Prepare ConnectionRequest packet
  ul_ccch_msg.msg_type = LIBLTE_RRC_UL_CCCH_MSG_TYPE_RRC_CON_REQ;

  if (ueIdentity_configured) {
    ul_ccch_msg.msg.rrc_con_req.ue_id_type = LIBLTE_RRC_CON_REQ_UE_ID_TYPE_S_TMSI;
    ul_ccch_msg.msg.rrc_con_req.ue_id.s_tmsi.m_tmsi = ueIdentity.m_tmsi;
    ul_ccch_msg.msg.rrc_con_req.ue_id.s_tmsi.mmec   = ueIdentity.mmec;
  } else {
    ul_ccch_msg.msg.rrc_con_req.ue_id_type = LIBLTE_RRC_CON_REQ_UE_ID_TYPE_RANDOM_VALUE;
    // TODO use proper RNG
    uint64_t random_id = 0;
    for (uint i = 0; i < 5; i++) { // fill random ID bytewise, 40 bits = 5 bytes
      random_id |= ( (uint64_t)rand() & 0xFF ) << i*8;
    }
    ul_ccch_msg.msg.rrc_con_req.ue_id.random = random_id;
  }

  ul_ccch_msg.msg.rrc_con_req.cause = cause;

  send_ul_ccch_msg();
}

/* RRC connection re-establishment procedure (5.3.7) */
void rrc::send_con_restablish_request(LIBLTE_RRC_CON_REEST_REQ_CAUSE_ENUM cause)
{
  bzero(&ul_ccch_msg, sizeof(LIBLTE_RRC_UL_CCCH_MSG_STRUCT));

  uint16_t crnti;
  uint16_t pci;
  uint32_t cellid;
  if (cause == LIBLTE_RRC_CON_REEST_REQ_CAUSE_HANDOVER_FAILURE) {
    crnti  = ho_src_rnti;
    pci    = ho_src_cell.get_pci();
    cellid = ho_src_cell.get_cell_id();
  } else {
    mac_interface_rrc::ue_rnti_t uernti;
    // mac->get_rntis(&uernti); TODO how to get rnti
    crnti  = uernti.crnti;
    pci    = serving_cell->get_pci();
    cellid = serving_cell->get_cell_id();
  }

  // Compute shortMAC-I
  uint8_t varShortMAC[128], varShortMAC_packed[16];
  bzero(varShortMAC, 128);
  bzero(varShortMAC_packed, 16);
  uint8_t *msg_ptr = varShortMAC;

  // ASN.1 encode VarShortMAC-Input
  liblte_rrc_pack_cell_identity_ie(cellid, &msg_ptr);
  liblte_rrc_pack_phys_cell_id_ie(pci, &msg_ptr);
  liblte_rrc_pack_c_rnti_ie(crnti, &msg_ptr);

  // byte align (already zero-padded)
  uint32_t N_bits  = (uint32_t) (msg_ptr-varShortMAC);
  uint32_t N_bytes = ((N_bits-1)/8+1);
  srslte_bit_pack_vector(varShortMAC, varShortMAC_packed, N_bytes*8);

  rrc_log->info("Encoded varShortMAC: cellId=0x%x, PCI=%d, rnti=0x%x (%d bytes, %d bits)\n",
                cellid, pci, crnti, N_bytes, N_bits);

  // Compute MAC-I
  uint8_t mac_key[4];
  switch(integ_algo) {
    case INTEGRITY_ALGORITHM_ID_128_EIA1:
      security_128_eia1(&k_rrc_int[16],
                        0xffffffff,    // 32-bit all to ones
                        0x1f,          // 5-bit all to ones
                        1,             // 1-bit to one
                        varShortMAC_packed,
                        N_bytes,
                        mac_key);
      break;
    case INTEGRITY_ALGORITHM_ID_128_EIA2:
      security_128_eia2(&k_rrc_int[16],
                        0xffffffff,    // 32-bit all to ones
                        0x1f,          // 5-bit all to ones
                        1,             // 1-bit to one
                        varShortMAC_packed,
                        N_bytes,
                        mac_key);
      break;
    default:
      rrc_log->info("Unsupported integrity algorithm during reestablishment\n");
  }

  // Prepare ConnectionRestalishmentRequest packet
  ul_ccch_msg.msg_type = LIBLTE_RRC_UL_CCCH_MSG_TYPE_RRC_CON_REEST_REQ;
  ul_ccch_msg.msg.rrc_con_reest_req.ue_id.c_rnti = crnti;
  ul_ccch_msg.msg.rrc_con_reest_req.ue_id.phys_cell_id = pci;
  ul_ccch_msg.msg.rrc_con_reest_req.ue_id.short_mac_i = mac_key[2] << 8 | mac_key[3];
  ul_ccch_msg.msg.rrc_con_reest_req.cause = cause;

  rrc_log->info("Initiating RRC Connection Reestablishment Procedure\n");
  rrc_log->console("RRC Connection Reestablishment\n");

  // Perform cell selection in accordance to 36.304
  if (cell_selection_criteria(serving_cell->get_rsrp()) && serving_cell->in_sync) {
    // if (phy->cell_select(&serving_cell->phy_cell)) {
    if (true) {

      //if (timers.get(t311)->is_running()) {
      if (true) { //TODO
        // Actions following cell reselection while T311 is running 5.3.7.3
        rrc_log->info("Cell Selection finished. Initiating transmission of RRC Connection Reestablishment Request\n");
        liblte_rrc_pack_ul_ccch_msg(&ul_ccch_msg, (LIBLTE_BIT_MSG_STRUCT *) &bit_buf);

        send_ul_ccch_msg();
      } else {
        rrc_log->info("T311 expired while selecting cell. Going to IDLE\n");
        go_idle = true;
      }
    } else {
      rrc_log->warning("Could not re-synchronize with cell.\n");
      go_idle = true;
    }
  } else {
    rrc_log->info("Selected cell no longer suitable for camping (in_sync=%s). Going to IDLE\n", serving_cell->in_sync?"yes":"no");
    go_idle = true;
  }
}

void rrc::send_con_restablish_complete() {
  bzero(&ul_dcch_msg, sizeof(LIBLTE_RRC_UL_DCCH_MSG_STRUCT));

  rrc_log->debug("Preparing RRC Connection Reestablishment Complete\n");

  rrc_log->console("RRC Connected\n");

  // Prepare ConnectionSetupComplete packet
  ul_dcch_msg.msg_type = LIBLTE_RRC_UL_DCCH_MSG_TYPE_RRC_CON_REEST_COMPLETE;
  ul_dcch_msg.msg.rrc_con_reest_complete.rrc_transaction_id = transaction_id;

  send_ul_dcch_msg();
}

void rrc::send_con_setup_complete(byte_buffer_t *nas_msg) {
  bzero(&ul_dcch_msg, sizeof(LIBLTE_RRC_UL_DCCH_MSG_STRUCT));
  rrc_log->debug("Preparing RRC Connection Setup Complete\n");

  // Prepare ConnectionSetupComplete packet
  ul_dcch_msg.msg_type = LIBLTE_RRC_UL_DCCH_MSG_TYPE_RRC_CON_SETUP_COMPLETE;
  ul_dcch_msg.msg.rrc_con_setup_complete.registered_mme_present = false;
  ul_dcch_msg.msg.rrc_con_setup_complete.rrc_transaction_id = transaction_id;
  ul_dcch_msg.msg.rrc_con_setup_complete.selected_plmn_id = 1;
  memcpy(ul_dcch_msg.msg.rrc_con_setup_complete.dedicated_info_nas.msg, nas_msg->msg, nas_msg->N_bytes);
  ul_dcch_msg.msg.rrc_con_setup_complete.dedicated_info_nas.N_bytes = nas_msg->N_bytes;

  pool->deallocate(nas_msg);

  send_ul_dcch_msg();
}

void rrc::send_ul_info_transfer(byte_buffer_t *nas_msg) {
  bzero(&ul_dcch_msg, sizeof(LIBLTE_RRC_UL_DCCH_MSG_STRUCT));

  rrc_log->debug("Preparing RX Info Transfer\n");

  // Prepare RX INFO packet
  ul_dcch_msg.msg_type = LIBLTE_RRC_UL_DCCH_MSG_TYPE_UL_INFO_TRANSFER;
  ul_dcch_msg.msg.ul_info_transfer.dedicated_info_type = LIBLTE_RRC_UL_INFORMATION_TRANSFER_TYPE_NAS;
  memcpy(ul_dcch_msg.msg.ul_info_transfer.dedicated_info.msg, nas_msg->msg, nas_msg->N_bytes);
  ul_dcch_msg.msg.ul_info_transfer.dedicated_info.N_bytes = nas_msg->N_bytes;

  pool->deallocate(nas_msg);

  send_ul_dcch_msg();
}

void rrc::send_security_mode_complete() {
  bzero(&ul_dcch_msg, sizeof(LIBLTE_RRC_UL_DCCH_MSG_STRUCT));
  rrc_log->debug("Preparing Security Mode Complete\n");

  ul_dcch_msg.msg_type = LIBLTE_RRC_UL_DCCH_MSG_TYPE_SECURITY_MODE_COMPLETE;
  ul_dcch_msg.msg.security_mode_complete.rrc_transaction_id = transaction_id;

  send_ul_dcch_msg();
}

void rrc::send_rrc_con_reconfig_complete() {
  bzero(&ul_dcch_msg, sizeof(LIBLTE_RRC_UL_DCCH_MSG_STRUCT));
  rrc_log->debug("Preparing RRC Connection Reconfig Complete\n");

  ul_dcch_msg.msg_type = LIBLTE_RRC_UL_DCCH_MSG_TYPE_RRC_CON_RECONFIG_COMPLETE;
  ul_dcch_msg.msg.rrc_con_reconfig_complete.rrc_transaction_id = transaction_id;

  send_ul_dcch_msg();
}

bool rrc::ho_prepare() {
  if (pending_mob_reconf) {
    rrc_log->info("Processing HO command to target PCell=%d\n", mob_reconf.mob_ctrl_info.target_pci);

    int target_cell_idx = find_neighbour_cell(serving_cell->get_earfcn(), mob_reconf.mob_ctrl_info.target_pci);
    if (target_cell_idx < 0) {
      rrc_log->console("Received HO command to unknown PCI=%d\n", mob_reconf.mob_ctrl_info.target_pci);
      rrc_log->error("Could not find target cell earfcn=%d, pci=%d\n",
                     serving_cell->get_earfcn(),
                     mob_reconf.mob_ctrl_info.target_pci);
      return false;
    }

    // Section 5.3.5.4
    /* timers.get(t310)->stop();
    timers.get(t304)->set(this, liblte_rrc_t304_num[mob_reconf.mob_ctrl_info.t304]);
    if (mob_reconf.mob_ctrl_info.carrier_freq_eutra_present &&
        mob_reconf.mob_ctrl_info.carrier_freq_eutra.dl_carrier_freq != serving_cell->get_earfcn()) {
      rrc_log->error("Received mobilityControlInfo for inter-frequency handover\n");
      return false;
    }

    // Save serving cell and current configuration
    ho_src_cell = *serving_cell;
    mac_interface_rrc::ue_rnti_t uernti;
    mac->get_rntis(&uernti);
    ho_src_rnti = uernti.crnti;

    mac->set_ho_rnti(mob_reconf.mob_ctrl_info.new_ue_id, mob_reconf.mob_ctrl_info.target_pci);
     apply_rr_config_common_dl(&mob_reconf.mob_ctrl_info.rr_cnfg_common);

    if (!phy->cell_select(&neighbour_cells[target_cell_idx]->phy_cell)) {
      rrc_log->error("Could not synchronize with target cell pci=%d. Trying to return to source PCI\n",
                     neighbour_cells[target_cell_idx]->get_pci());
      return false;
    }

    set_serving_cell(target_cell_idx);

    if (mob_reconf.mob_ctrl_info.rach_cnfg_ded_present) {
      rrc_log->info("Starting non-contention based RA with preamble_idx=%d, mask_idx=%d\n",
                    mob_reconf.mob_ctrl_info.rach_cnfg_ded.preamble_index,
                    mob_reconf.mob_ctrl_info.rach_cnfg_ded.prach_mask_index);
      mac->start_noncont_ho(mob_reconf.mob_ctrl_info.rach_cnfg_ded.preamble_index,
                            mob_reconf.mob_ctrl_info.rach_cnfg_ded.prach_mask_index);
    } else {
      rrc_log->info("Starting contention-based RA\n");
      mac->start_cont_ho();
    }
    */

    int ncc = -1;
    if (mob_reconf.sec_cnfg_ho_present) {
      ncc = mob_reconf.sec_cnfg_ho.intra_lte.next_hop_chaining_count;
      if (mob_reconf.sec_cnfg_ho.intra_lte.key_change_ind) {
        rrc_log->console("keyChangeIndicator in securityConfigHO not supported\n");
        return false;
      }
      if (mob_reconf.sec_cnfg_ho.intra_lte.sec_alg_cnfg_present) {
        cipher_algo = (CIPHERING_ALGORITHM_ID_ENUM) mob_reconf.sec_cnfg_ho.intra_lte.sec_alg_cnfg.cipher_alg;
        integ_algo  = (INTEGRITY_ALGORITHM_ID_ENUM) mob_reconf.sec_cnfg_ho.intra_lte.sec_alg_cnfg.int_alg;
        rrc_log->info("Changed Ciphering to %s and Integrity to %s\n",
                      ciphering_algorithm_id_text[cipher_algo],
                      integrity_algorithm_id_text[integ_algo]);
      }
    }

    /*TODO phy?
    usim->generate_as_keys_ho(mob_reconf.mob_ctrl_info.target_pci, phy->get_current_earfcn(),
                              ncc,
                              k_rrc_enc, k_rrc_int, k_up_enc, k_up_int, cipher_algo, integ_algo);
    */

    // pdcp->config_security_all(k_rrc_enc, k_rrc_int, cipher_algo, integ_algo);
    send_rrc_con_reconfig_complete();
  }
  return true;
}


bool rrc::con_reconfig_ho(LIBLTE_RRC_CONNECTION_RECONFIGURATION_STRUCT *reconfig)
{
/*TODO phy?
  if (reconfig->mob_ctrl_info.target_pci == phy->get_current_pci()) {
    rrc_log->console("Warning: Received HO command to own cell\n");
    rrc_log->warning("Received HO command to own cell\n");
    return false;
  }
*/

  rrc_log->info("Received HO command to target PCell=%d\n", reconfig->mob_ctrl_info.target_pci);
  rrc_log->console("Received HO command to target PCell=%d, NCC=%d\n",
                   reconfig->mob_ctrl_info.target_pci, reconfig->sec_cnfg_ho.intra_lte.next_hop_chaining_count);

  // store mobilityControlInfo
  memcpy(&mob_reconf, reconfig, sizeof(LIBLTE_RRC_CONNECTION_RECONFIGURATION_STRUCT));
  pending_mob_reconf = true;

  ho_start = true;

  return true;
}

// Handle RRC Reconfiguration without MobilityInformation Section 5.3.5.3
bool rrc::con_reconfig(LIBLTE_RRC_CONNECTION_RECONFIGURATION_STRUCT *reconfig) {
  /* TODO
  if (reconfig->rr_cnfg_ded_present) {
    if (!apply_rr_config_dedicated(&reconfig->rr_cnfg_ded)) {
      return false;
    }
  }
  if (reconfig->meas_cnfg_present) {
    if (!measurements.parse_meas_config(&reconfig->meas_cnfg)) {
      return false;
    }
  }
  */

  send_rrc_con_reconfig_complete();

  byte_buffer_t *nas_sdu;
  for (uint32_t i = 0; i < reconfig->N_ded_info_nas; i++) {
    nas_sdu = pool_allocate;
    if (nas_sdu) {
      memcpy(nas_sdu->msg, &reconfig->ded_info_nas_list[i].msg, reconfig->ded_info_nas_list[i].N_bytes);
      nas_sdu->N_bytes = reconfig->ded_info_nas_list[i].N_bytes;
      nas->write_pdu(RB_ID_SRB1, nas_sdu);
    } else {
      rrc_log->error("Fatal Error: Couldn't allocate PDU in handle_rrc_con_reconfig().\n");
      return false;
    }
  }
  return true;
}

// HO failure from T304 expiry 5.3.5.6
void rrc::ho_failed() {
  send_con_restablish_request(LIBLTE_RRC_CON_REEST_REQ_CAUSE_HANDOVER_FAILURE);
}

// Reconfiguration failure or Section 5.3.5.5
void rrc::con_reconfig_failed()
{
  // Set previous PHY/MAC configuration
  // phy->set_config(&previous_phy_cfg); TODO
  // mac->set_config(&previous_mac_cfg);

  if (security_is_activated) {
    // Start the Reestablishment Procedure
    send_con_restablish_request(LIBLTE_RRC_CON_REEST_REQ_CAUSE_RECONFIG_FAILURE);
  } else {
    go_idle = true;
  }
}

void rrc::handle_rrc_con_reconfig(uint32_t lcid, LIBLTE_RRC_CONNECTION_RECONFIGURATION_STRUCT *reconfig)
{
/* TODO
  phy->get_config(&previous_phy_cfg);
  mac->get_config(&previous_mac_cfg);
*/

  if (reconfig->mob_ctrl_info_present) {
    if (!con_reconfig_ho(reconfig)) {
      con_reconfig_failed();
    }
  } else {
    if (!con_reconfig(reconfig)) {
      con_reconfig_failed();
    }
  }
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
  drb_up = false;
  security_is_activated = false;
/*TODO
  measurements.reset();
  pdcp->reset();
  rlc->reset();
  timers.get(t301)->stop();
  timers.get(t310)->stop();
  timers.get(t311)->stop();
  timers.get(t304)->stop();
  rrc_log->info("Going RRC_IDLE\n");
  if (phy->cell_is_camping()) {
    // Receive paging
    mac->pcch_start_rx();
    // Instruct PHY to measure serving cell for cell reselection
    phy->meas_start(phy->get_current_earfcn(), phy->get_current_pci());
  }
*/
}

/*******************************************************************************
*
*
*
* Reception of Broadcast messages (MIB and SIBs)
*
*
*
*******************************************************************************/
void rrc::write_pdu_bcch_bch(byte_buffer_t *pdu) {
  // Do we need to do something with BCH?
  rrc_log->info_hex(pdu->msg, pdu->N_bytes, "BCCH BCH message received.");
  pool->deallocate(pdu);
}

void rrc::write_pdu_bcch_dlsch(byte_buffer_t *pdu) {
  // mac->clear_rntis();

  rrc_log->info_hex(pdu->msg, pdu->N_bytes, "BCCH DLSCH message received.");
  rrc_log->info("BCCH DLSCH message Stack latency: %ld us\n", pdu->get_latency_us());
  LIBLTE_RRC_BCCH_DLSCH_MSG_STRUCT dlsch_msg;
  ZERO_OBJECT(dlsch_msg);

  srslte_bit_unpack_vector(pdu->msg, bit_buf.msg, pdu->N_bytes * 8);
  bit_buf.N_bits = pdu->N_bytes * 8;
  pool->deallocate(pdu);
  liblte_rrc_unpack_bcch_dlsch_msg((LIBLTE_BIT_MSG_STRUCT *) &bit_buf, &dlsch_msg);

  for(uint32_t i=0; i<dlsch_msg.N_sibs; i++) {
    rrc_log->info("Processing SIB%d (%d/%d)\n", liblte_rrc_sys_info_block_type_num[dlsch_msg.sibs[i].sib_type], i, dlsch_msg.N_sibs);

    if (LIBLTE_RRC_SYS_INFO_BLOCK_TYPE_1 == dlsch_msg.sibs[i].sib_type) {
      serving_cell->set_sib1(&dlsch_msg.sibs[i].sib.sib1);
      handle_sib1();
    } else if (LIBLTE_RRC_SYS_INFO_BLOCK_TYPE_2 == dlsch_msg.sibs[i].sib_type && !serving_cell->has_sib2()) {
      serving_cell->set_sib2(&dlsch_msg.sibs[i].sib.sib2);
      handle_sib2();
    } else if (LIBLTE_RRC_SYS_INFO_BLOCK_TYPE_3 == dlsch_msg.sibs[i].sib_type && !serving_cell->has_sib3()) {
      serving_cell->set_sib3(&dlsch_msg.sibs[i].sib.sib3);
      handle_sib3();
    }else if (LIBLTE_RRC_SYS_INFO_BLOCK_TYPE_13 == dlsch_msg.sibs[i].sib_type && !serving_cell->has_sib13()) {
      serving_cell->set_sib13(&dlsch_msg.sibs[i].sib.sib13);
      handle_sib13();
    }
  }
}

void rrc::handle_sib1()
{
  LIBLTE_RRC_SYS_INFO_BLOCK_TYPE_1_STRUCT *sib1 = serving_cell->sib1ptr();
  rrc_log->info("SIB1 received, CellID=%d, si_window=%d, sib2_period=%d\n",
                serving_cell->get_cell_id()&0xfff,
                liblte_rrc_si_window_length_num[sib1->si_window_length],
                liblte_rrc_si_periodicity_num[sib1->sched_info[0].si_periodicity]);

  // Print SIB scheduling info
  uint32_t i,j;
  for(i=0;i<sib1->N_sched_info;i++){
    for(j=0;j<sib1->sched_info[i].N_sib_mapping_info;j++){
      LIBLTE_RRC_SIB_TYPE_ENUM t       = sib1->sched_info[i].sib_mapping_info[j].sib_type;
      LIBLTE_RRC_SI_PERIODICITY_ENUM p = sib1->sched_info[i].si_periodicity;
      rrc_log->debug("SIB scheduling info, sib_type=%d, si_periodicity=%d\n",
                    liblte_rrc_sib_type_num[t],
                    liblte_rrc_si_periodicity_num[p]);
    }
  }

  // Set TDD Config
  /*
  if(sib1->tdd) {
    phy->set_config_tdd(&sib1->tdd_cnfg);
  }*/
}

void rrc::handle_sib2()
{
  rrc_log->info("SIB2 received\n");

  //apply_sib2_configs(serving_cell->sib2ptr());

}

void rrc::handle_sib3()
{
  rrc_log->info("SIB3 received\n");

  LIBLTE_RRC_SYS_INFO_BLOCK_TYPE_3_STRUCT *sib3 = serving_cell->sib3ptr();

  // cellReselectionInfoCommon
  cell_resel_cfg.q_hyst = liblte_rrc_q_hyst_num[sib3->q_hyst];

  // cellReselectionServingFreqInfo
  cell_resel_cfg.threshservinglow = sib3->thresh_serving_low;

  // intraFreqCellReselectionInfo
  cell_resel_cfg.Qrxlevmin       = sib3->q_rx_lev_min;
  if (sib3->s_intra_search_present) {
    cell_resel_cfg.s_intrasearchP  = sib3->s_intra_search;
  } else {
    cell_resel_cfg.s_intrasearchP  = INFINITY;
  }

}

void rrc::handle_sib13()
{
  rrc_log->info("SIB13 received\n");
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
    if(0 == lcid && !serving_cell->has_mcch) {
      srslte_bit_unpack_vector(pdu->msg, bit_buf.msg, pdu->N_bytes * 8);
      bit_buf.N_bits = pdu->N_bytes * 8;
      liblte_rrc_unpack_mcch_msg((LIBLTE_BIT_MSG_STRUCT *) &bit_buf, &serving_cell->mcch);
      serving_cell->has_mcch = true;
      // phy->set_config_mbsfn_mcch(&serving_cell->mcch); TODO
    }

    pool->deallocate(pdu);
  }
}

/*******************************************************************************
*
*
*
* Packet processing
*
*
*******************************************************************************/
byte_buffer_t* rrc::byte_align_and_pack()
{
  // Byte align and pack the message bits for PDCP
  if ((bit_buf.N_bits % 8) != 0) {
    for (uint32_t i = 0; i < 8 - (bit_buf.N_bits % 8); i++)
      bit_buf.msg[bit_buf.N_bits + i] = 0;
    bit_buf.N_bits += 8 - (bit_buf.N_bits % 8);
  }

  // Reset and reuse sdu buffer if provided
  byte_buffer_t *pdcp_buf = pool_allocate;
  if (pdcp_buf) {
    srslte_bit_pack_vector(bit_buf.msg, pdcp_buf->msg, bit_buf.N_bits);
    pdcp_buf->N_bytes = bit_buf.N_bits / 8;
    pdcp_buf->set_timestamp();
  } else {
    rrc_log->error("Fatal Error: Couldn't allocate PDU in byte_align_and_pack().\n");
  }
  return pdcp_buf;
}

void rrc::send_ul_ccch_msg()
{
  liblte_rrc_pack_ul_ccch_msg(&ul_ccch_msg, (LIBLTE_BIT_MSG_STRUCT *) &bit_buf);
  byte_buffer_t *pdu = byte_align_and_pack();
  if (pdu) {
    // Set UE contention resolution ID in MAC
    uint64_t uecri = 0;
    uint8_t *ue_cri_ptr = (uint8_t *) &uecri;
    uint32_t nbytes = 6;
    for (uint32_t i = 0; i < nbytes; i++) {
      ue_cri_ptr[nbytes - i - 1] = pdu->msg[i];
    }

    rrc_log->debug("Setting UE contention resolution ID: %" PRIu64 "\n", uecri);
    // mac->set_contention_id(uecri);

    rrc_log->info("Sending %s\n", liblte_rrc_ul_ccch_msg_type_text[ul_ccch_msg.msg_type]);
    // pdcp->write_sdu(RB_ID_SRB0, pdu); change to socket TODO
    rrc_pdu p = {0x01, ue_addr, RB_ID_SRB0, rnti, pdu};
    pdu_queue.push(p);
  }
}

void rrc::send_ul_dcch_msg()
{
  liblte_rrc_pack_ul_dcch_msg(&ul_dcch_msg, (LIBLTE_BIT_MSG_STRUCT *) &bit_buf);
  byte_buffer_t *pdu = byte_align_and_pack();
  if (pdu) {
    rrc_log->info("Sending %s\n", liblte_rrc_ul_dcch_msg_type_text[ul_dcch_msg.msg_type]);
    // pdcp->write_sdu(RB_ID_SRB1, pdu); change to socket TODO
    rrc_pdu p = {0x01, ue_addr, RB_ID_SRB1, rnti, pdu};
    pdu_queue.push(p);
  }
}

uint32_t rrc::get_sdu(uint8_t *p) {
    rrc_pdu pdu = pdu_queue.wait_pop();
    memcpy(p, &pdu, sizeof(pdu));
    return sizeof(pdu);
}

void rrc::write_sdu(uint32_t lcid, byte_buffer_t *sdu) {

  if (state == RRC_STATE_IDLE) {
    rrc_log->warning("Received ULInformationTransfer SDU when in IDLE\n");
    return;
  }
  rrc_log->info_hex(sdu->msg, sdu->N_bytes, "TX %s SDU", get_rb_name(lcid).c_str());
  send_ul_info_transfer(sdu);
}

void rrc::write_pdu(uint32_t lcid, byte_buffer_t *pdu) {
  rrc_log->info_hex(pdu->msg, pdu->N_bytes, "RX %s PDU", get_rb_name(lcid).c_str());

  switch (lcid) {
    case RB_ID_SRB0:
      parse_dl_ccch(pdu);
      break;
    case RB_ID_SRB1:
    case RB_ID_SRB2:
      parse_dl_dcch(lcid, pdu);
      break;
    default:
      rrc_log->error("RX PDU with invalid bearer id: %d", lcid);
      break;
  }
}

void rrc::parse_dl_ccch(byte_buffer_t *pdu) {
  srslte_bit_unpack_vector(pdu->msg, bit_buf.msg, pdu->N_bytes * 8);
  bit_buf.N_bits = pdu->N_bytes * 8;
  pool->deallocate(pdu);
  bzero(&dl_ccch_msg, sizeof(LIBLTE_RRC_DL_CCCH_MSG_STRUCT));
  liblte_rrc_unpack_dl_ccch_msg((LIBLTE_BIT_MSG_STRUCT *) &bit_buf, &dl_ccch_msg);

  rrc_log->info("SRB0 - Received %s\n",
                liblte_rrc_dl_ccch_msg_type_text[dl_ccch_msg.msg_type]);

  switch (dl_ccch_msg.msg_type) {
    case LIBLTE_RRC_DL_CCCH_MSG_TYPE_RRC_CON_REJ:
      // 5.3.3.8
      rrc_log->info("Received ConnectionReject. Wait time: %d\n",
                    dl_ccch_msg.msg.rrc_con_rej.wait_time);
      rrc_log->console("Received ConnectionReject. Wait time: %d\n",
                    dl_ccch_msg.msg.rrc_con_rej.wait_time);

      // timers.get(t300)->stop();

      if (dl_ccch_msg.msg.rrc_con_rej.wait_time) {
        nas->set_barring(nas_interface_rrc::BARRING_ALL);
//        timers.get(t302)->set(this, dl_ccch_msg.msg.rrc_con_rej.wait_time*1000);
//        timers.get(t302)->run();
      } else {
        // Perform the actions upon expiry of T302 if wait time is zero
        nas->set_barring(nas_interface_rrc::BARRING_NONE);
        go_idle = true;
      }
      break;
    case LIBLTE_RRC_DL_CCCH_MSG_TYPE_RRC_CON_SETUP:
      rrc_log->info("ConnectionSetup received\n");
      transaction_id = dl_ccch_msg.msg.rrc_con_setup.rrc_transaction_id;
      handle_con_setup(&dl_ccch_msg.msg.rrc_con_setup);
      break;
    case LIBLTE_RRC_DL_CCCH_MSG_TYPE_RRC_CON_REEST:
      rrc_log->info("ConnectionReestablishment received\n");
      rrc_log->console("Reestablishment OK\n");
      transaction_id = dl_ccch_msg.msg.rrc_con_reest.rrc_transaction_id;
      handle_con_reest(&dl_ccch_msg.msg.rrc_con_reest);
      break;
      /* Reception of RRCConnectionReestablishmentReject 5.3.7.8 */
    case LIBLTE_RRC_DL_CCCH_MSG_TYPE_RRC_CON_REEST_REJ:
      rrc_log->info("ConnectionReestablishmentReject received\n");
      rrc_log->console("Reestablishment Reject\n");
      go_idle = true;
      break;
    default:
      break;
  }
}

void rrc::parse_dl_dcch(uint32_t lcid, byte_buffer_t *pdu) {
  srslte_bit_unpack_vector(pdu->msg, bit_buf.msg, pdu->N_bytes * 8);
  bit_buf.N_bits = pdu->N_bytes * 8;
  liblte_rrc_unpack_dl_dcch_msg((LIBLTE_BIT_MSG_STRUCT *) &bit_buf, &dl_dcch_msg);

  rrc_log->info("%s - Received %s\n",
                get_rb_name(lcid).c_str(),
                liblte_rrc_dl_dcch_msg_type_text[dl_dcch_msg.msg_type]);

  pool->deallocate(pdu);

  switch (dl_dcch_msg.msg_type) {
    case LIBLTE_RRC_DL_DCCH_MSG_TYPE_DL_INFO_TRANSFER:
      pdu = pool_allocate;
      if (!pdu) {
        rrc_log->error("Fatal error: out of buffers in pool\n");
        return;
      }
      memcpy(pdu->msg, dl_dcch_msg.msg.dl_info_transfer.dedicated_info.msg,
             dl_dcch_msg.msg.dl_info_transfer.dedicated_info.N_bytes);
      pdu->N_bytes = dl_dcch_msg.msg.dl_info_transfer.dedicated_info.N_bytes;
      nas->write_pdu(lcid, pdu);
      break;
    case LIBLTE_RRC_DL_DCCH_MSG_TYPE_SECURITY_MODE_COMMAND:
      transaction_id = dl_dcch_msg.msg.security_mode_cmd.rrc_transaction_id;

      cipher_algo = (CIPHERING_ALGORITHM_ID_ENUM) dl_dcch_msg.msg.security_mode_cmd.sec_algs.cipher_alg;
      integ_algo = (INTEGRITY_ALGORITHM_ID_ENUM) dl_dcch_msg.msg.security_mode_cmd.sec_algs.int_alg;

      rrc_log->info("Received Security Mode Command eea: %s, eia: %s\n",
                    ciphering_algorithm_id_text[cipher_algo],
                    integrity_algorithm_id_text[integ_algo]);

      // Generate AS security keys
      uint8_t k_asme[32];
      nas->get_k_asme(k_asme, 32);
      usim->generate_as_keys(k_asme, nas->get_ul_count(), k_rrc_enc, k_rrc_int, k_up_enc, k_up_int, cipher_algo, integ_algo);
      rrc_log->info_hex(k_rrc_enc, 32, "RRC encryption key - k_rrc_enc");
      rrc_log->info_hex(k_rrc_int, 32, "RRC integrity key  - k_rrc_int");
      rrc_log->info_hex(k_up_enc, 32,  "UP encryption key  - k_up_enc");

      security_is_activated = true;

      // Configure PDCP for security
      //pdcp->config_security(lcid, k_rrc_enc, k_rrc_int, cipher_algo, integ_algo);
      //pdcp->enable_integrity(lcid);
      send_security_mode_complete();
      //pdcp->enable_encryption(lcid);
      break;
    case LIBLTE_RRC_DL_DCCH_MSG_TYPE_RRC_CON_RECONFIG:
      transaction_id = dl_dcch_msg.msg.rrc_con_reconfig.rrc_transaction_id;
      handle_rrc_con_reconfig(lcid, &dl_dcch_msg.msg.rrc_con_reconfig);
      break;
    case LIBLTE_RRC_DL_DCCH_MSG_TYPE_UE_CAPABILITY_ENQUIRY:
      transaction_id = dl_dcch_msg.msg.ue_cap_enquiry.rrc_transaction_id;
      for (uint32_t i = 0; i < dl_dcch_msg.msg.ue_cap_enquiry.N_ue_cap_reqs; i++) {
        if (LIBLTE_RRC_RAT_TYPE_EUTRA == dl_dcch_msg.msg.ue_cap_enquiry.ue_capability_request[i]) {
          send_rrc_ue_cap_info();
          break;
        }
      }
      break;
    case LIBLTE_RRC_DL_DCCH_MSG_TYPE_RRC_CON_RELEASE:
      rrc_connection_release();
      break;
    default:
      break;
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
  bool enable_ul_64 = args.ue_category >= 5 && serving_cell->sib2ptr()->rr_config_common_sib.pusch_cnfg.enable_64_qam;
  rrc_log->info("%s 64QAM PUSCH\n", enable_ul_64 ? "Enabling" : "Disabling");
  //phy->set_config_64qam_en(enable_ul_64);
}

void rrc::send_rrc_ue_cap_info() {
  rrc_log->debug("Preparing UE Capability Info\n");

  ul_dcch_msg.msg_type = LIBLTE_RRC_UL_DCCH_MSG_TYPE_UE_CAPABILITY_INFO;
  ul_dcch_msg.msg.ue_capability_info.rrc_transaction_id = transaction_id;

  LIBLTE_RRC_UE_CAPABILITY_INFORMATION_STRUCT *info = &ul_dcch_msg.msg.ue_capability_info;
  info->N_ue_caps = 1;
  info->ue_capability_rat[0].rat_type = LIBLTE_RRC_RAT_TYPE_EUTRA;

  LIBLTE_RRC_UE_EUTRA_CAPABILITY_STRUCT *cap = &info->ue_capability_rat[0].eutra_capability;
  cap->access_stratum_release = LIBLTE_RRC_ACCESS_STRATUM_RELEASE_REL8;
  cap->ue_category = args.ue_category;

  cap->pdcp_params.max_rohc_ctxts_present = false;
  cap->pdcp_params.supported_rohc_profiles[0] = false;
  cap->pdcp_params.supported_rohc_profiles[1] = false;
  cap->pdcp_params.supported_rohc_profiles[2] = false;
  cap->pdcp_params.supported_rohc_profiles[3] = false;
  cap->pdcp_params.supported_rohc_profiles[4] = false;
  cap->pdcp_params.supported_rohc_profiles[5] = false;
  cap->pdcp_params.supported_rohc_profiles[6] = false;
  cap->pdcp_params.supported_rohc_profiles[7] = false;
  cap->pdcp_params.supported_rohc_profiles[8] = false;

  cap->phy_params.specific_ref_sigs_supported = false;
  cap->phy_params.tx_antenna_selection_supported = false;

  cap->rf_params.N_supported_band_eutras = args.nof_supported_bands;
  cap->meas_params.N_band_list_eutra     = args.nof_supported_bands;
  for (uint32_t i=0;i<args.nof_supported_bands;i++) {
    cap->rf_params.supported_band_eutra[i].band_eutra = args.supported_bands[i];
    cap->rf_params.supported_band_eutra[i].half_duplex = false;
    cap->meas_params.band_list_eutra[i].N_inter_freq_need_for_gaps = 1;
    cap->meas_params.band_list_eutra[i].inter_freq_need_for_gaps[0] = true;
  }

  cap->feature_group_indicator_present = true;
  cap->feature_group_indicator = args.feature_group;
  cap->inter_rat_params.utra_fdd_present = false;
  cap->inter_rat_params.utra_tdd128_present = false;
  cap->inter_rat_params.utra_tdd384_present = false;
  cap->inter_rat_params.utra_tdd768_present = false;
  cap->inter_rat_params.geran_present = false;
  cap->inter_rat_params.cdma2000_hrpd_present = false;
  cap->inter_rat_params.cdma2000_1xrtt_present = false;

  send_ul_dcch_msg();
}

void rrc::handle_con_setup(LIBLTE_RRC_CONNECTION_SETUP_STRUCT *setup) {
  // Apply the Radio Resource configuration
  //apply_rr_config_dedicated(&setup->rr_cnfg);

  // Must enter CONNECT before stopping T300
  state = RRC_STATE_CONNECTED;

  rrc_log->console("RRC Connected\n");
  nas->set_barring(nas_interface_rrc::BARRING_NONE);

  if (dedicatedInfoNAS) {
    send_con_setup_complete(dedicatedInfoNAS);
    dedicatedInfoNAS = NULL; // deallocated Inside!
  } else {
    rrc_log->error("Pending to transmit a ConnectionSetupComplete but no dedicatedInfoNAS was in queue\n");
  }
}

/* Reception of RRCConnectionReestablishment by the UE 5.3.7.5 */
void rrc::handle_con_reest(LIBLTE_RRC_CONNECTION_REESTABLISHMENT_STRUCT *setup) {

  // Apply the Radio Resource configuration TODO: should we add srb/drb?
  //apply_rr_config_dedicated(&setup->rr_cnfg);

  // Send ConnectionSetupComplete message
  send_con_restablish_complete();
}


void rrc::add_srb(LIBLTE_RRC_SRB_TO_ADD_MOD_STRUCT *srb_cnfg) {
  srbs[srb_cnfg->srb_id] = *srb_cnfg;
  rrc_log->info("Added radio bearer %s\n", get_rb_name(srb_cnfg->srb_id).c_str());
}

void rrc::add_drb(LIBLTE_RRC_DRB_TO_ADD_MOD_STRUCT *drb_cnfg) {

  if (!drb_cnfg->pdcp_cnfg_present ||
      !drb_cnfg->rlc_cnfg_present ||
      !drb_cnfg->lc_cnfg_present) {
    rrc_log->error("Cannot add DRB - incomplete configuration\n");
    return;
  }
  uint32_t lcid = 0;
  if (drb_cnfg->lc_id_present) {
    lcid = drb_cnfg->lc_id;
  } else {
    lcid = RB_ID_SRB2 + drb_cnfg->drb_id;
    rrc_log->warning("LCID not present, using %d\n", lcid);
  }

  /*TODO: how about pdcp
  // Setup PDCP
  srslte_pdcp_config_t pdcp_cfg;
  pdcp_cfg.is_data = true;
  if (drb_cnfg->pdcp_cnfg.rlc_um_pdcp_sn_size_present) {
    if (LIBLTE_RRC_PDCP_SN_SIZE_7_BITS == drb_cnfg->pdcp_cnfg.rlc_um_pdcp_sn_size) {
      pdcp_cfg.sn_len = 7;
    }
  }
  pdcp->add_bearer(lcid, pdcp_cfg);
  pdcp->config_security(lcid, k_up_enc, k_up_int, cipher_algo, integ_algo);
  pdcp->enable_encryption(lcid);
*/

  drbs[lcid] = *drb_cnfg;
  drb_up     = true;
  rrc_log->info("Added radio bearer %s\n", get_rb_name(lcid).c_str());
}

void rrc::release_drb(uint8_t lcid) {
  // TODO
}

void rrc::add_mrb(uint32_t lcid, uint32_t port)
{
  gw->add_mch_port(lcid, port);
  //rlc->add_bearer_mrb(lcid);
  //mac->mch_start_rx(lcid);
  rrc_log->info("Added MRB bearer for lcid:%d\n", lcid);
}


const std::string rrc::rb_id_str[] = {"SRB0", "SRB1", "SRB2",
                                      "DRB1", "DRB2", "DRB3",
                                      "DRB4", "DRB5", "DRB6",
                                      "DRB7", "DRB8"};

} // namespace srsue
