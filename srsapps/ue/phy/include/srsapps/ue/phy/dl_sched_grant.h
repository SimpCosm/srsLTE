/**
 *
 * \section COPYRIGHT
 *
 * Copyright 2013-2015 The srsLTE Developers. See the
 * COPYRIGHT file at the top-level directory of this distribution.
 *
 * \section LICENSE
 *
 * This file is part of the srsLTE library.
 *
 * srsLTE is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * srsLTE is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * A copy of the GNU Affero General Public License can be found in
 * the LICENSE file in the top-level directory of this distribution
 * and at http://www.gnu.org/licenses/.
 *
 */



#include <string.h>

#include "srslte/srslte.h"
#include "srsapps/ue/phy/sched_grant.h"

#ifndef UEDLSCHEDGRANT_H
#define UEDLSCHEDGRANT_H

namespace srslte {
namespace ue {  

  /* Uplink/Downlink scheduling grant generated by a successfully decoded PDCCH */ 
  class dl_sched_grant : public sched_grant {
  public:

             dl_sched_grant(rnti_type_t type, uint16_t rnti) : sched_grant(type, rnti) {} 
             dl_sched_grant(uint16_t rnti) : sched_grant(rnti) {} 
             
    uint32_t get_rv() {
      return dl_dci.rv_idx; 
    }
    void     set_rv(uint32_t rv) {
      dl_dci.rv_idx = rv; 
    }
    bool     get_ndi() {
      return dl_dci.ndi; 
    }
    void     set_ndi(bool value) {
      dl_dci.ndi = value; 
    }
    uint32_t get_harq_process() {
      return dl_dci.harq_process; 
    }
    void     get_dl_grant(srslte_ra_dl_grant_t *ul_grant) {
      memcpy(ul_grant, &grant, sizeof(srslte_ra_dl_grant_t));
    }
    bool     is_sps_release() {
      return false; 
    }
    uint32_t get_tbs() {
      return grant.mcs.tbs;
    }
    uint32_t get_ncce() {
      return ncce; 
    }
    uint32_t get_mcs() {
      return dl_dci.mcs_idx;
    }
    const char* get_dciformat_string() {
      switch(dl_dci.dci_format) {
        case srslte_ra_dl_dci_t::SRSLTE_RA_DCI_FORMAT1: 
          return "Format1";
        case srslte_ra_dl_dci_t::SRSLTE_RA_DCI_FORMAT1A:
          return "Format1A";
        case srslte_ra_dl_dci_t::SRSLTE_RA_DCI_FORMAT1C:
          return "Format1C";
      }
    }
    bool     create_from_dci(srslte_dci_msg_t *msg, uint32_t nof_prb, uint32_t ncce_) {
      ncce = ncce_; 
      if (srslte_dci_msg_to_dl_grant(msg, rnti, nof_prb, &dl_dci, &grant)) {
        return false; 
      } else {
        return true; 
      }
    }
    bool     get_pdsch_cfg(uint32_t sf_idx, uint32_t cfi, srslte_ue_dl_t *ue_dl) {      
      memcpy(&ue_dl->pdsch_cfg.grant, &grant, sizeof(srslte_ra_dl_grant_t));
      
      /* Setup PDSCH configuration for this CFI, SFIDX and RVIDX */
      if (srslte_ue_dl_cfg_grant(ue_dl, NULL, cfi, sf_idx, rnti, get_rv())) {
        return false; 
      }
      return true; 
    }
  private: 
    srslte_ra_dl_grant_t grant;
    srslte_ra_dl_dci_t   dl_dci;
    uint32_t             ncce; 
  };
 
}
}

#endif