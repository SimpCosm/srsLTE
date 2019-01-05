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
 * File:        interfaces.h
 * Description: Abstract base class interfaces provided by layers
 *              to other layers.
 *****************************************************************************/

#ifndef SRSLTE_UE_INTERFACES_H
#define SRSLTE_UE_INTERFACES_H

#include <string>

#include "srslte/asn1/liblte_rrc.h"
#include "srslte/common/interfaces_common.h"
#include "srslte/common/common.h"
#include "srslte/common/security.h"
#include "srslte/upper/rlc_interface.h"

namespace srsue {

typedef enum {
  AUTH_OK,
  AUTH_FAILED,
  AUTH_SYNCH_FAILURE
} auth_result_t;

// UE interface
class ue_interface
{
};

// USIM interface for NAS
class usim_interface_nas
{
public:
  virtual std::string get_imsi_str() = 0;
  virtual std::string get_imei_str() = 0;
  virtual bool get_imsi_vec(uint8_t* imsi_, uint32_t n) = 0;
  virtual bool get_imei_vec(uint8_t* imei_, uint32_t n) = 0;
  virtual bool get_home_plmn_id(LIBLTE_RRC_PLMN_IDENTITY_STRUCT *home_plmn_id) = 0;
  virtual auth_result_t generate_authentication_response(uint8_t  *rand,
                                                uint8_t  *autn_enb,
                                                uint16_t  mcc,
                                                uint16_t  mnc,
                                                uint8_t  *res,
                                                int      *res_len,
                                                uint8_t  *k_asme) = 0;
  virtual void generate_nas_keys(uint8_t *k_asme,
                                 uint8_t *k_nas_enc,
                                 uint8_t *k_nas_int,
                                 srslte::CIPHERING_ALGORITHM_ID_ENUM cipher_algo,
                                 srslte::INTEGRITY_ALGORITHM_ID_ENUM integ_algo) = 0;
};

// USIM interface for RRC
class usim_interface_rrc
{
public:
  virtual void generate_as_keys(uint8_t *k_asme,
                                uint32_t count_ul,
                                uint8_t *k_rrc_enc,
                                uint8_t *k_rrc_int,
                                uint8_t *k_up_enc,
                                uint8_t *k_up_int,
                                srslte::CIPHERING_ALGORITHM_ID_ENUM cipher_algo,
                                srslte::INTEGRITY_ALGORITHM_ID_ENUM integ_algo) = 0;
  virtual void generate_as_keys_ho(uint32_t pci,
                                   uint32_t earfcn,
                                   int ncc,
                                   uint8_t *k_rrc_enc,
                                   uint8_t *k_rrc_int,
                                   uint8_t *k_up_enc,
                                   uint8_t *k_up_int,
                                   srslte::CIPHERING_ALGORITHM_ID_ENUM cipher_algo,
                                   srslte::INTEGRITY_ALGORITHM_ID_ENUM integ_algo) = 0;
};

// GW interface for NAS
class gw_interface_nas
{
public:
  virtual srslte::error_t setup_if_addr(uint32_t ip_addr, uint32_t type, char *err_str) = 0;
};

// GW interface for RRC
class gw_interface_rrc
{
public:
  virtual void add_mch_port(uint32_t lcid, uint32_t port) = 0;
};

// GW interface for PDCP
class gw_interface_pdcp
{
public:
  virtual void write_pdu(uint32_t lcid, srslte::byte_buffer_t *pdu) = 0;
  virtual void write_pdu_mch(uint32_t lcid, srslte::byte_buffer_t *pdu) = 0;
};

// NAS interface for RRC
class nas_interface_rrc
{
public:
  typedef enum {
    BARRING_NONE = 0,
    BARRING_MO_DATA,
    BARRING_MO_SIGNALLING,
    BARRING_MT,
    BARRING_ALL
  } barring_t;
  virtual void      set_barring(barring_t barring) = 0;
  virtual void      paging(LIBLTE_RRC_S_TMSI_STRUCT *ue_identiy) = 0;
  virtual bool      is_attached() = 0;
  virtual void      write_pdu(uint32_t lcid, srslte::byte_buffer_t *pdu) = 0;
  virtual uint32_t  get_ul_count() = 0;
  virtual bool      get_k_asme(uint8_t *k_asme_, uint32_t n) = 0;
};

// NAS interface for UE
class nas_interface_ue
{
public:
  virtual bool attach_request() = 0;
  virtual bool deattach_request() = 0;
};

// NAS interface for UE
class nas_interface_gw
{
public:
  virtual bool attach_request() = 0;
};

// RRC interface for MAC
class rrc_interface_mac_common
{
public:
  virtual void ra_problem() = 0;
};

class rrc_interface_mac : public rrc_interface_mac_common
{
public:
  virtual void ho_ra_completed(bool ra_successful) = 0;
  virtual void release_pucch_srs() = 0;
  virtual void run_tti(uint32_t tti) = 0;
};

// RRC interface for PHY
class rrc_interface_phy
{
public:
  virtual void in_sync() = 0;
  virtual void out_of_sync() = 0;
  virtual void new_phy_meas(float rsrp, float rsrq, uint32_t tti, int earfcn = -1, int pci = -1) = 0;
};

// RRC interface for NAS
class rrc_interface_nas
{
public:
  typedef struct {
    LIBLTE_RRC_PLMN_IDENTITY_STRUCT plmn_id;
    uint16_t                        tac;
  } found_plmn_t;

  const static int MAX_FOUND_PLMNS = 16;

  virtual void write_sdu(uint32_t lcid, srslte::byte_buffer_t *sdu) = 0;
  virtual uint16_t get_mcc() = 0;
  virtual uint16_t get_mnc() = 0;
  virtual void enable_capabilities() = 0;
  virtual int plmn_search(found_plmn_t found_plmns[MAX_FOUND_PLMNS]) = 0;
  virtual void plmn_select(LIBLTE_RRC_PLMN_IDENTITY_STRUCT plmn_id) = 0;
  virtual bool connection_request(LIBLTE_RRC_CON_REQ_EST_CAUSE_ENUM cause,
                                  srslte::byte_buffer_t *dedicatedInfoNAS) = 0;
  virtual void set_ue_idenity(LIBLTE_RRC_S_TMSI_STRUCT s_tmsi) = 0;
  virtual bool is_connected() = 0;
  virtual std::string get_rb_name(uint32_t lcid) = 0;
};

// RRC interface for PDCP
class rrc_interface_pdcp
{
public:
  virtual void write_pdu(uint32_t lcid, srslte::byte_buffer_t *pdu) = 0;
  virtual void write_pdu_bcch_bch(srslte::byte_buffer_t *pdu) = 0;
  virtual void write_pdu_bcch_dlsch(srslte::byte_buffer_t *pdu) = 0;
  virtual void write_pdu_pcch(srslte::byte_buffer_t *pdu) = 0;
  virtual void write_pdu_mch(uint32_t lcid, srslte::byte_buffer_t *pdu) = 0;
  virtual std::string get_rb_name(uint32_t lcid) = 0;
};

// RRC interface for RLC
class rrc_interface_rlc
{
public:
  virtual void max_retx_attempted() = 0;
  virtual std::string get_rb_name(uint32_t lcid) = 0;
};

// RRC interface for GW
class rrc_interface_gw
{
public:
  virtual void write_sdu(uint32_t lcid, srslte::byte_buffer_t *sdu) = 0;
//  virtual bool is_drb_enabled(uint32_t lcid) = 0;
};

// PDCP interface for RRC
class pdcp_interface_rrc
{
public:
  virtual void reestablish() = 0;
  virtual void reset() = 0;
  virtual void write_sdu(uint32_t lcid, srslte::byte_buffer_t *sdu) = 0;
  virtual void add_bearer(uint32_t lcid, srslte::srslte_pdcp_config_t cnfg = srslte::srslte_pdcp_config_t()) = 0;
  virtual void config_security(uint32_t lcid,
                               uint8_t *k_enc_,
                               uint8_t *k_int_,
                               srslte::CIPHERING_ALGORITHM_ID_ENUM cipher_algo_,
                               srslte::INTEGRITY_ALGORITHM_ID_ENUM integ_algo_) = 0;
  virtual void config_security_all(uint8_t *k_enc_,
                                   uint8_t *k_int_,
                                   srslte::CIPHERING_ALGORITHM_ID_ENUM cipher_algo_,
                                   srslte::INTEGRITY_ALGORITHM_ID_ENUM integ_algo_) = 0;
  virtual void enable_integrity(uint32_t lcid) = 0;
  virtual void enable_encryption(uint32_t lcid) = 0;
};

} // namespace srsue

#endif // SRSLTE_UE_INTERFACES_H
