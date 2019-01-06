/**
 *
 * \section COPYRIGHT
 *
 * Copyright 2013-2017 Software Radio Systems Limited
 *
 * \section LICENSE
 *
 * This file is part of srsLTE.
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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>

#include "srslte/common/config_file.h"

#include <iostream>
#include <string>
#include <boost/program_options.hpp>
#include <boost/program_options/parsers.hpp>
#include <srsenb/hdr/enb.h>

#include "srsenb/hdr/upper/rrc.h"
#include "srsenb/hdr/enb.h"

using namespace std;
using namespace srsenb;
namespace bpo = boost::program_options;

/**********************************************************************
 *  Program arguments processing
 ***********************************************************************/
string config_file;

void parse_args(all_args_t *args, int argc, char* argv[]) {

  string enb_id;
  string cell_id;
  string tac;
  string mcc;
  string mnc;

  // Command line only options
  bpo::options_description general("General options");
  general.add_options()
      ("help,h", "Produce help message")
      ("version,v", "Print version information and exit")
      ;

  // Command line or config file options
  bpo::options_description common("Configuration options");
  common.add_options()

    ("enb.enb_id",        bpo::value<string>(&enb_id)->default_value("0x0"),                       "eNodeB ID")
    ("enb.name",          bpo::value<string>(&args->enb.s1ap.enb_name)->default_value("srsenb01"), "eNodeB Name")
    ("enb.cell_id",       bpo::value<string>(&cell_id)->default_value("0x0"),                      "Cell ID")
    ("enb.tac",           bpo::value<string>(&tac)->default_value("0x0"),                          "Tracking Area Code")
    ("enb.mcc",           bpo::value<string>(&mcc)->default_value("001"),                          "Mobile Country Code")
    ("enb.mnc",           bpo::value<string>(&mnc)->default_value("01"),                           "Mobile Network Code")
    ("enb.mme_addr",      bpo::value<string>(&args->enb.s1ap.mme_addr)->default_value("127.0.0.1"),"IP address of MME for S1 connnection")
    ("enb.gtp_bind_addr", bpo::value<string>(&args->enb.s1ap.gtp_bind_addr)->default_value("192.168.3.1"), "Local IP address to bind for GTP connection")
    ("enb.s1c_bind_addr", bpo::value<string>(&args->enb.s1ap.s1c_bind_addr)->default_value("192.168.3.1"), "Local IP address to bind for S1AP connection")
    ("enb.rrc_bind_addr", bpo::value<string>(&args->enb.rrc.rrc_bind_addr)->default_value("127.0.0.1"), "IP address for UE to connect")
    ("enb.rrc_bind_port", bpo::value<uint32_t>(&args->enb.rrc.rrc_bind_port)->default_value(10001), "Port for UE to connect")
    ("enb.phy_cell_id",   bpo::value<uint32_t>(&args->enb.pci)->default_value(0),                  "Physical Cell Identity (PCI)")
    ("enb.n_prb",         bpo::value<uint32_t>(&args->enb.n_prb)->default_value(25),               "Number of PRB")
    ("enb.nof_ports",     bpo::value<uint32_t>(&args->enb.nof_ports)->default_value(1),            "Number of ports")
    ("enb.tm",            bpo::value<uint32_t>(&args->enb.transmission_mode)->default_value(1),    "Transmission mode (1-8)")
    ("enb.p_a",           bpo::value<float>(&args->enb.p_a)->default_value(0.0f),                  "Power allocation rho_a (-6, -4.77, -3, -1.77, 0, 1, 2, 3)")

    ("enb_files.sib_config", bpo::value<string>(&args->enb_files.sib_config)->default_value("sib.conf"),      "SIB configuration files")
    ("enb_files.rr_config",  bpo::value<string>(&args->enb_files.rr_config)->default_value("rr.conf"),      "RR configuration files")
    ("enb_files.drb_config", bpo::value<string>(&args->enb_files.drb_config)->default_value("drb.conf"),      "DRB configuration files")

    ("pcap.enable",       bpo::value<bool>(&args->pcap.enable)->default_value(false),           "Enable MAC packet captures for wireshark")
    ("pcap.filename",     bpo::value<string>(&args->pcap.filename)->default_value("ue.pcap"),   "MAC layer capture filename")

    ("gui.enable",        bpo::value<bool>(&args->gui.enable)->default_value(false),            "Enable GUI plots")

    ("log.rrc_level",     bpo::value<string>(&args->log.rrc_level),   "RRC log level")
    ("log.rrc_hex_limit", bpo::value<int>(&args->log.rrc_hex_limit),  "RRC log hex dump limit")
    ("log.gtpu_level",    bpo::value<string>(&args->log.gtpu_level),  "GTPU log level")
    ("log.gtpu_hex_limit",bpo::value<int>(&args->log.gtpu_hex_limit), "GTPU log hex dump limit")
    ("log.s1ap_level",    bpo::value<string>(&args->log.s1ap_level),  "S1AP log level")
    ("log.s1ap_hex_limit",bpo::value<int>(&args->log.s1ap_hex_limit), "S1AP log hex dump limit")

    ("log.all_level",     bpo::value<string>(&args->log.all_level)->default_value("info"),   "ALL log level")
    ("log.all_hex_limit", bpo::value<int>(&args->log.all_hex_limit)->default_value(32),  "ALL log hex dump limit")

    ("log.filename",      bpo::value<string>(&args->log.filename)->default_value("/tmp/ue.log"),"Log filename")
    ("log.file_max_size", bpo::value<int>(&args->log.file_max_size)->default_value(-1), "Maximum file size (in kilobytes). When passed, multiple files are created. Default -1 (single file)")

    /* Expert section */

    ("expert.rrc_inactivity_timer",
        bpo::value<uint32_t>(&args->expert.rrc_inactivity_timer)->default_value(60000),
        "Inactivity timer in ms")

    ("expert.enable_mbsfn",
        bpo::value<bool>(&args->expert.enable_mbsfn)->default_value(false),
        "enables mbms in the enodeb")

    ("expert.print_buffer_state",
        bpo::value<bool>(&args->expert.print_buffer_state)->default_value(false),
       "Prints on the console the buffer state every 10 seconds")
  ;

  // Positional options - config file location
  bpo::options_description position("Positional options");
  position.add_options()
  ("config_file", bpo::value< string >(&config_file), "eNodeB configuration file")
  ;
  bpo::positional_options_description p;
  p.add("config_file", -1);

  // these options are allowed on the command line
  bpo::options_description cmdline_options;
  cmdline_options.add(common).add(position).add(general);

  // parse the command line and store result in vm
  bpo::variables_map vm;
  bpo::store(bpo::command_line_parser(argc, argv).options(cmdline_options).positional(p).run(), vm);
  bpo::notify(vm);

  // help option was given - print usage and exit
  if (vm.count("help")) {
      cout << "Usage: " << argv[0] << " [OPTIONS] config_file" << endl << endl;
      cout << common << endl << general << endl;
      exit(0);
  }

  // print version number and exit
  if (vm.count("version")) {
    cout << "Version " <<
         srslte_get_version_major() << "." <<
         srslte_get_version_minor() << "." <<
         srslte_get_version_patch() << endl;
    exit(0);
  }

  // if no config file given, check users home path
  if (!vm.count("config_file")) {
    if (!config_exists(config_file, "enb.conf")) {
      cout << "Failed to read eNB configuration file " << config_file << " - exiting" << endl;
      exit(1);
    }
  }

  cout << "Reading configuration file " << config_file << "..." << endl;
  ifstream conf(config_file.c_str(), ios::in);
  if(conf.fail()) {
    cout << "Failed to read configuration file " << config_file << " - exiting" << endl;
    exit(1);
  }
  bpo::store(bpo::parse_config_file(conf, common), vm);
  bpo::notify(vm);

  // Convert hex strings
  {
    std::stringstream sstr;
    sstr << std::hex << vm["enb.enb_id"].as<std::string>();
    sstr >> args->enb.s1ap.enb_id;
  }
  {
    std::stringstream sstr;
    sstr << std::hex << vm["enb.cell_id"].as<std::string>();
    uint16_t tmp; // Need intermediate uint16_t as uint8_t is treated as char
    sstr >> tmp;
    args->enb.s1ap.cell_id = tmp;
  }
  {
    std::stringstream sstr;
    sstr << std::hex << vm["enb.tac"].as<std::string>();
    sstr >> args->enb.s1ap.tac;
  }

  // Convert MCC/MNC strings
  if(!srslte::string_to_mcc(mcc, &args->enb.s1ap.mcc)) {
    cout << "Error parsing enb.mcc:" << mcc << " - must be a 3-digit string." << endl;
  }
  if(!srslte::string_to_mnc(mnc, &args->enb.s1ap.mnc)) {
    cout << "Error parsing enb.mnc:" << mnc << " - must be a 2 or 3-digit string." << endl;
  }


  // Apply all_level to any unset layers
  if (vm.count("log.all_level")) {
    if(!vm.count("log.rrc_level")) {
      args->log.rrc_level = args->log.all_level;
    }
    if(!vm.count("log.gtpu_level")) {
      args->log.gtpu_level = args->log.all_level;
    }
    if(!vm.count("log.s1ap_level")) {
      args->log.s1ap_level = args->log.all_level;
    }
  }

  // Apply all_hex_limit to any unset layers
  if (vm.count("log.all_hex_limit")) {
    if(!vm.count("log.rrc_hex_limit")) {
      args->log.rrc_hex_limit = args->log.all_hex_limit;
    }
    if(!vm.count("log.gtpu_hex_limit")) {
      args->log.gtpu_hex_limit = args->log.all_hex_limit;
    }
    if(!vm.count("log.s1ap_hex_limit")) {
      args->log.s1ap_hex_limit = args->log.all_hex_limit;
    }
  }

  // Check remaining eNB config files
  if (!config_exists(args->enb_files.sib_config, "sib.conf")) {
    cout << "Failed to read SIB configuration file " << args->enb_files.sib_config << " - exiting" << endl;
    exit(1);
  }

  if (!config_exists(args->enb_files.rr_config, "rr.conf")) {
    cout << "Failed to read RR configuration file " << args->enb_files.rr_config << " - exiting" << endl;
    exit(1);
  }

  if (!config_exists(args->enb_files.drb_config, "drb.conf")) {
    cout << "Failed to read DRB configuration file " << args->enb_files.drb_config << " - exiting" << endl;
    exit(1);
  }
}

static int  sigcnt = 0;
static bool running    = true;

void sig_int_handler(int signo)
{
  sigcnt++;
  running = false;
  printf("Stopping srsENB... Press Ctrl+C %d more times to force stop\n", 10-sigcnt);
  if (sigcnt >= 10) {
    exit(-1);
  }
}

void* receive_loop(void* arg) {
   rrc* _rrc = (rrc*) arg;
   while(true) {
       pthread_testcancel();
       _rrc->receive_uplink();
   }
}

void* send_loop(void* arg) {
    // TODO parse here
    rrc* _rrc = (rrc*) arg;
    while(true) {
        pthread_testcancel();
        _rrc->send_downlink();
    }
}


int main(int argc, char *argv[])
{
  signal(SIGINT, sig_int_handler);
  signal(SIGTERM, sig_int_handler);
  all_args_t        args;
  enb              *enb = enb::get_instance();

  //srslte_debug_handle_crash(argc, argv);

  cout << "---  Software Radio Systems LTE eNodeB  ---" << endl << endl;

  parse_args(&args, argc, argv);
  if(!enb->init(&args)) {
    exit(1);
  }
  cout << "--- Enb Init --- \n\n";

  pthread_t send_tid;
  pthread_t receive_tid;
  pthread_create(&send_tid, NULL, &send_loop, &(enb->rrc));
  pthread_create(&receive_tid, NULL, &receive_loop, &(enb->rrc));

  bool plot_started         = false;
  bool signals_pregenerated = false;
  if(running) {
    if (!plot_started && args.gui.enable) {
      enb->start_plot();
      plot_started = true;
    }
  }
  int cnt=0;
  while (running) {
    if (args.expert.print_buffer_state) {
      cnt++;
      if (cnt==1000) {
        cnt=0;
        enb->print_pool();
      }
    }
    usleep(10000);
  }
  enb->stop();
  enb->cleanup();
  cout << "---  exiting  ---" << endl;
  exit(0);
}
