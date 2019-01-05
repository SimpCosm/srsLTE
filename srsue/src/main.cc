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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>

#include <iostream>
#include <fstream>
#include <string>
#include <boost/program_options.hpp>
#include <boost/program_options/parsers.hpp>

#include "srsue/hdr/ue.h"
#include "srslte/common/config_file.h"
#include "srslte/srslte.h"
#include "srslte/version.h"

using namespace std;
using namespace srsue;
namespace bpo = boost::program_options;

/**********************************************************************
 *  Program arguments processing
 ***********************************************************************/
string config_file;

void parse_args(all_args_t *args, int argc, char *argv[]) {

  // Command line only options
  bpo::options_description general("General options");

  general.add_options()
    ("help,h", "Produce help message")
    ("version,v", "Print version information and exit");

  // Command line or config file options
  bpo::options_description common("Configuration options");
  common.add_options()
    ("rrc.feature_group", bpo::value<uint32_t>(&args->rrc.feature_group)->default_value(0xe6041000), "Hex value of the featureGroupIndicators field in the"
                                                                                           "UECapabilityInformation message. Default 0xe6041000")
    ("rrc.ue_category",     bpo::value<string>(&args->ue_category_str)->default_value("4"),  "UE Category (1 to 5)")
    ("rrc.enb_addr",        bpo::value<string>(&args->rrc.enb_addr)->default_value("127.0.1.1"),  "IP address of eNB for rrc connection")
    ("rrc.enb_port",        bpo::value<uint32_t>(&args->rrc.enb_port)->default_value(8000),  "Port of eNB for rrc connection")
    ("rrc.ue_bind_addr",    bpo::value<string>(&args->rrc.ue_bind_addr)->default_value("127.0.0.1"),  "Local IP address for eNB to connect")
    ("rrc.ue_bind_port",    bpo::value<uint32_t>(&args->rrc.ue_bind_port)->default_value(6259),  "Local Port for eNB to connect")
    ("rrc.ue_gate_addr",    bpo::value<string>(&args->rrc.ue_gate_addr)->default_value("127.0.0.1"),  "Local IP address for eNB to connect")
    ("rrc.ue_gate_port",    bpo::value<uint32_t>(&args->rrc.ue_gate_port)->default_value(5060),  "Local Port for eNB to connect")

    ("nas.apn",               bpo::value<string>(&args->nas.apn_name)->default_value(""),  "Set Access Point Name (APN) for data services")
    ("nas.user",              bpo::value<string>(&args->nas.apn_user)->default_value(""),  "Username for CHAP authentication")
    ("nas.pass",              bpo::value<string>(&args->nas.apn_pass)->default_value(""),  "Password for CHAP authentication")
    ("nas.force_imsi_attach", bpo::value<bool>(&args->nas.force_imsi_attach)->default_value(false),  "Whether to always perform an IMSI attach")


    ("pcap.enable", bpo::value<bool>(&args->pcap.enable)->default_value(false), "Enable MAC packet captures for wireshark")
    ("pcap.filename", bpo::value<string>(&args->pcap.filename)->default_value("ue.pcap"), "MAC layer capture filename")
    ("pcap.nas_enable",   bpo::value<bool>(&args->pcap.nas_enable)->default_value(false), "Enable NAS packet captures for wireshark")
    ("pcap.nas_filename", bpo::value<string>(&args->pcap.nas_filename)->default_value("ue_nas.pcap"), "NAS layer capture filename (useful when NAS encryption is enabled)")


    ("gui.enable", bpo::value<bool>(&args->gui.enable)->default_value(false), "Enable GUI plots")

    ("log.rrc_level", bpo::value<string>(&args->log.rrc_level), "RRC log level")
    ("log.rrc_hex_limit", bpo::value<int>(&args->log.rrc_hex_limit), "RRC log hex dump limit")
    ("log.gw_level", bpo::value<string>(&args->log.gw_level), "GW log level")
    ("log.gw_hex_limit", bpo::value<int>(&args->log.gw_hex_limit), "GW log hex dump limit")
    ("log.nas_level", bpo::value<string>(&args->log.nas_level), "NAS log level")
    ("log.nas_hex_limit", bpo::value<int>(&args->log.nas_hex_limit), "NAS log hex dump limit")
    ("log.usim_level", bpo::value<string>(&args->log.usim_level), "USIM log level")
    ("log.usim_hex_limit", bpo::value<int>(&args->log.usim_hex_limit), "USIM log hex dump limit")


    ("log.all_level", bpo::value<string>(&args->log.all_level)->default_value("info"), "ALL log level")
    ("log.all_hex_limit", bpo::value<int>(&args->log.all_hex_limit)->default_value(32), "ALL log hex dump limit")

    ("log.filename", bpo::value<string>(&args->log.filename)->default_value("/tmp/ue.log"), "Log filename")
    ("log.file_max_size", bpo::value<int>(&args->log.file_max_size)->default_value(-1), "Maximum file size (in kilobytes). When passed, multiple files are created. Default -1 (single file)")

    ("usim.mode", bpo::value<string>(&args->usim.mode)->default_value("soft"), "USIM mode (soft or pcsc)")
    ("usim.algo", bpo::value<string>(&args->usim.algo), "USIM authentication algorithm")
    ("usim.op", bpo::value<string>(&args->usim.op), "USIM operator code")
    ("usim.opc", bpo::value<string>(&args->usim.opc), "USIM operator code (ciphered variant)")
    ("usim.imsi", bpo::value<string>(&args->usim.imsi), "USIM IMSI")
    ("usim.imei", bpo::value<string>(&args->usim.imei), "USIM IMEI")
    ("usim.k", bpo::value<string>(&args->usim.k), "USIM K")
    ("usim.pin", bpo::value<string>(&args->usim.pin), "PIN in case real SIM card is used")
    ("usim.reader", bpo::value<string>(&args->usim.reader)->default_value(""), "Force specifiy PCSC reader. Default: Try all available readers.")

    /* Expert section */
    ("expert.ip_netmask",
     bpo::value<string>(&args->expert.ip_netmask)->default_value("255.255.255.0"),
     "Netmask of the tun_srsue device")

     ("expert.mbms_service",
     bpo::value<int>(&args->expert.mbms_service)->default_value(-1),
     "automatically starts an mbms service of the number given")

    ("expert.pregenerate_signals",
     bpo::value<bool>(&args->expert.pregenerate_signals)->default_value(false),
     "Pregenerate uplink signals after attach. Improves CPU performance.")

    ("expert.print_buffer_state",
     bpo::value<bool>(&args->expert.print_buffer_state)->default_value(false),
     "Prints on the console the buffer state every 10 seconds");

  // Positional options - config file location
  bpo::options_description position("Positional options");
  position.add_options()
    ("config_file", bpo::value<string>(&config_file), "UE configuration file");
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

    if (!config_exists(config_file, "ue.conf")) {
      cout << "Failed to read UE configuration file " << config_file << " - exiting" << endl;
      exit(1);
    }
  }

  cout << "Reading configuration file " << config_file << "..." << endl;
  ifstream conf(config_file.c_str(), ios::in);
  if (conf.fail()) {
    cout << "Failed to read configuration file " << config_file << " - exiting" << endl;
    exit(1);
  }

  // parse config file and handle errors gracefully
  try {
    bpo::store(bpo::parse_config_file(conf, common), vm);
    bpo::notify(vm);
  } catch (const boost::program_options::error& e) {
    cerr << e.what() << endl;
    exit(1);
  }

  //Check conflicting OP/OPc options and which is being used
  if (vm.count("usim.op") && !vm["usim.op"].defaulted() &&
      vm.count("usim.opc") && !vm["usim.opc"].defaulted())
  {
    cout << "Conflicting options OP and OPc. Please configure either one or the other." << endl;
    exit(1);
  }
  else {
    args->usim.using_op = vm.count("usim.op");
  }

  // Apply all_level to any unset layers
  if (vm.count("log.all_level")) {
    if (!vm.count("log.rrc_level")) {
      args->log.rrc_level = args->log.all_level;
    }
    if (!vm.count("log.nas_level")) {
      args->log.nas_level = args->log.all_level;
    }
    if (!vm.count("log.gw_level")) {
      args->log.gw_level = args->log.all_level;
    }
    if (!vm.count("log.usim_level")) {
      args->log.usim_level = args->log.all_level;
    }
  }


  // Apply all_hex_limit to any unset layers
  if (vm.count("log.all_hex_limit")) {
    if (!vm.count("log.rrc_hex_limit")) {
      args->log.rrc_hex_limit = args->log.all_hex_limit;
    }
    if (!vm.count("log.nas_hex_limit")) {
      args->log.nas_hex_limit = args->log.all_hex_limit;
    }
    if (!vm.count("log.gw_hex_limit")) {
      args->log.gw_hex_limit = args->log.all_hex_limit;
    }
    if (!vm.count("log.usim_hex_limit")) {
      args->log.usim_hex_limit = args->log.all_hex_limit;
    }
  }
}

static int sigcnt = 0;
static bool running = true;
uint32_t serv, port;

void sig_int_handler(int signo) {
  sigcnt++;
  running = false;
  printf("Stopping srsUE... Press Ctrl+C %d more times to force stop\n", 10-sigcnt);
  if (sigcnt >= 10) {
    exit(-1);
  }
}

void *send_loop(void *arg) {
    srsue::rrc* _rrc = (srsue::rrc*)arg;
    while (true) {
        _rrc->send_uplink();
    }
}

void *recv_loop(void *arg) {
    srsue::rrc* _rrc = (srsue::rrc*)arg;
    while (true) {
        _rrc->recv_downlink();
    }
}

void *input_loop(void *m) {
  string key;
  while (running) {
    getline(cin, key);
    if (cin.eof() || cin.bad()) {
      cout << "Closing stdin thread." << endl;
      break;
    } else {
      if (0 == key.compare("q")) {
        running = false;
      }
    else if (0 == key.compare("mbms")) {

    } else if (key.find("mbms_service_start") != string::npos) {

      char *dup = strdup(key.c_str());
      strtok(dup, " ");
      char *s = strtok(NULL, " ");
      if(NULL == s) {
        cout << "Usage: mbms_service_start <service_id> <port_number>" << endl;
        continue;
      }
      serv = atoi(s);
      char* p = strtok(NULL, " ");
      if(NULL == p) {
        cout << "Usage: mbms_service_start <service_id> <port_number>" << endl;
        continue;
      }
      port = atoi(p);
      free(dup);
    }
   }
  }
  return NULL;
}

int main(int argc, char *argv[])
{
  signal(SIGINT, sig_int_handler);
  signal(SIGTERM, sig_int_handler);
  all_args_t args;

  srslte_debug_handle_crash(argc, argv);

  parse_args(&args, argc, argv);

  srsue_instance_type_t type = LTE;
  ue_base *ue = ue_base::get_instance(type);
  if (!ue) {
    cout << "Error creating UE instance." << endl << endl;
    exit(1);
  }

  cout << "---  Software Radio Systems " << srsue_instance_type_text[type] << " UE  ---" << endl << endl;
  if (!ue->init(&args)) {
    exit(1);
  }
  cout << "UE init done" << endl;

  pthread_t input;
  pthread_t send_tid;
  pthread_t recv_tid;
  pthread_create(&input, NULL, &input_loop, &args);
  pthread_create(&send_tid, NULL, &send_loop, ue->get_rrc());
  pthread_create(&recv_tid, NULL, &recv_loop, ue->get_rrc());
  printf("Attaching UE...\n");
  while (!ue->attach() && running) {
    sleep(1);
  }
  int cnt=0;
  while (running) {
    if (args.expert.print_buffer_state) {
      cnt++;
      if (cnt==10) {
        cnt=0;
        ue->print_pool();
      }
    }
    sleep(1);
  }
  pthread_cancel(input);
  ue->stop();
  ue->cleanup();
  cout << "---  exiting  ---" << endl;
  exit(0);
}
