/*
 *  µAnytun
 *
 *  µAnytun is a tiny implementation of SATP. Unlike Anytun which is a full
 *  featured implementation µAnytun has no support for multiple connections
 *  or synchronisation. It is a small single threaded implementation intended
 *  to act as a client on small platforms.
 *  The secure anycast tunneling protocol (satp) defines a protocol used
 *  for communication between any combination of unicast and anycast
 *  tunnel endpoints.  It has less protocol overhead than IPSec in Tunnel
 *  mode and allows tunneling of every ETHER TYPE protocol (e.g.
 *  ethernet, ip, arp ...). satp directly includes cryptography and
 *  message authentication based on the methodes used by SRTP.  It is
 *  intended to deliver a generic, scaleable and secure solution for
 *  tunneling and relaying of packets of any protocol.
 *  
 *
 *  Copyright (C) 2007-2008 Christian Pointner <equinox@anytun.org>
 *
 *  This file is part of µAnytun.
 *
 *  µAnytun is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 3 as
 *  published by the Free Software Foundation.
 *
 *  µAnytun is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with µAnytun. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _OPTIONS_H_
#define _OPTIONS_H_

struct buffer_struct {
  u_int32_t length_;
  u_int8_t* buf_;
};
typedef struct buffer_struct buffer_t;

struct options_struct {
  char* progname_;
  int daemonize_;
  int chroot_;
  char* username_;
  char* chroot_dir_;
  char* pid_file_;
  sender_id_t sender_id_;
  char* local_addr_;
  char* local_port_;
  char* remote_addr_;
  char* remote_port_;
  char* dev_name_;
  char* dev_type_;
  char* ifconfig_param_local_;
  char* ifconfig_param_remote_netmask_;
  char* post_up_script_;
  window_size_t seq_window_size_;
  char* cipher_;
  char* kd_prf_;
  char* auth_algo_;
  mux_t mux_;
  buffer_t key_;
  buffer_t salt_;
};
typedef struct options_struct options_t;

buffer_t options_parse_hex_string(const char* hex);

int options_parse(options_t** opt, int argc, char* argv[]);
void options_default(options_t* opt);
void options_clear(options_t** opt);
void options_print_usage();
void options_print(options_t* opt);

#endif

