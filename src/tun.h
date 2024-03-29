/*
 *  uAnytun
 *
 *  uAnytun is a tiny implementation of SATP. Unlike Anytun which is a full
 *  featured implementation uAnytun has no support for multiple connections
 *  or synchronisation. It is a small single threaded implementation intended
 *  to act as a client on small platforms.
 *  The secure anycast tunneling protocol (satp) defines a protocol used
 *  for communication between any combination of unicast and anycast
 *  tunnel endpoints.  It has less protocol overhead than IPSec in Tunnel
 *  mode and allows tunneling of every ETHER TYPE protocol (e.g.
 *  ethernet, ip, arp ...). satp directly includes cryptography and
 *  message authentication based on the methods used by SRTP.  It is
 *  intended to deliver a generic, scaleable and secure solution for
 *  tunneling and relaying of packets of any protocol.
 *
 *
 *  Copyright (C) 2007-2017 Christian Pointner <equinox@anytun.org>
 *
 *  This file is part of uAnytun.
 *
 *  uAnytun is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  any later version.
 *
 *  uAnytun is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with uAnytun. If not, see <http://www.gnu.org/licenses/>.
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL.  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so.  If you
 *  do not wish to do so, delete this exception statement from your
 *  version.  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */

#ifndef UANYTUN_tun_h_INCLUDED
#define UANYTUN_tun_h_INCLUDED

#include <stdlib.h>

enum device_type_enum { TYPE_UNDEF, TYPE_TUN, TYPE_TAP };
typedef enum device_type_enum device_type_t;

struct tun_device_struct {
  int fd_;
  unsigned int with_pi_;
  char* actual_name_;
  device_type_t type_;
  u_int16_t mtu_;
  char* net_addr_;
  char* net_mask_;
  u_int16_t prefix_length_;
};
typedef struct tun_device_struct tun_device_t;

int tun_init(tun_device_t* dev, const char* dev_name, const char* dev_type, const char* ifcfg_addr, u_int16_t ifcfg_prefix);
int tun_init_post(tun_device_t* dev);
void tun_do_ifconfig(tun_device_t* dev);
void tun_close(tun_device_t* dev);

int tun_read(tun_device_t* dev, u_int8_t* buf, u_int32_t len);
int tun_write(tun_device_t* dev, u_int8_t* buf, u_int32_t len);

// in tun_helper.h
void tun_conf(tun_device_t* dev, const char* dev_name, const char* dev_type, const char* ifcfg_addr, u_int16_t ifcfg_prefix, u_int16_t mtu);
int tun_fix_return(int ret, size_t pi_length);
const char* tun_get_type_string(tun_device_t* dev);

#endif
