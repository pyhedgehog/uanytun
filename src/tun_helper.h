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
 *  message authentication based on the methodes used by SRTP.  It is
 *  intended to deliver a generic, scaleable and secure solution for
 *  tunneling and relaying of packets of any protocol.
 *
 *
 *  Copyright (C) 2007-2014 Christian Pointner <equinox@anytun.org>
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
 */

#ifndef UANYTUN_tun_helper_h_INCLUDED
#define UANYTUN_tun_helper_h_INCLUDED

#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void tun_conf(tun_device_t* dev, const char* dev_name, const char* dev_type, const char* ifcfg_addr, u_int16_t ifcfg_prefix, u_int16_t mtu)
{
  if(!dev) return;

  dev->mtu_ = mtu;
  dev->type_ = TYPE_UNDEF;
  if(dev_type) {
    if(!strncmp(dev_type, "tun", 3))
      dev->type_ = TYPE_TUN;
    else if (!strncmp(dev_type, "tap", 3))
      dev->type_ = TYPE_TAP;
  }
  else if(dev_name) {
    if(!strncmp(dev_name, "tun", 3))
      dev->type_ = TYPE_TUN;
    else if(!strncmp(dev_name, "tap", 3))
      dev->type_ = TYPE_TAP;
  }

  dev->net_addr_ = NULL;
  dev->net_mask_ = NULL;
  dev->prefix_length_ = 0;
  if(ifcfg_addr) {
    dev->net_addr_ = strdup(ifcfg_addr);
    dev->prefix_length_ = ifcfg_prefix;

    u_int32_t mask = 0;
    u_int16_t i = 0;
    for(i = 0; i < ifcfg_prefix; ++i) {
      mask = mask >> 1;
      mask |= 0x80000000L;
    }
    struct in_addr addr;
    addr.s_addr = ntohl(mask);
    dev->net_mask_ = strdup(inet_ntoa(addr));
  }
}


int tun_fix_return(int ret, size_t pi_length)
{
  if(ret < 0)
    return ret;

  return ((size_t)ret > pi_length ? (ret - pi_length) : 0);
}

const char* tun_get_type_string(tun_device_t* dev)
{
  if(!dev || dev->fd_ < 0)
    return "";

  switch(dev->type_)
  {
  case TYPE_UNDEF: return "undef"; break;
  case TYPE_TUN: return "tun"; break;
  case TYPE_TAP: return "tap"; break;
  }
  return "";
}



#endif
