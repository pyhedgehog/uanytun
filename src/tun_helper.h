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

#ifndef _TUN_HELPER_H_
#define _TUN_HELPER_H_

#include <string.h>

void tun_conf(tun_device_t* dev, const char* dev_name, const char* dev_type, const char* ifcfg_lp, const char* ifcfg_rnmp, u_int16_t mtu)
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

  dev->local_ = NULL;
  dev->remote_netmask_ = NULL;
  if(ifcfg_lp)
    dev->local_ = strdup(ifcfg_lp);
  if(ifcfg_rnmp)
    dev->remote_netmask_ = strdup(ifcfg_rnmp);
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
