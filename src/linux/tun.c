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

#include "datatypes.h"

#include "tun.h"

#include "tun_helper.h"

#include <stdlib.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>
#define DEFAULT_DEVICE "/dev/net/tun"

#include "log.h"

int tun_init(tun_device_t* dev, const char* dev_name, const char* dev_type, const char* ifcfg_lp, const char* ifcfg_rnmp)
{
  if(!dev) 
    return;
 
  tun_conf(dev, dev_name, dev_type, ifcfg_lp, ifcfg_rnmp, 1400);
  dev->actual_name_ = NULL;

	dev->fd_ = open(DEFAULT_DEVICE, O_RDWR);
	if(dev->fd_ < 0) {
    log_printf(ERR, "can't open device file (%s): %m", DEFAULT_DEVICE);
    tun_close(dev);
    return -1;
  }

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));

  if(dev->type_ == TYPE_TUN) {
    ifr.ifr_flags = IFF_TUN;
    dev->with_pi_ = 1;
  } 
  else if(dev->type_ == TYPE_TAP) {
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    dev->with_pi_ = 0;
  } 
  else {
    log_printf(ERR, "unable to recognize type of device (tun or tap)");
    tun_close(dev);
    return -1;
  }

	if(dev_name)
		strncpy(ifr.ifr_name, dev_name, IFNAMSIZ);

	if(!ioctl(dev->fd_, TUNSETIFF, &ifr)) {
		dev->actual_name_ = strdup(ifr.ifr_name);
	} else if(!ioctl(dev->fd_, (('T' << 8) | 202), &ifr)) {
		dev->actual_name_ = strdup(ifr.ifr_name);
	} else {
    log_printf(ERR, "tun/tap device ioctl failed: %m");
    tun_close(dev);
    return -1;
  }

  if(!dev->actual_name_) {
    log_printf(ERR, "can't open device file: memory error");
    tun_close(dev);
    return -2;
  }

  if(ifcfg_lp && ifcfg_rnmp)
    tun_do_ifconfig(dev);

  return 0;
}

int tun_init_post(tun_device_t* dev)
{
// nothing yet
}

void tun_close(tun_device_t* dev)
{
  if(!dev)
    return;

  if(dev->fd_ > 0)
    close(dev->fd_);

  if(dev->actual_name_)
    free(dev->actual_name_);

  if(dev->local_)
    free(dev->local_);

  if(dev->remote_netmask_)
    free(dev->remote_netmask_);
}

int tun_read(tun_device_t* dev, u_int8_t* buf, u_int32_t len)
{
  if(!dev || dev->fd_ < 0)
    return -1;

  if(dev->with_pi_)
  {
    struct iovec iov[2];
    struct tun_pi tpi;
    
    iov[0].iov_base = &tpi;
    iov[0].iov_len = sizeof(tpi);
    iov[1].iov_base = buf;
    iov[1].iov_len = len;
    return(tun_fix_return(readv(dev->fd_, iov, 2), sizeof(tpi)));
  }
  else
    return(read(dev->fd_, buf, len));
}

int tun_write(tun_device_t* dev, u_int8_t* buf, u_int32_t len)
{
  if(!dev || dev->fd_ < 0)
    return -1;

  if(!buf)
    return 0;

  if(dev->with_pi_)
  {
    struct iovec iov[2];
    struct tun_pi tpi;
    struct iphdr *hdr = (struct iphdr *)buf;
    
    tpi.flags = 0;
    if(hdr->version == 4)
      tpi.proto = htons(ETH_P_IP);
    else
      tpi.proto = htons(ETH_P_IPV6);
    
    iov[0].iov_base = &tpi;
    iov[0].iov_len = sizeof(tpi);
    iov[1].iov_base = buf;
    iov[1].iov_len = len;
    return(tun_fix_return(writev(dev->fd_, iov, 2), sizeof(tpi)));
  }
  else
    return(write(dev->fd_, buf, len));
}

void tun_do_ifconfig(tun_device_t* dev)
{
  if(!dev || !dev->actual_name_ || !dev->local_ || !dev->remote_netmask_)
    return;

  char* command = NULL;
  if(dev->type_ == TYPE_TUN)
    asprintf(&command, "/sbin/ifconfig %s %s pointopoint %s mtu %d", dev->actual_name_, dev->local_, dev->remote_netmask_, dev->mtu_);
  else
    asprintf(&command, "/sbin/ifconfig %s %s netmask %s mtu %d", dev->actual_name_, dev->local_, dev->remote_netmask_, dev->mtu_);

  if(!command) {
    log_printf(ERR, "Execution of ifconfig failed");
    return;
  }

  int result = system(command);
  if(result == -1)
    log_printf(ERR, "Execution of ifconfig failed");
  else
    log_printf(NOTICE, "ifconfig returned %d", WEXITSTATUS(result));

  free(command);
}
