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

#include "log.h"

#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_tun.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#define DEVICE_FILE_MAX 255

int tun_init(tun_device_t* dev, const char* dev_name, const char* dev_type, const char* ifcfg_addr, u_int16_t ifcfg_prefix)
{
  if(!dev) 
    return;
 
  tun_conf(dev, dev_name, dev_type, ifcfg_addr, ifcfg_prefix, 1400);
  dev->actual_name_ = NULL;

  char* device_file = NULL;
  char* actual_name_start = NULL;
  int dynamic = 1;
  if(dev_name) {
    asprintf(&device_file, "/dev/%s", dev_name);
    dynamic = 0;
  }
  else if(dev->type_ == TYPE_TUN) {
    asprintf(&device_file, "/dev/tun");
    actual_name_start = "tun";
  }
  else if(dev->type_ == TYPE_TAP) {
    asprintf(&device_file, "/dev/tap");
    actual_name_start = "tap";
  }
  else {
    log_printf(ERR, "unable to recognize type of device (tun or tap)");
    tun_close(dev);
    return -1;
  }
  if(!device_file) {
    log_printf(ERR, "can't open device file: memory error");
    tun_close(dev);
    return -2;
  }

  u_int32_t dev_id=0;
  if(dynamic) {
    for(; dev_id <= DEVICE_FILE_MAX; ++dev_id) {
      char* device_file_tmp = NULL;
      asprintf(&device_file_tmp, "%s%d", device_file, dev_id);

      if(!device_file_tmp) {
        log_printf(ERR, "can't open device file: memory error");
        free(device_file);
        tun_close(dev);
        return -2;
      }
        
      dev->fd_ = open(device_file_tmp, O_RDWR);
      free(device_file_tmp);
      if(dev->fd_ >= 0)
        break;
    }
  }
  else
    dev->fd_ = open(device_file, O_RDWR);
  free(device_file);

  if(dev->fd_ < 0) {
    if(dynamic)
      log_printf(ERR, "can't open device file dynamically: no unused node left");
    else
      log_printf(ERR, "can't open device file (%s): %m", device_file);
    
    tun_close(dev);
    return -1;
  }

  if(dynamic)
    asprintf(&(dev->actual_name_), "%s%d", actual_name_start, dev_id);
  else
    dev->actual_name_ = strdup(dev_name);

  if(!dev->actual_name_) {
    log_printf(ERR, "can't open device file: memory error");
    tun_close(dev);
    return -2;
  }

  int ret = tun_init_post(dev);
  if(ret) 
    return ret;

  if(ifcfg_addr)
    tun_do_ifconfig(dev);

  return 0;
}


#if defined(__GNUC__) && defined(__OpenBSD__)

int tun_init_post(tun_device_t* dev)
{
  if(!dev)
    return -1;

  dev->with_pi_ = 1;
  if(dev->type_ == TYPE_TAP)
    dev->with_pi_ = 0;
  
  struct tuninfo ti;  

  if (ioctl(dev->fd_, TUNGIFINFO, &ti) < 0) {
    log_printf(ERR, "can't enable multicast for interface");
    return -1;
  }  

  ti.flags |= IFF_MULTICAST;
  
  if (ioctl(dev->fd_, TUNSIFINFO, &ti) < 0) {
    log_printf(ERR, "can't enable multicast for interface");
    return -1;
  }
  return 0;
}

#elif defined(__GNUC__) && defined(__FreeBSD__)

int tun_init_post(tun_device_t* dev)
{
  if(!dev)
    return -1;

  dev->with_pi_ = 1;
  if(dev->type_ == TYPE_TAP)
    dev->with_pi_ = 0;

  int arg = 0;
  ioctl(dev->fd_, TUNSLMODE, &arg);
  arg = 1;
  ioctl(dev->fd_, TUNSIFHEAD, &arg);

  return 0;
}

#elif defined(__GNUC__) && defined(__NetBSD__)

int tun_init_post(tun_device_t* dev)
{
  if(!dev)
    return -1;

  dev->with_pi_ = 0;

  int arg = IFF_POINTOPOINT|IFF_MULTICAST;
  ioctl(dev->fd_, TUNSIFMODE, &arg);
  arg = 0;
  ioctl(dev->fd_, TUNSLMODE, &arg);

  return 0;
}

#else
 #error This Device works just for OpenBSD, FreeBSD or NetBSD
#endif



void tun_close(tun_device_t* dev)
{
  if(!dev)
    return;

  if(dev->fd_ > 0)
    close(dev->fd_);

  if(dev->actual_name_)
    free(dev->actual_name_);

  if(dev->net_addr_)
    free(dev->net_addr_);
}

int tun_read(tun_device_t* dev, u_int8_t* buf, u_int32_t len)
{
  if(!dev || dev->fd_ < 0)
    return -1;

  if(dev->with_pi_)
  {
    struct iovec iov[2];
    u_int32_t type;
    
    iov[0].iov_base = &type;
    iov[0].iov_len = sizeof(type);
    iov[1].iov_base = buf;
    iov[1].iov_len = len;
    return(tun_fix_return(readv(dev->fd_, iov, 2), sizeof(type)));
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
    u_int32_t type;
    struct ip *hdr = (struct ip*)buf;
    
    type = 0;
    if(hdr->ip_v == 4)
      type = htonl(AF_INET);
    else
      type = htonl(AF_INET6);
    
    iov[0].iov_base = &type;
    iov[0].iov_len = sizeof(type);
    iov[1].iov_base = buf;
    iov[1].iov_len = len;
    return(tun_fix_return(writev(dev->fd_, iov, 2), sizeof(type)));
  }
  else
    return(write(dev->fd_, buf, len));
}

void tun_do_ifconfig(tun_device_t* dev)
{
  if(!dev || !dev->actual_name_ || !dev->net_addr_)
    return;


/*   char* command = NULL; */
/*   char* netmask; */
/*   char* end; */
/*   if(dev->type_ == TYPE_TAP) { */
/*     netmask = "netmask "; */
/* #if defined(__GNUC__) && defined(__OpenBSD__) */
/*     end = " link0"; */
/* #elif defined(__GNUC__) && defined(__FreeBSD__) */
/*     end = " up"; */
/* #elif defined(__GNUC__) && defined(__NetBSD__) */
/*     end = ""; */
/* #else */
/*  #error This Device works just for OpenBSD, FreeBSD or NetBSD */
/* #endif */
/*   } */
/*   else { */
/*     netmask = ""; */
/*     end = " netmask 255.255.255.255 up"; */
/*   } */

/*   asprintf(&command, "/sbin/ifconfig %s %s %s%s mtu %d%s", dev->actual_name_, dev->local_ , netmask,  */
/*                                                            dev->remote_netmask_, dev->mtu_, end); */
/*   if(!command) { */
/*     log_printf(ERR, "Execution of ifconfig failed"); */
/*     return; */
/*   } */

/*   int result = system(command); */
/*   if(result == -1) */
/*     log_printf(ERR, "Execution of ifconfig failed"); */
/*   else */
/*     log_printf(NOTICE, "ifconfig returned %d", WEXITSTATUS(result)); */

/*   free(command); */
}
