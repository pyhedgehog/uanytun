/*
 *  �Anytun
 *
 *  �Anytun is a tiny implementation of SATP. Unlike Anytun which is a full
 *  featured implementation �Anytun has no support for multiple connections
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
 *  This file is part of �Anytun.
 *
 *  �Anytun is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 3 as
 *  published by the Free Software Foundation.
 *
 *  �Anytun is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with �Anytun. If not, see <http://www.gnu.org/licenses/>.
 */

#include "datatypes.h"

#include <stdlib.h>
#include <stdio.h>

#include "log.h"
#include "signal.h"
#include "tun.h"
#include "udp.h"

#include "daemon.h"
#include "sysexec.h"

int main(int argc, char* argv[])
{
  log_init("uanytun", DAEMON);
  signal_init();

//  chrootAndDrop("/var/run/", "nobody");
//  daemonize();
//  log_printf(INFO, "running in background now");

  tun_device_t* dev;
  tun_init(&dev, NULL, "tun", "192.168.23.1", "192.168.23.2");
  if(!dev) {
    log_printf(ERR, "error on tun_init");
    exit(-1);
  }

/*   int ret = exec_script("post-up.sh", dev->actual_name_); */
/*   log_printf(NOTICE, "post-up script returned %d", ret); */

  udp_socket_t* sock;
  udp_init(&sock, NULL, "4444");
  if(!sock) {
    log_printf(ERR, "error on udp_init");
    exit(-1);
  }

  udp_set_remote(sock, "anycast.anytun.org", "4444");
  char* remote_string = udp_get_remote_end_string(sock);
  log_printf(INFO, "set remote end to: %s", remote_string);
  free(remote_string);

  log_printf(INFO, "entering main loop");
  u_int8_t buf[1600];
  int len = 0;
  unsigned int cnt = 0;
  while(cnt < 5) {
    len = tun_read(dev, buf, 1600);
    printf("read %d bytes from device\n", len);
//    tun_write(dev, buf, len);
    cnt++;
  }
  tun_close(&dev);
  udp_close(&sock);

  return 0;
}