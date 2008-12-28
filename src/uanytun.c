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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "log.h"
#include "signal.h"
#include "options.h"

#include "tun.h"
#include "udp.h"

#include "plain_packet.h"
#include "encrypted_packet.h"

#include "daemon.h"
#include "sysexec.h"

void main_loop(tun_device_t* dev, udp_socket_t* sock, options_t* opt)
{
  log_printf(INFO, "entering main loop");

  plain_packet_t plain_packet;
  plain_packet_init(&plain_packet);
  encrypted_packet_t encrypted_packet;
  encrypted_packet_init(&encrypted_packet);
  u_int32_t len = 0;
  udp_endpoint_t remote;

  while(1) {
    plain_packet_set_payload_length(&plain_packet, -1);
    encrypted_packet_set_length(&encrypted_packet, -1);

    


/*     len = tun_read(dev, plain_packet_get_payload(&plain_packet), plain_packet_get_payload_length(&plain_packet)); */
/*     plain_packet_set_payload_length(&plain_packet, len); */

/*     udp_write(sock, encrypted_packet_get_packet(&encrypted_packet), encrypted_packet_get_length(&encrypted_packet)); */




/*     len = udp_read(sock, encrypted_packet_get_packet(&encrypted_packet), encrypted_packet_get_length(&encrypted_packet), &remote); */
/*     encrypted_packet_set_length(&encrypted_packet, len); */

/*     if(memcmp(&remote, &(sock->remote_end_), sizeof(remote))) { */
/*       memcpy(&(sock->remote_end_), &remote, sizeof(remote)); */
/*       char* addrstring = udp_endpoint_to_string(remote); */
/*       log_printf(NOTICE, "autodetected remote host changed %s", addrstring); */
/*       free(addrstring); */
/*     } */

/*     tun_write(dev, plain_packet_get_payload(&plain_packet), plain_packet_get_payload_length(&plain_packet)); */
    sleep(1);
  }
}

void print_hex_dump(const u_int8_t* buf, u_int32_t len)
{
  u_int32_t i;

  for(i=0; i < len; i++) {
    printf("%02X ", buf[i]);
    if(!((i+1)%8))
      printf(" ");
    if(!((i+1)%16))
      printf("\n");
  }
  printf("\n");
}


int main(int argc, char* argv[])
{
  log_init("uanytun", DAEMON);
  signal_init();

  options_t* opt;
  int ret = options_parse(&opt, argc, argv);
  if(ret) {
    options_print_usage();
    log_printf(ERR, "error on options_parse, exitting");
    exit(ret);
  }


  tun_device_t* dev;
  tun_init(&dev, opt->dev_name_, opt->dev_type_, opt->ifconfig_param_local_, opt->ifconfig_param_remote_netmask_);
  if(!dev) {
    log_printf(ERR, "error on tun_init, exitting");
    exit(-1);
  }
  log_printf(NOTICE, "dev of type '%s' opened, actual name is '%s'", tun_get_type_string(dev), dev->actual_name_);

  if(opt->post_up_script_) {
    int ret = exec_script(opt->post_up_script_, dev->actual_name_);
    log_printf(NOTICE, "post-up script returned %d", ret);
  }


  udp_socket_t* sock;
  udp_init(&sock, opt->local_addr_, opt->local_port_);
  if(!sock) {
    log_printf(ERR, "error on udp_init, exitting");
    exit(-1);
  }
  char* local_string = udp_get_local_end_string(sock);
  log_printf(NOTICE, "listening on: %s", local_string);
  free(local_string);

  if(opt->remote_addr_) {
    udp_set_remote(sock, opt->remote_addr_, opt->remote_port_);
    char* remote_string = udp_get_remote_end_string(sock);
    log_printf(NOTICE, "set remote end to: %s", remote_string);
    free(remote_string);
  }


  FILE* pid_file = NULL;
  if(opt->pid_file_) {
    pid_file = fopen(opt->pid_file_, "w");
    if(!pid_file) {
      log_printf(WARNING, "unable to open pid file: %m");
    }
  }

  if(opt->chroot_)
    chrootAndDrop("/var/run/", "nobody");
  if(opt->daemonize_) {
    pid_t oldpid = getpid();
    daemonize();
    log_printf(INFO, "running in background now (old pid: %d)", oldpid);
  }

  if(pid_file) {
    pid_t pid = getpid();
    fprintf(pid_file, "%d", pid);
    fclose(pid_file);
  }

  main_loop(dev, sock, opt);

  tun_close(&dev);
  udp_close(&sock);
  options_clear(&opt);

  log_printf(NOTICE, "normal shutdown");

  return 0;
}
