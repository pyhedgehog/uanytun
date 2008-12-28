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

#include "options.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int options_parse(options_t** opt, int argc, char* argv[])
{
  if(!opt)
    return -1;

  *opt = malloc(sizeof(options_t));
  options_default(*opt);

  return 0;
}

void options_default(options_t* opt)
{
  if(!opt)
    return;

  opt->progname_ = strdup("uanytun");
  opt->daemonize_ = 1;
  opt->chroot_ = 0;
  opt->username_ = strdup("nobody");
  opt->chroot_dir_ = strdup("/var/run/uanytun");
  opt->pid_file_ = NULL;
  opt->sender_id_ = 0;
  opt->local_addr_ = NULL;
  opt->local_port_ = strdup("4444");
  opt->remote_addr_ = NULL;
  opt->remote_port_ = strdup("4444");
  opt->dev_name_ = NULL;
  opt->dev_type_ = NULL;
  opt->ifconfig_param_local_ = NULL;
  opt->ifconfig_param_remote_netmask_ = NULL;
  opt->post_up_script_ = NULL;
  opt->seq_window_size_ = 100;
  opt->cipher_ = strdup("aes-ctr");
  opt->kd_prf_ = strdup("aes-ctr");
  opt->auth_algo_ = strdup("sha1");
  opt->mux_ = 0;
  opt->key_ = NULL;
  opt->key_length_ = 0;
  opt->salt_ = NULL;
  opt->salt_length_ = 0;
}

void options_clear(options_t** opt)
{
  if(!opt || !(*opt))
    return;

  if((*opt)->progname_)
    free((*opt)->progname_);
  if((*opt)->username_)
    free((*opt)->username_);
  if((*opt)->chroot_dir_)
    free((*opt)->chroot_dir_);
  if((*opt)->pid_file_)
    free((*opt)->pid_file_);
  if((*opt)->local_addr_)
    free((*opt)->local_addr_);
  if((*opt)->local_port_)
    free((*opt)->local_port_);
  if((*opt)->remote_addr_)
    free((*opt)->remote_addr_);
  if((*opt)->remote_port_)
    free((*opt)->remote_port_);
  if((*opt)->dev_name_)
    free((*opt)->dev_name_);
  if((*opt)->dev_type_)
    free((*opt)->dev_type_);
  if((*opt)->ifconfig_param_local_)
    free((*opt)->ifconfig_param_local_);
  if((*opt)->ifconfig_param_remote_netmask_)
    free((*opt)->ifconfig_param_remote_netmask_);
  if((*opt)->post_up_script_)
    free((*opt)->post_up_script_);
  if((*opt)->cipher_)
    free((*opt)->cipher_);
  if((*opt)->kd_prf_)
    free((*opt)->kd_prf_);
  if((*opt)->auth_algo_)
    free((*opt)->auth_algo_);
  if((*opt)->key_)
    free((*opt)->key_);
  if((*opt)->salt_)
    free((*opt)->salt_);

  free(*opt);
  *opt = NULL;
}

void options_print_usage()
{
  printf("USAGE:\n");
  printf("uanytun [-h|--help]                         prints this...\n");
//  printf("       [-f|--config] <file>                the config file\n");
  printf("        [-D|--nodaemonize]                  don't run in background\n");
  printf("        [-C|--chroot]                       chroot and drop privileges\n");
  printf("        [-u|--username] <username>          if chroot change to this user\n");
  printf("        [-H|--chroot-dir] <path>            chroot to this directory\n");
  printf("        [-P|--write-pid] <path>             write pid to this file\n");
  printf("        [-i|--interface] <ip-address>       local ip address to bind to\n");
  printf("        [-p|--port] <port>                  local port to bind to\n");
  printf("        [-r|--remote-host] <hostname|ip>    remote host\n");
  printf("        [-o|--remote-port] <port>           remote port\n");
  printf("        [-d|--dev] <name>                   device name\n");
  printf("        [-t|--type] <tun|tap>               device type\n");
  printf("        [-n|--ifconfig] <local>             the local address for the tun/tap device\n");
  printf("                        <remote|netmask>    the remote address(tun) or netmask(tap)\n");
  printf("        [-x|--post-up-script] <script>      script gets called after interface is created\n");
  printf("        [-s|--sender-id ] <sender id>       the sender id to use\n");
  printf("        [-w|--window-size] <window size>    seqence number window size\n");
  printf("        [-m|--mux] <mux-id>                 the multiplex id to use\n");
  printf("        [-c|--cipher] <cipher type>         payload encryption algorithm\n");
  printf("        [-a|--auth-algo] <algo type>        message authentication algorithm\n");
//  printf("        [-k|--kd-prf] <kd-prf type>         key derivation pseudo random function\n");
//  printf("        [-K|--key] <master key>             master key to use for encryption\n");
//  printf("        [-A|--salt] <master salt>           master salt to use for encryption\n");
}

void options_print(options_t* opt)
{
  printf("progname: '%s'\n", opt->progname_);
  printf("daemonize: %d\n", opt->daemonize_);
  printf("chroot: %d\n", opt->chroot_);
  printf("username: '%s'\n", opt->username_);
  printf("chroot_dir: '%s'\n", opt->chroot_dir_);
  printf("pid_file: '%s'\n", opt->pid_file_);
  printf("local_addr: '%s'\n", opt->local_addr_);
  printf("local_port: '%s'\n", opt->local_port_);
  printf("remote_addr: '%s'\n", opt->remote_addr_);
  printf("remote_port: '%s'\n", opt->remote_port_);
  printf("dev_name: '%s'\n", opt->dev_name_);
  printf("dev_type: '%s'\n", opt->dev_type_);
  printf("ifconfig_local: '%s'\n", opt->ifconfig_param_local_);
  printf("ifconfig_remote_netmask: '%s'\n", opt->ifconfig_param_remote_netmask_);
  printf("post_up_script: '%s'\n", opt->post_up_script_);
  printf("sender_id: %d\n", opt->sender_id_);
  printf("mux: %d\n", opt->mux_);
  printf("seq_window_size: %d\n", opt->seq_window_size_);
  printf("cipher: '%s'\n", opt->cipher_);
  printf("auth_algo: '%s'\n", opt->auth_algo_);
  printf("kd_prf: '%s'\n", opt->kd_prf_);

  u_int32_t i;
  printf("key_[%d]: '", opt->key_length_);
  for(i=0; i<opt->key_length_; ++i) printf("%02X", opt->key_[i]);
  printf("'\n");

  printf("salt_[%d]: '", opt->salt_length_);
  for(i=0; i<opt->salt_length_; ++i) printf("%02X", opt->salt_[i]);
  printf("'\n");
}
