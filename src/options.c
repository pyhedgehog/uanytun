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

#include "log.h"

#define PARSE_BOOL_PARAM(SHORT, LONG, VALUE)             \
    else if(!strcmp(str,SHORT) || !strcmp(str,LONG))     \
      VALUE = 1;

#define PARSE_INVERSE_BOOL_PARAM(SHORT, LONG, VALUE)     \
    else if(!strcmp(str,SHORT) || !strcmp(str,LONG))     \
      VALUE = 0;

#define PARSE_INT_PARAM(SHORT, LONG, VALUE)              \
    else if(!strcmp(str,SHORT) || !strcmp(str,LONG))     \
    {                                                    \
      if(argc < 1)                                       \
        return i;                                        \
      VALUE = atoi(argv[i+1]);                           \
      argc--;                                            \
      i++;                                               \
    }

#define PARSE_STRING_PARAM(SHORT, LONG, VALUE)           \
    else if(!strcmp(str,SHORT) || !strcmp(str,LONG))     \
    {                                                    \
      if(argc < 1 || argv[i+1][0] == '-')                \
        return i;                                        \
      if(VALUE) free(VALUE);                             \
      VALUE = strdup(argv[i+1]);                         \
      if(!VALUE)                                         \
        return -2;                                       \
      argc--;                                            \
      i++;                                               \
    }

#define PARSE_STRING_PARAM_SEC(SHORT, LONG, VALUE)       \
    else if(!strcmp(str,SHORT) || !strcmp(str,LONG))     \
    {                                                    \
      if(argc < 1 || argv[i+1][0] == '-')                \
        return i;                                        \
      if(VALUE) free(VALUE);                             \
      VALUE = strdup(argv[i+1]);                         \
      if(!VALUE)                                         \
        return -2;                                       \
      size_t j;                                          \
      for(j=0; j < strlen(argv[i+1]); ++j)               \
        argv[i+1][j] = '#';                              \
      argc--;                                            \
      i++;                                               \
    }

#define PARSE_STRING_PARAM2(SHORT, LONG, VALUE1, VALUE2) \
    else if(!strcmp(str,SHORT) || !strcmp(str,LONG))     \
    {                                                    \
      if(argc < 2 ||                                     \
         argv[i+1][0] == '-' || argv[i+2][0] == '-')     \
        return i;                                        \
      if(VALUE1) free(VALUE1);                           \
      VALUE1 = strdup(argv[i+1]);                        \
      if(!VALUE1)                                        \
        return -2;                                       \
      if(VALUE2) free(VALUE2);                           \
      VALUE2 = strdup(argv[i+2]);                        \
      if(!VALUE2)                                        \
        return -2;                                       \
      argc-=2;                                           \
      i+=2;                                              \
    }

#define PARSE_HEXSTRING_PARAM_SEC(SHORT, LONG, VALUE)    \
    else if(!strcmp(str,SHORT) || !strcmp(str,LONG))     \
    {                                                    \
      if(argc < 1 || argv[i+1][0] == '-')                \
        return i;                                        \
      if(VALUE.buf_) free(VALUE.buf_);                   \
      int ret;                                           \
      ret = options_parse_hex_string(argv[i+1], &VALUE); \
      if(ret > 0)                                        \
        return i+1;                                      \
      else if(ret < 0)                                   \
        return ret;                                      \
      size_t j;                                          \
      for(j=0; j < strlen(argv[i+1]); ++j)               \
        argv[i+1][j] = '#';                              \
      argc--;                                            \
      i++;                                               \
    }

int options_parse_hex_string(const char* hex, buffer_t* buffer)
{
  if(!hex || !buffer)
    return -1;

  u_int32_t hex_len = strlen(hex);
  if(hex_len%2)
    return 1;

  if(buffer->buf_) 
    free(buffer->buf_);
  
  buffer->length_ = hex_len/2;
  buffer->buf_ = malloc(buffer->length_);
  if(!buffer->buf_) {
    buffer->length_ = 0;
    return -2;
  }

  const char* ptr = hex;
  int i;
  for(i=0;i<buffer->length_;++i) {
    u_int32_t tmp;
    sscanf(ptr, "%2X", &tmp);
    buffer->buf_[i] = (u_int8_t)tmp;
    ptr += 2;
  }

  return 0;
}

int options_parse(options_t* opt, int argc, char* argv[])
{
  if(!opt)
    return -1;

  options_default(opt);

  if(opt->progname_)
    free(opt->progname_);
  opt->progname_ = strdup(argv[0]);
  if(!opt->progname_)
    return -2;

  argc--;

  int i;
  for(i=1; argc > 0; ++i)
  {
    char* str = argv[i];
    argc--;

    if(!strcmp(str,"-h") || !strcmp(str,"--help"))
      return -1;
    PARSE_INVERSE_BOOL_PARAM("-D","--nodaemonize", opt->daemonize_)
    PARSE_BOOL_PARAM("-C","--chroot", opt->chroot_)
    PARSE_STRING_PARAM("-u","--username", opt->username_)
    PARSE_STRING_PARAM("-H","--chroot-dir", opt->chroot_dir_)
    PARSE_STRING_PARAM("-P","--write-pid", opt->pid_file_)
    PARSE_STRING_PARAM("-i","--interface", opt->local_addr_)
    PARSE_STRING_PARAM("-p","--port", opt->local_port_)
    PARSE_STRING_PARAM("-r","--remote-host", opt->remote_addr_)
    PARSE_STRING_PARAM("-o","--remote-port", opt->remote_port_)
    PARSE_STRING_PARAM("-d","--dev", opt->dev_name_)
    PARSE_STRING_PARAM("-t","--type", opt->dev_type_)
    PARSE_STRING_PARAM2("-n","--ifconfig", opt->ifconfig_param_local_, opt->ifconfig_param_remote_netmask_)
    PARSE_STRING_PARAM("-x","--post-up-script", opt->post_up_script_)
    PARSE_INT_PARAM("-s","--sender-id", opt->sender_id_)
    PARSE_INT_PARAM("-m","--mux", opt->mux_)
    PARSE_INT_PARAM("-w","--window-size", opt->seq_window_size_)
#ifndef NO_CRYPT
    PARSE_STRING_PARAM("-c","--cipher", opt->cipher_)
    PARSE_STRING_PARAM("-k","--kd-prf", opt->kd_prf_)
    PARSE_INT_PARAM("-l","--ld-kdr", opt->ld_kdr_)
    PARSE_STRING_PARAM("-a","--auth-algo", opt->auth_algo_)
    PARSE_STRING_PARAM_SEC("-E","--passphrase", opt->passphrase_)
    PARSE_HEXSTRING_PARAM_SEC("-K","--key", opt->key_)
    PARSE_HEXSTRING_PARAM_SEC("-A","--salt", opt->salt_)
#endif
    else 
      return i;
  }

#ifndef NO_CRYPT
  if((strcmp(opt->cipher_, "null") || strcmp(opt->auth_algo_, "null")) && 
     !strcmp(opt->kd_prf_, "null")) {
    log_printf(WARNING, "using NULL key derivation with encryption and or authentication enabled!");
  }
#endif

  if(!(opt->dev_name_) && !(opt->dev_type_))
    opt->dev_type_ = strdup("tun");

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
  opt->seq_window_size_ = 0;
#ifndef NO_CRYPT
  opt->cipher_ = strdup("aes-ctr");
  opt->kd_prf_ = strdup("aes-ctr");
  opt->ld_kdr_ = 0;
  opt->auth_algo_ = strdup("sha1");
  opt->passphrase_ = NULL;
#else
  opt->cipher_ = strdup("null");
#endif
  opt->mux_ = 0;
  opt->key_.buf_ = NULL;
  opt->key_.length_ = 0;
  opt->salt_.buf_ = NULL;
  opt->salt_.length_ = 0;
}

void options_clear(options_t* opt)
{
  if(!opt)
    return;

  if(opt->progname_)
    free(opt->progname_);
  if(opt->username_)
    free(opt->username_);
  if(opt->chroot_dir_)
    free(opt->chroot_dir_);
  if(opt->pid_file_)
    free(opt->pid_file_);
  if(opt->local_addr_)
    free(opt->local_addr_);
  if(opt->local_port_)
    free(opt->local_port_);
  if(opt->remote_addr_)
    free(opt->remote_addr_);
  if(opt->remote_port_)
    free(opt->remote_port_);
  if(opt->dev_name_)
    free(opt->dev_name_);
  if(opt->dev_type_)
    free(opt->dev_type_);
  if(opt->ifconfig_param_local_)
    free(opt->ifconfig_param_local_);
  if(opt->ifconfig_param_remote_netmask_)
    free(opt->ifconfig_param_remote_netmask_);
  if(opt->post_up_script_)
    free(opt->post_up_script_);
  if(opt->cipher_)
    free(opt->cipher_);
#ifndef NO_CRYPT
  if(opt->kd_prf_)
    free(opt->kd_prf_);
  if(opt->auth_algo_)
    free(opt->auth_algo_);
  if(opt->passphrase_)
    free(opt->passphrase_);
#endif
  if(opt->key_.buf_)
    free(opt->key_.buf_);
  if(opt->salt_.buf_)
    free(opt->salt_.buf_);
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
#ifndef NO_CRYPT
  printf("        [-c|--cipher] <cipher type>         payload encryption algorithm\n");
  printf("        [-a|--auth-algo] <algo type>        message authentication algorithm\n");
  printf("        [-k|--kd-prf] <kd-prf type>         key derivation pseudo random function\n");
  printf("        [-l|--ld-kdr] <ld-kdr>              log2 of key derivation rate\n");
  printf("        [-E|--passphrase <pass phrase>      a passprhase to generate master key and salt from\n");
  printf("        [-K|--key] <master key>             master key to use for encryption\n");
  printf("        [-A|--salt] <master salt>           master salt to use for encryption\n");
#endif
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
#ifndef NO_CRYPT
  printf("auth_algo: '%s'\n", opt->auth_algo_);
  printf("kd_prf: '%s'\n", opt->kd_prf_);
  printf("ld_kdr: %d\n", opt->ld_kdr_);
  printf("passphrase: '%s'\n", opt->passphrase_);
#endif

  u_int32_t i;
  printf("key_[%d]: '", opt->key_.length_);
  for(i=0; i<opt->key_.length_; ++i) printf("%02X", opt->key_.buf_[i]);
  printf("'\n");

  printf("salt_[%d]: '", opt->salt_.length_);
  for(i=0; i<opt->salt_.length_; ++i) printf("%02X", opt->salt_.buf_[i]);
  printf("'\n");
}
