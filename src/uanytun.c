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
 *  Copyright (C) 2007-2008 Christian Pointner <equinox@anytun.org>
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

#include "datatypes.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "log.h"
#include "sig_handler.h"
#include "options.h"

#include "tun.h"
#include "udp.h"

#include "plain_packet.h"
#include "encrypted_packet.h"

#include "seq_window.h"

#include "cipher.h"
#ifndef NO_CRYPT
#include "key_derivation.h"
#include "auth_algo.h"
#else
typedef u_int8_t auth_algo_t;
#endif
#include "init_crypt.h"

#include "daemon.h"
#include "sysexec.h"


int init_main_loop(options_t* opt, cipher_t* c, auth_algo_t* aa, key_derivation_t* kd, seq_win_t* seq_win)
{
  int ret = cipher_init(c, opt->cipher_);
  if(ret) {
    log_printf(ERROR, "could not initialize cipher of type %s", opt->cipher_);
    return ret;
  }
  
#ifndef NO_CRYPT
  ret = auth_algo_init(aa, opt->auth_algo_);
  if(ret) {
    log_printf(ERROR, "could not initialize auth algo of type %s", opt->auth_algo_);
    cipher_close(c);
    return ret;
  }

  ret = key_derivation_init(kd, opt->kd_prf_, opt->role_, opt->passphrase_, opt->key_.buf_, opt->key_.length_, opt->salt_.buf_, opt->salt_.length_);
  if(ret) {
    log_printf(ERROR, "could not initialize key derivation of type %s", opt->kd_prf_);
    cipher_close(c);
    auth_algo_close(aa);
    return ret;
  }
#endif

  ret = seq_win_init(seq_win, opt->seq_window_size_);
  if(ret) {
    printf("could not initialize sequence window");
    cipher_close(c);
#ifndef NO_CRYPT
    auth_algo_close(aa);
    key_derivation_close(kd);
#endif
    return ret;
  }
  return 0;
}

int process_tun_data(tun_device_t* dev, udp_socket_t* sock, options_t* opt, plain_packet_t* plain_packet, encrypted_packet_t* encrypted_packet,
                     cipher_t* c, auth_algo_t* aa, key_derivation_t* kd, seq_nr_t seq_nr)
{
  plain_packet_set_payload_length(plain_packet, -1);
  encrypted_packet_set_length(encrypted_packet, -1);

  int len = tun_read(dev, plain_packet_get_payload(plain_packet), plain_packet_get_payload_length(plain_packet));
  if(len == -1) {
    log_printf(ERROR, "error on reading from device: %s", strerror(errno));
    return 0;
  }
  
  plain_packet_set_payload_length(plain_packet, len);
  
  if(dev->type_ == TYPE_TUN)
    plain_packet_set_type(plain_packet, PAYLOAD_TYPE_TUN);
  else if(dev->type_ == TYPE_TAP)
    plain_packet_set_type(plain_packet, PAYLOAD_TYPE_TAP);    
  else
    plain_packet_set_type(plain_packet, PAYLOAD_TYPE_UNKNOWN);

  if(!sock->remote_end_set_)
    return 0;
  
  cipher_encrypt(c, kd, kd_outbound, plain_packet, encrypted_packet, seq_nr, opt->sender_id_, opt->mux_); 
  
#ifndef NO_CRYPT
  auth_algo_generate(aa, kd, kd_outbound, encrypted_packet);
#endif
  
  len = udp_write(sock, encrypted_packet_get_packet(encrypted_packet), encrypted_packet_get_length(encrypted_packet));
  if(len == -1)
    log_printf(ERROR, "error on sending udp packet: %s", strerror(errno));

  return 0;
}

int process_sock_data(tun_device_t* dev, udp_socket_t* sock, options_t* opt, plain_packet_t* plain_packet, encrypted_packet_t* encrypted_packet,
                      cipher_t* c, auth_algo_t* aa, key_derivation_t* kd, seq_win_t* seq_win)
{
  plain_packet_set_payload_length(plain_packet, -1);
  encrypted_packet_set_length(encrypted_packet, -1);

  udp_endpoint_t remote;
  memset(&remote, 0, sizeof(udp_endpoint_t));
  int len = udp_read(sock, encrypted_packet_get_packet(encrypted_packet), encrypted_packet_get_length(encrypted_packet), &remote);
  if(len == -1) {
    log_printf(ERROR, "error on receiving udp packet: %s", strerror(errno));
    return 0;
  }
  else if(len < encrypted_packet_get_minimum_length(encrypted_packet)) {
    log_printf(WARNING, "received packet is to short");
    return 0;
  }
  encrypted_packet_set_length(encrypted_packet, len);

#ifndef NO_CRYPT
  if(!auth_algo_check_tag(aa, kd, kd_inbound, encrypted_packet)) {
    log_printf(WARNING, "wrong authentication tag, discarding packet");
    return 0;
  }
#endif
  
  if(encrypted_packet_get_mux(encrypted_packet) != opt->mux_) {
    log_printf(WARNING, "wrong mux value, discarding packet");
    return 0;
  }
  
  int result = seq_win_check_and_add(seq_win, encrypted_packet_get_sender_id(encrypted_packet), encrypted_packet_get_seq_nr(encrypted_packet));
  if(result > 0) {
    log_printf(WARNING, "detected replay attack, discarding packet");
    return 0;
  }
  else if(result < 0) {
    log_printf(ERROR, "memory error at sequence window");
    return -2;
  }
   
  if(memcmp(&remote, &(sock->remote_end_), sizeof(remote))) {
    memcpy(&(sock->remote_end_), &remote, sizeof(remote));
    sock->remote_end_set_ = 1;
    char* addrstring = udp_endpoint_to_string(remote);
    log_printf(NOTICE, "autodetected remote host changed %s", addrstring);
    free(addrstring);
  }

  if(encrypted_packet_get_payload_length(encrypted_packet) <= plain_packet_get_header_length()) {
    log_printf(WARNING, "ignoring packet with zero length payload");
    return 0;
  }

  int ret = cipher_decrypt(c, kd, kd_inbound, encrypted_packet, plain_packet); 
  if(ret) 
    return ret;
 
  len = tun_write(dev, plain_packet_get_payload(plain_packet), plain_packet_get_payload_length(plain_packet));
  if(len == -1)
    log_printf(ERROR, "error on writing to device: %s", strerror(errno));
  
  return 0;
}


int main_loop(tun_device_t* dev, udp_socket_t* sock, options_t* opt)
{
  log_printf(INFO, "entering main loop");

  plain_packet_t plain_packet;
  plain_packet_init(&plain_packet);
  encrypted_packet_t encrypted_packet;
  encrypted_packet_init(&encrypted_packet, opt->auth_tag_length_);
  seq_nr_t seq_nr = 0;
  fd_set readfds, readyfds;

  cipher_t c;
  auth_algo_t aa;
  key_derivation_t kd;
  seq_win_t seq_win;

  int ret = init_main_loop(opt, &c, &aa, &kd, &seq_win);
  if(ret)
    return ret;

  FD_ZERO(&readfds);
  FD_SET(dev->fd_, &readfds);
  FD_SET(sock->fd_, &readfds);
  int nfds = dev->fd_ > sock->fd_ ? dev->fd_ : sock->fd_;

  int return_value = 0;
  int sig_fd = signal_init();
  if(sig_fd < 0)
    return_value -1;

  FD_SET(sig_fd, &readfds);
  nfds = (nfds < sig_fd) ? sig_fd : nfds;

  while(!return_value) {
    memcpy(&readyfds, &readfds, sizeof(readyfds));
    int ret = select(nfds + 1, &readyfds, NULL, NULL, NULL);
    if(ret == -1 && errno != EINTR) {
      log_printf(ERROR, "select returned with error: %s", strerror(errno));
      return_value = -1;
      break;
    }
    if(!ret || ret == -1)
      continue;

    if(FD_ISSET(sig_fd, &readyfds)) {
      if(signal_handle()) {
        return_value = 1;
        break;
      }
    }

    if(FD_ISSET(dev->fd_, &readyfds)) {
      return_value = process_tun_data(dev, sock, opt, &plain_packet, &encrypted_packet, &c, &aa, &kd, seq_nr);
      seq_nr++;
      if(return_value)
        break;
    }

    if(FD_ISSET(sock->fd_, &readyfds)) {
      return_value = process_sock_data(dev, sock, opt, &plain_packet, &encrypted_packet, &c, &aa, &kd, &seq_win); 
      if(return_value)
        break;
    }
  }

  cipher_close(&c);
#ifndef NO_CRYPT
  auth_algo_close(&aa);
  key_derivation_close(&kd);
#endif
  seq_win_clear(&seq_win);
  signal_stop();

  return return_value;
}

int main(int argc, char* argv[])
{
  log_init();

  options_t opt;
  int ret = options_parse(&opt, argc, argv);
  if(ret) {
    if(ret > 0) {
      fprintf(stderr, "syntax error near: %s\n\n", argv[ret]);
    }
    if(ret == -2) {
      fprintf(stderr, "memory error on options_parse, exitting\n");
    }
    if(ret == -3) {
      fprintf(stderr, "syntax error: -4 and -6 are mutual exclusive\n\n");
    }
    if(ret == -4) {
      fprintf(stderr, "syntax error: unknown role name\n\n");
    }
    if(ret == -5) {
      options_print_version();
    }

    if(ret != -2 && ret != -5) 
      options_print_usage();

    if(ret == -1 || ret == -5)
      ret = 0;

    options_clear(&opt);
    log_close();
    exit(ret);
  }
  string_list_element_t* tmp = opt.log_targets_.first_;
  while(tmp) {
    ret = log_add_target(tmp->string_);
    if(ret) {
      switch(ret) {
      case -2: fprintf(stderr, "memory error on log_add_target, exitting\n"); break;
      case -3: fprintf(stderr, "unknown log target: '%s', exitting\n", tmp->string_); break;
      case -4: fprintf(stderr, "this log target is only allowed once: '%s', exitting\n", tmp->string_); break;
      default: fprintf(stderr, "syntax error near: '%s', exitting\n", tmp->string_); break;
      }
        
      options_clear(&opt);
      log_close();
      exit(ret);
    }
    tmp = tmp->next_;
  }

  log_printf(NOTICE, "just started...");
  options_parse_post(&opt);

  priv_info_t priv;
  if(opt.username_)
    if(priv_init(&priv, opt.username_, opt.groupname_)) {
      options_clear(&opt);
      log_close();
      exit(-1);
    }

  ret = init_crypt();
  if(ret) {
    log_printf(ERROR, "error on crpyto initialization, exitting");
    options_clear(&opt);
    log_close();
    exit(ret);
  }

  tun_device_t dev;
  ret = tun_init(&dev, opt.dev_name_, opt.dev_type_, opt.ifconfig_param_.net_addr_, opt.ifconfig_param_.prefix_length_);
  if(ret) {
    log_printf(ERROR, "error on tun_init, exitting");
    options_clear(&opt);
    log_close();
    exit(ret);
  }
  log_printf(NOTICE, "dev of type '%s' opened, actual name is '%s'", tun_get_type_string(&dev), dev.actual_name_);

  if(opt.post_up_script_) {
    log_printf(NOTICE, "executing post-up script '%s'", opt.post_up_script_);
    char* const argv[] = { opt.post_up_script_, dev.actual_name_, NULL };
    char* const evp[] = { NULL };
    int ret = uanytun_exec(opt.post_up_script_, argv, evp);
  }


  udp_socket_t sock;
  ret = udp_init(&sock, opt.local_addr_, opt.local_port_, opt.resolv_addr_type_);
  if(ret) {
    log_printf(ERROR, "error on udp_init, exitting");
    tun_close(&dev);
    options_clear(&opt);
    log_close();
    exit(ret);
  }
  char* local_string = udp_get_local_end_string(&sock);
  if(local_string) {
    log_printf(NOTICE, "listening on: %s", local_string);
    free(local_string);
  }


  if(opt.remote_addr_) {
    if(!udp_set_remote(&sock, opt.remote_addr_, opt.remote_port_, opt.resolv_addr_type_)) {
      char* remote_string = udp_get_remote_end_string(&sock);
      if(remote_string) {
        log_printf(NOTICE, "set remote end to: %s", remote_string);
        free(remote_string);
      }
    }
  }


  FILE* pid_file = NULL;
  if(opt.pid_file_) {
    pid_file = fopen(opt.pid_file_, "w");
    if(!pid_file) {
      log_printf(WARNING, "unable to open pid file: %s", strerror(errno));
    }
  }

  if(opt.chroot_dir_)
    if(do_chroot(opt.chroot_dir_)) {
      tun_close(&dev);
      udp_close(&sock);
      options_clear(&opt);
      log_close();
      exit(-1);
    }
  if(opt.username_)
    if(priv_drop(&priv)) {
      tun_close(&dev);
      udp_close(&sock);
      options_clear(&opt);
      log_close();
      exit(-1);
    }  

  if(opt.daemonize_) {
    pid_t oldpid = getpid();
    daemonize();
    log_printf(INFO, "running in background now (old pid: %d)", oldpid);
  }

  if(pid_file) {
    pid_t pid = getpid();
    fprintf(pid_file, "%d", pid);
    fclose(pid_file);
  }

  ret = main_loop(&dev, &sock, &opt);

  tun_close(&dev);
  udp_close(&sock);
  options_clear(&opt);

  if(!ret)
    log_printf(NOTICE, "normal shutdown");
  else if(ret < 0)
    log_printf(NOTICE, "shutdown after error");
  else
    log_printf(NOTICE, "shutdown after signal");

  log_close();

  return ret;
}
