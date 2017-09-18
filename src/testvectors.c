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

#include "datatypes.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "log.h"

#include "key_derivation.h"
#include "init_crypt.h"

int main(int argc, char* argv[])
{
  log_init();
  log_add_target("stdout:5");
  log_printf(NOTICE, "just started...");

  if(argc < 2) {
    log_printf(ERROR, "usage: %s <passphrase>", argv[0]);
    return 1;
  }

  key_derivation_t kd;
  int ret = key_derivation_init(&kd, "aes-ctr", ROLE_LEFT, argv[1], NULL, 0, NULL, 0);
  if(ret) {
    return ret;
  }
  log_printf(NOTICE, "role: left");

      /***********/

  key_derivation_dir_t dir = kd_outbound;
  satp_prf_label_t label = LABEL_ENC;
  seq_nr_t seq_nr = 0;
  log_printf(NOTICE, "dir: outbound");
  log_printf(NOTICE, "label: enc");
  log_printf(NOTICE, "seq_nr: 0x%08lX", seq_nr);

  u_int8_t out[32];
  memset(out, 0, sizeof(out));
  ret = key_derivation_generate(&kd, dir, label, seq_nr, out, sizeof(out));
  if(ret) {
    return ret;
  }
  log_print_hex_dump(DEBUG, out, sizeof(out));

      /***********/

  dir = kd_inbound;
  label = LABEL_ENC;
  seq_nr = 1231415;
  log_printf(NOTICE, "dir: inbound");
  log_printf(NOTICE, "label: enc");
  log_printf(NOTICE, "seq_nr: 0x%08lX", seq_nr);

  memset(out, 0, sizeof(out));
  ret = key_derivation_generate(&kd, dir, label, seq_nr, out, sizeof(out));
  if(ret) {
    return ret;
  }
  log_print_hex_dump(DEBUG, out, sizeof(out));

      /***********/

  dir = kd_inbound;
  label = LABEL_SALT;
  seq_nr = 1231415;
  log_printf(NOTICE, "dir: inbound");
  log_printf(NOTICE, "label: salt");
  log_printf(NOTICE, "seq_nr: 0x%08lX", seq_nr);

  memset(out, 0, sizeof(out));
  ret = key_derivation_generate(&kd, dir, label, seq_nr, out, sizeof(out));
  if(ret) {
    return ret;
  }
  log_print_hex_dump(DEBUG, out, sizeof(out));

      /***********/

  dir = kd_inbound;
  label = LABEL_AUTH;
  seq_nr = 14;
  log_printf(NOTICE, "dir: inbound");
  log_printf(NOTICE, "label: auth");
  log_printf(NOTICE, "seq_nr: 0x%08lX", seq_nr);

  memset(out, 0, sizeof(out));
  ret = key_derivation_generate(&kd, dir, label, seq_nr, out, sizeof(out));
  if(ret) {
    return ret;
  }
  log_print_hex_dump(DEBUG, out, sizeof(out));

      /***********/

  dir = kd_outbound;
  label = LABEL_AUTH;
  seq_nr = 12;
  log_printf(NOTICE, "dir: outbound");
  log_printf(NOTICE, "label: auth");
  log_printf(NOTICE, "seq_nr: 0x%08lX", seq_nr);

  memset(out, 0, sizeof(out));
  ret = key_derivation_generate(&kd, dir, label, seq_nr, out, sizeof(out));
  if(ret) {
    return ret;
  }
  log_print_hex_dump(DEBUG, out, sizeof(out));

      /***********/

  return ret;
}
