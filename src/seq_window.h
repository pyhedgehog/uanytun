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

#ifndef _SEQ_WINDOW_H_
#define _SEQ_WINDOW_H_

struct seq_win_element_struct {
  sender_id_t sender_id_;
  seq_nr_t max_;
  window_size_t pos_;
  u_int8_t* window_;
  struct seq_win_element_struct* next_;
};
typedef struct seq_win_element_struct seq_win_element_t;

struct seq_win_struct {
  window_size_t size_;
  seq_win_element_t* first_;
};
typedef struct seq_win_struct seq_win_t;

int seq_win_init(seq_win_t* win, window_size_t size);
void seq_win_clear(seq_win_t* win);
seq_win_element_t* seq_win_new_element(sender_id_t sender_id, seq_nr_t max, window_size_t size);
int seq_win_check_and_add(seq_win_t* win, sender_id_t sender_id, seq_nr_t seq_nr);

void seq_win_print(seq_win_t* win);

#endif
