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
 *  Copyright (C) 2007-2014 Christian Pointner <equinox@anytun.org>
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

#ifndef UANYTUN_packet_queue_h_INCLUDED
#define UANYTUN_packet_queue_h_INCLUDED

#define PACKET_QUEUE_FLAGS_USED 0x00000001

struct packet_queue_struct {
  size_t size_;
  void* packets_;
  int* flags_;
};
typedef struct packet_queue_struct packet_queue_t;

#define packet_queue_init(TYPE, ...) do {                                \
    int i;                                                               \
    for(i = 0; i < TYPE ## _queue.size_; ++i) {                          \
      TYPE ## _queue.flags_[i] = 0;                                      \
      TYPE ## _init(&(((TYPE ## _t*)TYPE ## _queue.packets_)[i]), ## __VA_ARGS__); \
    }                                                                    \
  } while(0)

#define packet_queue_acquire_next(TYPE, idx) do {                    \
    idx = -1;                                                        \
    int i;                                                           \
    for(i = 0; i < TYPE ## _queue.size_; ++i) {                      \
      if(!(TYPE ## _queue.flags_[i] & PACKET_QUEUE_FLAGS_USED)) {    \
        TYPE ## _queue.flags_[i] |= PACKET_QUEUE_FLAGS_USED;         \
        idx = i;                                                     \
        break;                                                       \
      }                                                              \
    }                                                                \
  } while(0)

#define packet_queue_release(TYPE, packet) do {                      \
    int i;                                                           \
    for(i = 0; i < TYPE ## _queue.size_; ++i) {                      \
      if(&(((TYPE ## _t*)TYPE ## _queue.packets_)[i]) == packet) {   \
        TYPE ## _queue.flags_[i] &= ~PACKET_QUEUE_FLAGS_USED;        \
        break;                                                       \
      }                                                              \
    }                                                                \
  } while(0)

#define packet_queue_get(TYPE, idx) (idx >= 0) && (idx < TYPE ## _queue.size_) ? &(((TYPE ## _t*)TYPE ## _queue.packets_)[idx]) : NULL


#define packet_queue_instantiate(SIZE, TYPE)                                         \
TYPE ## _t TYPE ## _data_array[SIZE];                                                \
int TYPE ## _flags_array[SIZE];                                                      \
packet_queue_t TYPE ## _queue = { SIZE, TYPE ## _data_array, TYPE ## _flags_array }; \
TYPE ## _t* TYPE ## _queue_get_next() {                                              \
  int idx;                                                                           \
  packet_queue_acquire_next(TYPE, idx);                                              \
  return packet_queue_get(TYPE, idx);                                                \
}                                                                                    \
void TYPE ## _queue_release(TYPE ## _t* packet) {                                    \
  packet_queue_release(TYPE, packet);                                                \
}                                                                                    \


#endif

