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
 *  Copyright (C) 2007-2016 Christian Pointner <equinox@anytun.org>
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

#include "encrypted_packet.h"

#include <stdlib.h>
#include <string.h>

void encrypted_packet_init(encrypted_packet_t* packet, u_int32_t auth_tag_length)
{
  if(!packet)
    return;

  memset (packet, 0, sizeof(*packet));
  if(auth_tag_length > (ENCRYPTED_PACKET_SIZE_MAX - sizeof(encrypted_packet_header_t)))
    packet->auth_tag_length_ = ENCRYPTED_PACKET_SIZE_MAX - sizeof(encrypted_packet_header_t);
  else
    packet->auth_tag_length_ = auth_tag_length;
}

u_int32_t encrypted_packet_get_minimum_length(encrypted_packet_t* packet)
{
  if(!packet)
    return 0;

  return (sizeof(encrypted_packet_header_t) + packet->auth_tag_length_);
}

u_int8_t* encrypted_packet_get_packet(encrypted_packet_t* packet)
{
  if(!packet)
    return NULL;

  return packet->data_.buf_;
}

u_int32_t encrypted_packet_get_length(encrypted_packet_t* packet)
{
  if(!packet)
    return 0;

  return (packet->payload_length_ + sizeof(encrypted_packet_header_t) + packet->auth_tag_length_);
}

void encrypted_packet_set_length(encrypted_packet_t* packet, u_int32_t len)
{
  if(!packet)
    return;

  if(len > ENCRYPTED_PACKET_SIZE_MAX)
    len = ENCRYPTED_PACKET_SIZE_MAX - sizeof(encrypted_packet_header_t) - packet->auth_tag_length_;
  else if(len < (sizeof(encrypted_packet_header_t) + packet->auth_tag_length_))
    len = 0;
  else
    len -= (sizeof(encrypted_packet_header_t) + packet->auth_tag_length_);

  packet->payload_length_ = len;
}

u_int8_t* encrypted_packet_get_payload(encrypted_packet_t* packet)
{
  if(!packet || !packet->payload_length_)
    return NULL;

  return (packet->data_.buf_ + sizeof(encrypted_packet_header_t));
}

u_int32_t encrypted_packet_get_payload_length(encrypted_packet_t* packet)
{
  if(!packet)
    return 0;

  return packet->payload_length_;
}

void encrypted_packet_set_payload_length(encrypted_packet_t* packet, u_int32_t len)
{
  if(!packet)
    return;

  if(len > (ENCRYPTED_PACKET_SIZE_MAX - sizeof(encrypted_packet_header_t) - packet->auth_tag_length_))
    len = ENCRYPTED_PACKET_SIZE_MAX - sizeof(encrypted_packet_header_t) - packet->auth_tag_length_;

  packet->payload_length_ = len;
}

u_int8_t* encrypted_packet_get_auth_portion(encrypted_packet_t* packet)
{
  if(!packet)
    return NULL;

  return packet->data_.buf_;
}

u_int32_t encrypted_packet_get_auth_portion_length(encrypted_packet_t* packet)
{
  if(!packet)
    return 0;

  return  packet->payload_length_ + sizeof(encrypted_packet_header_t);
}


u_int8_t* encrypted_packet_get_auth_tag(encrypted_packet_t* packet)
{
  if(!packet || !packet->auth_tag_length_)
    return NULL;

  return (packet->data_.buf_ + sizeof(encrypted_packet_header_t) + packet->payload_length_);
}

u_int32_t encrypted_packet_get_auth_tag_length(encrypted_packet_t* packet)
{
  if(!packet)
    return 0;

  return packet->auth_tag_length_;
}


seq_nr_t encrypted_packet_get_seq_nr(encrypted_packet_t* packet)
{
  if(!packet)
    return 0;

  return SEQ_NR_T_NTOH(packet->data_.header_.seq_nr_);
}

void encrypted_packet_set_seq_nr(encrypted_packet_t* packet, seq_nr_t seq_nr)
{
  if(!packet)
    return;

  packet->data_.header_.seq_nr_ = SEQ_NR_T_HTON(seq_nr);
}

sender_id_t encrypted_packet_get_sender_id(encrypted_packet_t* packet)
{
  if(!packet)
    return 0;

  return SENDER_ID_T_NTOH(packet->data_.header_.sender_id_);
}

void encrypted_packet_set_sender_id(encrypted_packet_t* packet, sender_id_t sender_id)
{
  if(!packet)
    return;

  packet->data_.header_.sender_id_ = SENDER_ID_T_HTON(sender_id);
}

mux_t encrypted_packet_get_mux(encrypted_packet_t* packet)
{
  if(!packet)
    return 0;

  return MUX_T_NTOH(packet->data_.header_.mux_);
}

void encrypted_packet_set_mux(encrypted_packet_t* packet, mux_t mux)
{
  if(!packet)
    return;

  packet->data_.header_.mux_ = MUX_T_HTON(mux);
}
