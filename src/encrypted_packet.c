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

#include "encrypted_packet.h"

#include <stdlib.h>
#include <string.h>

void encrypted_packet_init(encrypted_packet_t* packet)
{
  if(!packet)
    return;

  memset (packet, 0, sizeof(*packet));
}

u_int32_t encrypted_packet_get_header_length()
{
  return sizeof(encrypted_packet_header_t);
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

  return (packet->payload_length_ + sizeof(encrypted_packet_header_t));
}

void encrypted_packet_set_length(encrypted_packet_t* packet, u_int32_t len)
{
  if(!packet)
    return;

  if(len > ENCRYPTED_PACKET_SIZE_MAX)
    len = ENCRYPTED_PACKET_SIZE_MAX - sizeof(encrypted_packet_header_t);
  else if(len < sizeof(encrypted_packet_header_t))
    len = 0;
  else
    len -= sizeof(encrypted_packet_header_t);

  packet->payload_length_ = len;

  if(len >= ENCRYPTED_PACKET_AUTHTAG_SIZE) {
    packet->auth_tag_ = packet->data_.buf_ + sizeof(encrypted_packet_header_t);
    packet->auth_tag_ += packet->payload_length_ - ENCRYPTED_PACKET_AUTHTAG_SIZE;
  }
  else
    packet->auth_tag_ = NULL;
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

  if(len > ENCRYPTED_PACKET_SIZE_MAX || (len + sizeof(encrypted_packet_header_t)) > ENCRYPTED_PACKET_SIZE_MAX)
    len = ENCRYPTED_PACKET_SIZE_MAX - sizeof(encrypted_packet_header_t);

  packet->payload_length_ = len;

  if(len >= ENCRYPTED_PACKET_AUTHTAG_SIZE) {
    packet->auth_tag_ = packet->data_.buf_ + sizeof(encrypted_packet_header_t);
    packet->auth_tag_ += packet->payload_length_ - ENCRYPTED_PACKET_AUTHTAG_SIZE;
  }
  else
    packet->auth_tag_ = NULL;
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

  u_int32_t len = packet->payload_length_ + sizeof(encrypted_packet_header_t);

  if(!packet->auth_tag_)
    return len;
  
  return (len > ENCRYPTED_PACKET_AUTHTAG_SIZE) ? (len - ENCRYPTED_PACKET_AUTHTAG_SIZE) : 0;
}


u_int8_t* encrypted_packet_get_auth_tag(encrypted_packet_t* packet)
{
  if(!packet)
    return NULL;

  return packet->auth_tag_;
}

u_int32_t encrypted_packet_get_auth_tag_length(encrypted_packet_t* packet)
{
  if(!packet || !packet->auth_tag_)
    return 0;

  return ENCRYPTED_PACKET_AUTHTAG_SIZE;
}

void encrypted_packet_add_auth_tag(encrypted_packet_t* packet)
{
  if(!packet)
    return;

  encrypted_packet_set_payload_length(packet, packet->payload_length_ + ENCRYPTED_PACKET_AUTHTAG_SIZE);
}

void encrypted_packet_remove_auth_tag(encrypted_packet_t* packet)
{
  if(!packet || !packet->auth_tag_)
    return;

  packet->auth_tag_ = NULL;
  packet->payload_length_ = (packet->payload_length_ > ENCRYPTED_PACKET_AUTHTAG_SIZE) ? packet->payload_length_ - ENCRYPTED_PACKET_AUTHTAG_SIZE: 0;  
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
