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
 *  Copyright (C) 2007-2010 Christian Pointner <equinox@anytun.org>
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

#include "plain_packet.h"

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>

void plain_packet_init(plain_packet_t* packet)
{
  if(!packet)
    return;

  memset (packet, 0, sizeof(*packet));
}

u_int32_t plain_packet_get_header_length()
{
  return sizeof(payload_type_t);
}

u_int8_t* plain_packet_get_packet(plain_packet_t* packet)
{
  if(!packet)
    return NULL;

  return packet->data_.buf_;
}

u_int32_t plain_packet_get_length(plain_packet_t* packet)
{
  if(!packet)
    return 0;

  return (packet->payload_length_ + sizeof(payload_type_t));
}

void plain_packet_set_length(plain_packet_t* packet, u_int32_t len)
{
  if(!packet)
    return;
  
  if(len > PLAIN_PACKET_SIZE_MAX)
    len = PLAIN_PACKET_SIZE_MAX - sizeof(payload_type_t);
  else if(len < sizeof(payload_type_t))
    len = 0;
  else
    len -= sizeof(payload_type_t);

  packet->payload_length_ = len;  
}

u_int8_t* plain_packet_get_payload(plain_packet_t* packet)
{
  if(!packet || !packet->payload_length_)
    return NULL;

  return (packet->data_.buf_ + sizeof(payload_type_t));
}

u_int32_t plain_packet_get_payload_length(plain_packet_t* packet)
{
  if(!packet)
    return 0;

  return packet->payload_length_;
}

void plain_packet_set_payload_length(plain_packet_t* packet, u_int32_t len)
{
  if(!packet)
    return;

  if(len > PLAIN_PACKET_SIZE_MAX || (len + sizeof(payload_type_t)) > PLAIN_PACKET_SIZE_MAX)
    len = PLAIN_PACKET_SIZE_MAX - sizeof(payload_type_t);

  packet->payload_length_ = len;
}

payload_type_t plain_packet_get_type(plain_packet_t* packet)
{
  if(!packet)
    return 0;

  return PAYLOAD_TYPE_T_NTOH(packet->data_.payload_type_);
}

void plain_packet_set_type(plain_packet_t* packet, payload_type_t type)
{
  if(!packet)
    return;

  if(type == PAYLOAD_TYPE_TUN) {
    if(!packet->payload_length_) {
      packet->data_.payload_type_ = PAYLOAD_TYPE_T_HTON(PAYLOAD_TYPE_TUN);
      return;
    }

    struct ip* hdr = (struct ip*)(packet->data_.buf_ + sizeof(payload_type_t));
    if(hdr->ip_v == 4)
      packet->data_.payload_type_ = PAYLOAD_TYPE_T_HTON(PAYLOAD_TYPE_TUN4);
    else if(hdr->ip_v == 6)
      packet->data_.payload_type_ = PAYLOAD_TYPE_T_HTON(PAYLOAD_TYPE_TUN6);
  }
  else
    packet->data_.payload_type_ = PAYLOAD_TYPE_T_HTON(type);
}
