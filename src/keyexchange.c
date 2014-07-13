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

#define _GNU_SOURCE
#include "datatypes.h"

#include "keyexchange.h"
#include "log.h"

#include <errno.h>
#include <string.h>

int keyexchange_init(keyexchange_t* kx, const char* socket_path)
{
  if(!kx)
    return -1;

  memset(kx->data_buf_, 0, sizeof(kx->data_buf_));
  kx->data_buf_len_ = 0;
  return unixdomain_init(&(kx->socket_), socket_path);
}

int keyexchange_fill_fd_set(keyexchange_t* kx, fd_set* read, fd_set* write)
{
  int maxfd = unixdomain_fill_fd_set(&(kx->socket_), read);
  if(kx->data_buf_len_) {
    FD_SET(kx->socket_.client_fd_, write);
    maxfd = (kx->socket_.client_fd_ > maxfd) ? kx->socket_.client_fd_ : maxfd;
  }

  return maxfd;
}

void keyexchange_close(keyexchange_t* kx)
{
  unixdomain_close(&(kx->socket_));
}

static int keyexchange_handle_accept(keyexchange_t* kx, unixdomain_t* sock)
{
  int old_fd = sock->client_fd_;
  if(unixdomain_accept(sock)) {
    return -1;
  }
  if(old_fd != sock->client_fd_) {
    log_printf(INFO, "key exchange: new client");
  }
  return 0;
}

static int keyexchange_handle_read_data(keyexchange_t* kx)
{
      // TODO: don't overwrite existing data
      //       fix sizeof
  int len = unixdomain_read(&(kx->socket_), kx->data_buf_, sizeof(kx->data_buf_) - 1);
  if(len <= 0) {
    if(!len)
      log_printf(INFO, "key exchange: data interface disconnected");
    else
      log_printf(ERROR, "key exchange: data interface error: %s", strerror(errno));
    kx->socket_.client_fd_ = -1;
  } else {
        // TODO: this is a temporary fix for strings ending with linefeed
    if(kx->data_buf_[len-1] == '\n')
      kx->data_buf_len_ = len - 1;
    else
      kx->data_buf_len_ = len;

    kx->data_buf_[kx->data_buf_len_] = 0;
    log_printf(DEBUG, "key exchange: data interface received string '%s'", kx->data_buf_);
  }

  return 0;
}

static int keyexchange_handle_write_data(keyexchange_t* kx)
{
  int ret = unixdomain_write(&(kx->socket_), kx->data_buf_, kx->data_buf_len_);
      // TODO: handle partial writes
  kx->data_buf_len_ = 0;
  return ret;
}

int keyexchange_handle(keyexchange_t* kx, fd_set* rreadyfds, fd_set* wreadyfds)
{
  if(FD_ISSET(kx->socket_.server_fd_, rreadyfds))
    return keyexchange_handle_accept(kx, &(kx->socket_));

  if(FD_ISSET(kx->socket_.client_fd_, rreadyfds))
    return keyexchange_handle_read_data(kx);

  if(FD_ISSET(kx->socket_.client_fd_, wreadyfds))
    return keyexchange_handle_write_data(kx);

  return 0;
}
