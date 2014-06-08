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
 */

#include "datatypes.h"

#include "seq_window.h"

#include <stdlib.h>
#include <string.h>

#include <stdio.h>

int seq_win_init(seq_win_t* win, window_size_t size)
{
  if(!win)
    return -1;

  win->size_ = size;
  win->first_ = NULL;

  return 0;
}

void seq_win_clear(seq_win_t* win)
{
  if(!win)
    return;

  seq_win_element_t* ptr = win->first_;
  while(ptr) {
    seq_win_element_t* to_free = ptr;
    ptr = ptr->next_;
    if(to_free->window_)
      free(to_free->window_);

    free(to_free);
  }

  win->first_ = NULL;
}

static seq_win_element_t* seq_win_new_element(sender_id_t sender_id, seq_nr_t max, window_size_t size)
{
  if(!size)
    return NULL;

  seq_win_element_t* e = malloc(sizeof(seq_win_element_t));
  if(!e)
    return NULL;

  e->sender_id_ = sender_id;
  e->max_ = max;
  e->pos_ = 0;
  e->window_ = malloc(sizeof((*e->window_))*size);
  if(!e->window_) {
    free(e);
    return NULL;
  }
  memset(e->window_, 0, size);
  e->window_[e->pos_] = 1;
  e->next_ = NULL;

  return e;
}

int seq_win_check_and_add(seq_win_t* win, sender_id_t sender_id, seq_nr_t seq_nr)
{
  if(!win)
    return -1;

  if(!win->size_)
    return 0;

  seq_win_element_t* ptr = win->first_;
  while(ptr) {
    if(ptr->sender_id_ == sender_id) {

      int shifted = 0;
      if(ptr->max_ < win->size_) {
        ptr->max_ += SEQ_NR_MAX/2;
        seq_nr += SEQ_NR_MAX/2;
        shifted = 1;
      }
      else if(ptr->max_ > (SEQ_NR_MAX - win->size_)) {
        ptr->max_ -= SEQ_NR_MAX/2;
        seq_nr -= SEQ_NR_MAX/2;
        shifted = 2;
      }

      seq_nr_t min = ptr->max_ - win->size_ + 1;
      if(seq_nr < min || seq_nr == ptr->max_) {
        if(shifted == 1)
          ptr->max_ -= SEQ_NR_MAX/2;
        else if(shifted == 2)
          ptr->max_ += SEQ_NR_MAX/2;
        return 1;
      }

      if(seq_nr > ptr->max_) {
        seq_nr_t diff = seq_nr - ptr->max_;
        if(diff >= win->size_)
          diff = win->size_;

        window_size_t new_pos = ptr->pos_ + diff;

        if(new_pos >= win->size_) {
          new_pos -= win->size_;

          if(ptr->pos_ < win->size_ - 1)
            memset(&(ptr->window_[ptr->pos_ + 1]), 0, win->size_ - ptr->pos_ - 1);

          memset(ptr->window_, 0, new_pos);
        }
        else {
          memset(&(ptr->window_[ptr->pos_ + 1]), 0, diff);
        }
        ptr->pos_ = new_pos;
        ptr->window_[ptr->pos_] = 1;
        ptr->max_ = seq_nr;

        if(shifted == 1)
          ptr->max_ -= SEQ_NR_MAX/2;
        else if(shifted == 2)
          ptr->max_ += SEQ_NR_MAX/2;

        return 0;
      }

      seq_nr_t diff = ptr->max_ - seq_nr;
      window_size_t pos = diff > ptr->pos_ ? ptr->pos_ + win->size_ : ptr->pos_;
      pos -= diff;

      if(shifted == 1)
        ptr->max_ -= SEQ_NR_MAX/2;
      else if(shifted == 2)
        ptr->max_ += SEQ_NR_MAX/2;

      int ret = ptr->window_[pos];
      ptr->window_[pos] = 1;
      return ret;
    }
    ptr = ptr->next_;
  }
  if(!win->first_) {
    win->first_ = seq_win_new_element(sender_id, seq_nr, win->size_);
    if(!win->first_)
      return -2;
  }
  else {
    ptr = win->first_;
    while(ptr->next_)
      ptr = ptr->next_;
    ptr->next_ = seq_win_new_element(sender_id, seq_nr, win->size_);
    if(!ptr->next_)
      return -2;
  }

  return 0;
}

void seq_win_print(seq_win_t* win)
{
  printf("Sequence Window:\n");

  if(!win)
    return;

  seq_win_element_t* ptr = win->first_;
  while(ptr) {
    printf(" [%u]: (%u)-", ptr->sender_id_, ptr->max_);
    window_size_t i = ptr->pos_;
    while(1) {
      if(ptr->window_[i])
        printf("O");
      else
        printf(".");

      if(i)
        i--;
      else
        i = win->size_ - 1;

      if(i == ptr->pos_)
        break;
    }
    printf("\n");
    ptr = ptr->next_;
  }
}
