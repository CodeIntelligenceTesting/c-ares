/* MIT License
 *
 * Copyright (c) 2024 Brad House
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef __CI_TIME_H
#define __CI_TIME_H

/*! struct timeval on some systems like Windows doesn't support 64bit time so
 *  therefore can't be used due to Y2K38 issues.  Make our own that does have
 *  64bit time. */
typedef struct {
  ci_int64_t sec;  /*!< Seconds */
  unsigned int usec; /*!< Microseconds. Can't be negative. */
} ci_timeval_t;

/* return true if now is exactly check time or later */
ci_bool_t ci_timedout(const ci_timeval_t *now,
                          const ci_timeval_t *check);

void        ci_tvnow(ci_timeval_t *now);
void        ci_timeval_remaining(ci_timeval_t       *remaining,
                                   const ci_timeval_t *now,
                                   const ci_timeval_t *tout);
void ci_timeval_diff(ci_timeval_t *tvdiff, const ci_timeval_t *tvstart,
                       const ci_timeval_t *tvstop);

#endif
