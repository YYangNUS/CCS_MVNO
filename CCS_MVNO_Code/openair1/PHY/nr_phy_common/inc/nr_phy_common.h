/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this file
 * except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.openairinterface.org/?page_id=698
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */

#ifndef __NR_PHY_COMMON__H__
#define __NR_PHY_COMMON__H__
#include "PHY/impl_defs_top.h"
#include "PHY/TOOLS/tools_defs.h"

void freq2time(uint16_t ofdm_symbol_size, int16_t *freq_signal, int16_t *time_signal);
void nr_est_delay(int ofdm_symbol_size, const c16_t *ls_est, c16_t *ch_estimates_time, delay_t *delay);
unsigned int nr_get_tx_amp(int power_dBm, int power_max_dBm, int total_nb_rb, int nb_rb);
#endif
