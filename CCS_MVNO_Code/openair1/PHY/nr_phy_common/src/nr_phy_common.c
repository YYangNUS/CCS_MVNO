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

#include "nr_phy_common.h"

void freq2time(uint16_t ofdm_symbol_size, int16_t *freq_signal, int16_t *time_signal)
{
  const idft_size_idx_t idft_size = get_idft(ofdm_symbol_size);
  idft(idft_size, freq_signal, time_signal, 1);
}

void nr_est_delay(int ofdm_symbol_size, const c16_t *ls_est, c16_t *ch_estimates_time, delay_t *delay)
{
  freq2time(ofdm_symbol_size, (int16_t *)ls_est, (int16_t *)ch_estimates_time);

  int max_pos = delay->delay_max_pos;
  int max_val = delay->delay_max_val;
  const int sync_pos = 0;

  for (int i = 0; i < ofdm_symbol_size; i++) {
    int temp = c16amp2(ch_estimates_time[i]) >> 1;
    if (temp > max_val) {
      max_pos = i;
      max_val = temp;
    }
  }

  if (max_pos > ofdm_symbol_size / 2)
    max_pos = max_pos - ofdm_symbol_size;

  delay->delay_max_pos = max_pos;
  delay->delay_max_val = max_val;
  delay->est_delay = max_pos - sync_pos;
}

unsigned int nr_get_tx_amp(int power_dBm, int power_max_dBm, int total_nb_rb, int nb_rb)
{
  // assume power at AMP is 20dBm
  // if gain = 20 (power == 40)
  int gain_dB = power_dBm - power_max_dBm;
  double gain_lin;

  gain_lin = pow(10, .1 * gain_dB);
  if ((nb_rb > 0) && (nb_rb <= total_nb_rb)) {
    return ((int)(AMP * sqrt(gain_lin * total_nb_rb / (double)nb_rb)));
  } else {
    LOG_E(PHY, "Illegal nb_rb/N_RB_UL combination (%d/%d)\n", nb_rb, total_nb_rb);
    // mac_xface->macphy_exit("");
  }
  return (0);
}
