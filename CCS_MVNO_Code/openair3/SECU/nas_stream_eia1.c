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

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <math.h> // double ceil(double x);

#include "nas_stream_eia1.h"

#include "assertions.h"
#include "conversions.h"
#include "snow3g.h"

#define SECU_DEBUG

// see spec 3GPP Confidentiality and Integrity Algorithms UEA2&UIA2. Document 1: UEA2 and UIA2 Specification. Version 1.1

/* MUL64x.
 * Input V: a 64-bit input.
 * Input c: a 64-bit input.
 * Output : a 64-bit output.
 * A 64-bit memory is allocated which is to be freed by the calling
 * function.
 * See section 4.3.2 for details.
 */
static uint64_t MUL64x(uint64_t V, uint64_t c)
{
  if ( V & 0x8000000000000000 )
    return (V << 1) ^ c;
  else
    return V << 1;
}
/* MUL64xPOW.
 * Input V: a 64-bit input.
 * Input i: a positive integer.
 * Input c: a 64-bit input.
 * Output : a 64-bit output.
 * A 64-bit memory is allocated which is to be freed by the calling
function.
 * See section 4.3.3 for details.
 */
static uint64_t MUL64xPOW(uint64_t V, uint32_t i, uint64_t c)
{
  if ( i == 0)
    return V;
  else
    return MUL64x( MUL64xPOW(V,i-1,c) , c);
}
/* MUL64.
 * Input V: a 64-bit input.
 * Input P: a 64-bit input.
 * Input c: a 64-bit input.
 * Output : a 64-bit output.
 * A 64-bit memory is allocated which is to be freed by the calling
 * function.
 * See section 4.3.4 for details.
 */
static uint64_t MUL64(uint64_t V, uint64_t P, uint64_t c)
{
  uint64_t result = 0;
  int i = 0;

  for ( i=0; i<64; i++) {
    if( ( P>>i ) & 0x1 )
      result ^= MUL64xPOW(V,i,c);
  }

  return result;
}

/* read a big endian uint64_t at given address (potentially not 64-bits aligned)
 * don't read more than 'available_bytes'
 * (use 0 if no byte to read)
 * (note: the compiler will optimize this, no need to do better)
 */
static inline uint64_t U64(uint8_t *p, int available_bytes)
{
  uint64_t a = 0;
  uint64_t b = 0;
  uint64_t c = 0;
  uint64_t d = 0;
  uint64_t e = 0;
  uint64_t f = 0;
  uint64_t g = 0;
  uint64_t h = 0;
  switch (available_bytes) {
    case 8: h = p[7]; /* falltrough */
    case 7: g = p[6]; /* falltrough */
    case 6: f = p[5]; /* falltrough */
    case 5: e = p[4]; /* falltrough */
    case 4: d = p[3]; /* falltrough */
    case 3: c = p[2]; /* falltrough */
    case 2: b = p[1]; /* falltrough */
    case 1: a = p[0];
  }

  return (a << (32+24)) | (b << (32+16)) | (c << (32+8)) | (d << 32)
         | (e << 24) | (f << 16) | (g << 8) | h;
}

/*!
 * @brief Create integrity cmac t for a given message.
 * @param[in] stream_cipher Structure containing various variables to setup encoding
 * @param[out] out For EIA1 the output string is 32 bits long
 */
void nas_stream_encrypt_eia1(nas_stream_cipher_t const *stream_cipher, uint8_t out[4])
{
  snow_3g_context_t snow_3g_context;
  uint32_t        K[4],IV[4], z[5];
  int             i=0,D;
  uint32_t        MAC_I = 0;
  uint64_t        EVAL;
  uint64_t        V;
  uint64_t        P;
  uint64_t        Q;
  uint64_t        c;
  uint64_t        M_D_2;
  int             rem_bits;
  uint8_t         *key = (uint8_t *)stream_cipher->context;

  /* Load the Integrity Key for SNOW3G initialization as in section 4.4. */
  memcpy(K+3,key+0,4); /*K[3] = key[0]; we assume
    K[3]=key[0]||key[1]||...||key[31] , with key[0] the
    * most important bit of key*/
  memcpy(K+2,key+4,4); /*K[2] = key[1];*/
  memcpy(K+1,key+8,4); /*K[1] = key[2];*/
  memcpy(K+0,key+12,4); /*K[0] = key[3]; we assume
    K[0]=key[96]||key[97]||...||key[127] , with key[127] the
    * least important bit of key*/
  K[3] = hton_int32(K[3]);
  K[2] = hton_int32(K[2]);
  K[1] = hton_int32(K[1]);
  K[0] = hton_int32(K[0]);
  /* Prepare the Initialization Vector (IV) for SNOW3G initialization as in
    section 4.4. */
  IV[3] = (uint32_t)stream_cipher->count;
  IV[2] = ((((uint32_t)stream_cipher->bearer) & 0x0000001F) << 27);
  IV[1] = (uint32_t)(stream_cipher->count) ^ ( (uint32_t)(stream_cipher->direction) << 31 ) ;
  IV[0] = ((((uint32_t)stream_cipher->bearer) & 0x0000001F) << 27) ^ ((uint32_t)(stream_cipher->direction & 0x00000001) << 15);
  //printf ("K:\n");
  //hexprint(K, 16);
  //printf ("K[0]:%08X\n",K[0]);
  //printf ("K[1]:%08X\n",K[1]);
  //printf ("K[2]:%08X\n",K[2]);
  //printf ("K[3]:%08X\n",K[3]);

  //printf ("IV:\n");
  //hexprint(IV, 16);
  //printf ("IV[0]:%08X\n",IV[0]);
  //printf ("IV[1]:%08X\n",IV[1]);
  //printf ("IV[2]:%08X\n",IV[2]);
  //printf ("IV[3]:%08X\n",IV[3]);
  z[0] = z[1] = z[2] = z[3] = z[4] = 0;
  /* Run SNOW 3G to produce 5 keystream words z_1, z_2, z_3, z_4 and z_5. */
  snow3g_initialize(K, IV, &snow_3g_context);
  snow3g_generate_key_stream(5, z, &snow_3g_context);
  //printf ("z[0]:%08X\n",z[0]);
  //printf ("z[1]:%08X\n",z[1]);
  //printf ("z[2]:%08X\n",z[2]);
  //printf ("z[3]:%08X\n",z[3]);
  //printf ("z[4]:%08X\n",z[4]);
  P = ((uint64_t)z[0] << 32) | (uint64_t)z[1];
  Q = ((uint64_t)z[2] << 32) | (uint64_t)z[3];
  //printf ("P:%16lX\n",P);
  //printf ("Q:%16lX\n",Q);
  /* Calculation */
  D = ceil( stream_cipher->blength / 64.0 ) + 1;
  //printf ("D:%d\n",D);
  EVAL = 0;
  c = 0x1b;

  AssertFatal(stream_cipher->blength % 8 == 0, "unsupported buffer length\n");

  uint8_t *message = stream_cipher->message;

  /* for 0 <= i <= D-3 */
  for (i=0; i<D-2; i++) {
    V = EVAL ^ U64(&message[4 * 2*i], 8);
    EVAL = MUL64(V,P,c);
  }

  /* for D-2 */
  rem_bits = stream_cipher->blength % 64;

  if (rem_bits == 0)
    rem_bits = 64;

  M_D_2 = U64(&message[4 * (2*(D-2))], rem_bits/8);

  V = EVAL ^ M_D_2;
  EVAL = MUL64(V,P,c);
  /* for D-1 */
  EVAL ^= stream_cipher->blength;
  /* Multiply by Q */
  EVAL = MUL64(EVAL,Q,c);
  MAC_I = (uint32_t)(EVAL >> 32) ^ z[4];
  //printf ("MAC_I:%16X\n",MAC_I);
  MAC_I = hton_int32(MAC_I);
  memcpy(out, &MAC_I, 4);
}

stream_security_context_t *stream_integrity_init_eia1(const uint8_t *integrity_key)
{
  void *ret = calloc(1, 16);
  AssertFatal(ret != NULL, "out of memory\n");
  memcpy(ret, integrity_key, 16);
  return (stream_security_context_t *)ret;
}

void stream_integrity_free_eia1(stream_security_context_t *integrity_context)
{
  free(integrity_context);
}
