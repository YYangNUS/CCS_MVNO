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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "nr_mac_gNB.h"
#include "intertask_interface.h"
#include "openair3/ocp-gtpu/gtp_itf.h"

#include "mac_rrc_ul.h"

static f1ap_net_config_t read_DU_IP_config(const eth_params_t* f1_params, const char *f1u_ip_addr)
{
  f1ap_net_config_t nc = {0};

  nc.CU_f1_ip_address.ipv6 = 0;
  nc.CU_f1_ip_address.ipv4 = 1;
  strcpy(nc.CU_f1_ip_address.ipv4_address, f1_params->remote_addr);
  nc.CUport = f1_params->remote_portd;

  nc.DU_f1c_ip_address.ipv6 = 0;
  nc.DU_f1c_ip_address.ipv4 = 1;
  strcpy(nc.DU_f1c_ip_address.ipv4_address, f1_params->my_addr);
  nc.DU_f1u_ip_address = strdup(f1u_ip_addr);
  nc.DUport = f1_params->my_portd;
  LOG_I(F1AP,
        "F1-C DU IPaddr %s, connect to F1-C CU %s, binding GTP to %s\n",
        nc.DU_f1c_ip_address.ipv4_address,
        nc.CU_f1_ip_address.ipv4_address,
        nc.DU_f1u_ip_address);

  // sctp_in_streams/sctp_out_streams are given by SCTP layer
  return nc;
}

static void f1_reset_du_initiated_f1ap(const f1ap_reset_t *reset)
{
  (void) reset;
  AssertFatal(false, "%s() not implemented yet\n", __func__);
}

static void f1_reset_acknowledge_cu_initiated_f1ap(const f1ap_reset_ack_t *ack)
{
  MessageDef *msg = itti_alloc_new_message(TASK_MAC_GNB, 0, F1AP_RESET_ACK);
  f1ap_reset_ack_t *f1ap_msg = &F1AP_RESET_ACK(msg);
  *f1ap_msg = *ack;
  itti_send_msg_to_task(TASK_DU_F1, 0, msg);
}

static void f1_setup_request_f1ap(const f1ap_setup_req_t *req)
{
  MessageDef *msg = itti_alloc_new_message(TASK_MAC_GNB, 0, F1AP_DU_REGISTER_REQ);

  f1ap_setup_req_t *f1ap_setup = &F1AP_DU_REGISTER_REQ(msg).setup_req;
  f1ap_setup->gNB_DU_id = req->gNB_DU_id;
  f1ap_setup->gNB_DU_name = strdup(req->gNB_DU_name);
  f1ap_setup->num_cells_available = req->num_cells_available;
  for (int n = 0; n < req->num_cells_available; ++n) {
    f1ap_setup->cell[n].info = req->cell[n].info; // copy most fields
    if (req->cell[n].info.tac) {
      f1ap_setup->cell[n].info.tac = malloc(sizeof(*f1ap_setup->cell[n].info.tac));
      AssertFatal(f1ap_setup->cell[n].info.tac != NULL, "out of memory\n");
      *f1ap_setup->cell[n].info.tac = *req->cell[n].info.tac;
    }
    if (req->cell[n].info.measurement_timing_config_len > 0) {
      f1ap_setup->cell[n].info.measurement_timing_config = calloc(req->cell[n].info.measurement_timing_config_len, sizeof(uint8_t));
      AssertFatal(f1ap_setup->cell[n].info.measurement_timing_config != NULL, "out of memory\n");
      memcpy(f1ap_setup->cell[n].info.measurement_timing_config,
             req->cell[n].info.measurement_timing_config,
             req->cell[n].info.measurement_timing_config_len);
      f1ap_setup->cell[n].info.measurement_timing_config_len = req->cell[n].info.measurement_timing_config_len;
    }

    if (req->cell[n].sys_info) {
      f1ap_gnb_du_system_info_t *orig_sys_info = req->cell[n].sys_info;
      f1ap_gnb_du_system_info_t *copy_sys_info = calloc(1, sizeof(*copy_sys_info));
      AssertFatal(copy_sys_info, "out of memory\n");
      f1ap_setup->cell[n].sys_info = copy_sys_info;

      copy_sys_info->mib = calloc(orig_sys_info->mib_length, sizeof(uint8_t));
      AssertFatal(copy_sys_info->mib, "out of memory\n");
      memcpy(copy_sys_info->mib, orig_sys_info->mib, orig_sys_info->mib_length);
      copy_sys_info->mib_length = orig_sys_info->mib_length;

      if (orig_sys_info->sib1_length > 0) {
        copy_sys_info->sib1 = calloc(orig_sys_info->sib1_length, sizeof(uint8_t));
        AssertFatal(copy_sys_info->sib1, "out of memory\n");
        memcpy(copy_sys_info->sib1, orig_sys_info->sib1, orig_sys_info->sib1_length);
        copy_sys_info->sib1_length = orig_sys_info->sib1_length;
      }
    }
  }
  memcpy(f1ap_setup->rrc_ver, req->rrc_ver, sizeof(req->rrc_ver));

  F1AP_DU_REGISTER_REQ(msg).net_config = read_DU_IP_config(&RC.nrmac[0]->eth_params_n, RC.nrmac[0]->f1u_addr);

  itti_send_msg_to_task(TASK_DU_F1, 0, msg);
}

static void gnb_du_configuration_update_f1ap(const f1ap_gnb_du_configuration_update_t *upd)
{
  MessageDef *msg = itti_alloc_new_message(TASK_MAC_GNB, 0, F1AP_GNB_DU_CONFIGURATION_UPDATE);
  f1ap_gnb_du_configuration_update_t *f1_upd = &F1AP_GNB_DU_CONFIGURATION_UPDATE(msg);
  f1_upd->transaction_id = upd->transaction_id;
  AssertFatal(upd->num_cells_to_add == 0, "gNB-DU config update: cells to add not supported\n");
  f1_upd->num_cells_to_modify = upd->num_cells_to_modify;
  for (int n = 0; n < upd->num_cells_to_modify; ++n) {
    f1_upd->cell_to_modify[n].old_plmn = upd->cell_to_modify[n].old_plmn;
    f1_upd->cell_to_modify[n].old_nr_cellid = upd->cell_to_modify[n].old_nr_cellid;
    f1_upd->cell_to_modify[n].info = upd->cell_to_modify[n].info;
    if (upd->cell_to_modify[n].sys_info) {
      f1ap_gnb_du_system_info_t *orig_sys_info = upd->cell_to_modify[n].sys_info;
      f1ap_gnb_du_system_info_t *copy_sys_info = calloc(1, sizeof(*copy_sys_info));
      f1_upd->cell_to_modify[n].sys_info = copy_sys_info;

      copy_sys_info->mib = calloc(orig_sys_info->mib_length, sizeof(uint8_t));
      AssertFatal(copy_sys_info->mib != NULL, "out of memory\n");
      memcpy(copy_sys_info->mib, orig_sys_info->mib, orig_sys_info->mib_length);
      copy_sys_info->mib_length = orig_sys_info->mib_length;

      if (orig_sys_info->sib1_length > 0) {
        copy_sys_info->sib1 = calloc(orig_sys_info->sib1_length, sizeof(uint8_t));
        AssertFatal(copy_sys_info->sib1 != NULL, "out of memory\n");
        memcpy(copy_sys_info->sib1, orig_sys_info->sib1, orig_sys_info->sib1_length);
        copy_sys_info->sib1_length = orig_sys_info->sib1_length;
      }
    }
  }
  AssertFatal(upd->num_cells_to_delete == 0, "gNB-DU config update: cells to add not supported\n");
  itti_send_msg_to_task(TASK_DU_F1, 0, msg);
}

static void ue_context_setup_response_f1ap(const f1ap_ue_context_setup_t *req, const f1ap_ue_context_setup_t *resp)
{
  DevAssert(req->drbs_to_be_setup_length == resp->drbs_to_be_setup_length);

  DevAssert(req->srbs_to_be_setup_length == resp->srbs_to_be_setup_length);
  MessageDef *msg = itti_alloc_new_message (TASK_MAC_GNB, 0, F1AP_UE_CONTEXT_SETUP_RESP);
  f1ap_ue_context_setup_t *f1ap_msg = &F1AP_UE_CONTEXT_SETUP_RESP(msg);
  /* copy all fields, but reallocate rrc_containers! */
  *f1ap_msg = *resp;

  if (resp->srbs_to_be_setup_length > 0) {
    DevAssert(resp->srbs_to_be_setup != NULL);
    f1ap_msg->srbs_to_be_setup_length = resp->srbs_to_be_setup_length;
    f1ap_msg->srbs_to_be_setup = calloc(f1ap_msg->srbs_to_be_setup_length, sizeof(*f1ap_msg->srbs_to_be_setup));
    for (int i = 0; i < f1ap_msg->srbs_to_be_setup_length; ++i)
      f1ap_msg->srbs_to_be_setup[i] = resp->srbs_to_be_setup[i];
  }
  if (resp->drbs_to_be_setup_length > 0) {
    DevAssert(resp->drbs_to_be_setup != NULL);
    f1ap_msg->drbs_to_be_setup_length = resp->drbs_to_be_setup_length;
    f1ap_msg->drbs_to_be_setup = calloc(f1ap_msg->drbs_to_be_setup_length, sizeof(*f1ap_msg->drbs_to_be_setup));
    for (int i = 0; i < f1ap_msg->drbs_to_be_setup_length; ++i)
      f1ap_msg->drbs_to_be_setup[i] = resp->drbs_to_be_setup[i];
  }

  f1ap_msg->du_to_cu_rrc_information = malloc(sizeof(*resp->du_to_cu_rrc_information));
  AssertFatal(f1ap_msg->du_to_cu_rrc_information != NULL, "out of memory\n");
  f1ap_msg->du_to_cu_rrc_information_length = resp->du_to_cu_rrc_information_length;
  du_to_cu_rrc_information_t *du2cu = f1ap_msg->du_to_cu_rrc_information;
  du2cu->cellGroupConfig_length = resp->du_to_cu_rrc_information->cellGroupConfig_length;
  du2cu->cellGroupConfig = calloc(du2cu->cellGroupConfig_length, sizeof(*du2cu->cellGroupConfig));
  AssertFatal(du2cu->cellGroupConfig != NULL, "out of memory\n");
  memcpy(du2cu->cellGroupConfig, resp->du_to_cu_rrc_information->cellGroupConfig, du2cu->cellGroupConfig_length);

  itti_send_msg_to_task(TASK_DU_F1, 0, msg);
}

static void ue_context_modification_response_f1ap(const f1ap_ue_context_modif_req_t *req, const f1ap_ue_context_modif_resp_t *resp)
{
  MessageDef *msg = itti_alloc_new_message(TASK_MAC_GNB, 0, F1AP_UE_CONTEXT_MODIFICATION_RESP);
  f1ap_ue_context_modif_resp_t *f1ap_msg = &F1AP_UE_CONTEXT_MODIFICATION_RESP(msg);
  /* copy all fields, but reallocate rrc_containers! */
  *f1ap_msg = *resp;

  if (resp->srbs_to_be_setup_length > 0) {
    DevAssert(resp->srbs_to_be_setup != NULL);
    f1ap_msg->srbs_to_be_setup_length = resp->srbs_to_be_setup_length;
    f1ap_msg->srbs_to_be_setup = calloc(f1ap_msg->srbs_to_be_setup_length, sizeof(*f1ap_msg->srbs_to_be_setup));
    for (int i = 0; i < f1ap_msg->srbs_to_be_setup_length; ++i)
      f1ap_msg->srbs_to_be_setup[i] = resp->srbs_to_be_setup[i];
  }
  if (resp->drbs_to_be_setup_length > 0) {
    DevAssert(resp->drbs_to_be_setup != NULL);
    f1ap_msg->drbs_to_be_setup_length = resp->drbs_to_be_setup_length;
    f1ap_msg->drbs_to_be_setup = calloc(f1ap_msg->drbs_to_be_setup_length, sizeof(*f1ap_msg->drbs_to_be_setup));
    for (int i = 0; i < f1ap_msg->drbs_to_be_setup_length; ++i)
      f1ap_msg->drbs_to_be_setup[i] = resp->drbs_to_be_setup[i];
  }

  if (resp->du_to_cu_rrc_information != NULL) {
    f1ap_msg->du_to_cu_rrc_information = calloc(1, sizeof(*resp->du_to_cu_rrc_information));
    AssertFatal(f1ap_msg->du_to_cu_rrc_information != NULL, "out of memory\n");
    f1ap_msg->du_to_cu_rrc_information_length = resp->du_to_cu_rrc_information_length;
    du_to_cu_rrc_information_t *du2cu = f1ap_msg->du_to_cu_rrc_information;
    du2cu->cellGroupConfig_length = resp->du_to_cu_rrc_information->cellGroupConfig_length;
    du2cu->cellGroupConfig = calloc(du2cu->cellGroupConfig_length, sizeof(*du2cu->cellGroupConfig));
    AssertFatal(du2cu->cellGroupConfig != NULL, "out of memory\n");
    memcpy(du2cu->cellGroupConfig, resp->du_to_cu_rrc_information->cellGroupConfig, du2cu->cellGroupConfig_length);
  }

  itti_send_msg_to_task(TASK_DU_F1, 0, msg);
}

static void ue_context_modification_required_f1ap(const f1ap_ue_context_modif_required_t *required)
{
  MessageDef *msg = itti_alloc_new_message(TASK_MAC_GNB, 0, F1AP_UE_CONTEXT_MODIFICATION_REQUIRED);
  f1ap_ue_context_modif_required_t *f1ap_msg = &F1AP_UE_CONTEXT_MODIFICATION_REQUIRED(msg);
  f1ap_msg->gNB_CU_ue_id = required->gNB_CU_ue_id;
  f1ap_msg->gNB_DU_ue_id = required->gNB_DU_ue_id;
  f1ap_msg->du_to_cu_rrc_information = NULL;
  if (required->du_to_cu_rrc_information != NULL) {
    f1ap_msg->du_to_cu_rrc_information = calloc(1, sizeof(*f1ap_msg->du_to_cu_rrc_information));
    AssertFatal(f1ap_msg->du_to_cu_rrc_information != NULL, "out of memory\n");
    du_to_cu_rrc_information_t *du2cu = f1ap_msg->du_to_cu_rrc_information;
    AssertFatal(required->du_to_cu_rrc_information->cellGroupConfig != NULL && required->du_to_cu_rrc_information->cellGroupConfig_length > 0,
                "cellGroupConfig is mandatory\n");
    du2cu->cellGroupConfig_length = required->du_to_cu_rrc_information->cellGroupConfig_length;
    du2cu->cellGroupConfig = malloc(du2cu->cellGroupConfig_length * sizeof(*du2cu->cellGroupConfig));
    AssertFatal(du2cu->cellGroupConfig != NULL, "out of memory\n");
    memcpy(du2cu->cellGroupConfig, required->du_to_cu_rrc_information->cellGroupConfig, du2cu->cellGroupConfig_length);
    AssertFatal(required->du_to_cu_rrc_information->measGapConfig == NULL && required->du_to_cu_rrc_information->measGapConfig_length == 0, "not handled yet\n");
    AssertFatal(required->du_to_cu_rrc_information->requestedP_MaxFR1 == NULL && required->du_to_cu_rrc_information->requestedP_MaxFR1_length == 0, "not handled yet\n");
  }
  f1ap_msg->cause = required->cause;
  f1ap_msg->cause_value = required->cause_value;
  itti_send_msg_to_task(TASK_DU_F1, 0, msg);
}

static void ue_context_release_request_f1ap(const f1ap_ue_context_release_req_t* req)
{
  MessageDef *msg = itti_alloc_new_message(TASK_MAC_GNB, 0, F1AP_UE_CONTEXT_RELEASE_REQ);
  f1ap_ue_context_release_req_t *f1ap_msg = &F1AP_UE_CONTEXT_RELEASE_REQ(msg);
  *f1ap_msg = *req;
  itti_send_msg_to_task(TASK_DU_F1, 0, msg);
}

static void ue_context_release_complete_f1ap(const f1ap_ue_context_release_complete_t *complete)
{
  newGtpuDeleteAllTunnels(0, complete->gNB_DU_ue_id);

  MessageDef *msg = itti_alloc_new_message(TASK_MAC_GNB, 0, F1AP_UE_CONTEXT_RELEASE_COMPLETE);
  f1ap_ue_context_release_complete_t *f1ap_msg = &F1AP_UE_CONTEXT_RELEASE_COMPLETE(msg);
  *f1ap_msg = *complete;
  itti_send_msg_to_task(TASK_DU_F1, 0, msg);
}

static void initial_ul_rrc_message_transfer_f1ap(module_id_t module_id, const f1ap_initial_ul_rrc_message_t *ul_rrc)
{
  MessageDef *msg = itti_alloc_new_message(TASK_MAC_GNB, 0, F1AP_INITIAL_UL_RRC_MESSAGE);
  /* copy all fields, but reallocate rrc_containers! */
  f1ap_initial_ul_rrc_message_t *f1ap_msg = &F1AP_INITIAL_UL_RRC_MESSAGE(msg);
  *f1ap_msg = *ul_rrc;

  f1ap_msg->rrc_container = malloc(ul_rrc->rrc_container_length);
  DevAssert(f1ap_msg->rrc_container);
  memcpy(f1ap_msg->rrc_container, ul_rrc->rrc_container, ul_rrc->rrc_container_length);
  f1ap_msg->rrc_container_length = ul_rrc->rrc_container_length;

  f1ap_msg->du2cu_rrc_container = malloc(ul_rrc->du2cu_rrc_container_length);
  DevAssert(f1ap_msg->du2cu_rrc_container);
  memcpy(f1ap_msg->du2cu_rrc_container, ul_rrc->du2cu_rrc_container, ul_rrc->du2cu_rrc_container_length);
  f1ap_msg->du2cu_rrc_container_length = ul_rrc->du2cu_rrc_container_length;

  itti_send_msg_to_task(TASK_DU_F1, module_id, msg);
}

void mac_rrc_ul_f1ap_init(struct nr_mac_rrc_ul_if_s *mac_rrc)
{
  mac_rrc->f1_reset = f1_reset_du_initiated_f1ap;
  mac_rrc->f1_reset_acknowledge = f1_reset_acknowledge_cu_initiated_f1ap;
  mac_rrc->f1_setup_request = f1_setup_request_f1ap;
  mac_rrc->gnb_du_configuration_update = gnb_du_configuration_update_f1ap;
  mac_rrc->ue_context_setup_response = ue_context_setup_response_f1ap;
  mac_rrc->ue_context_modification_response = ue_context_modification_response_f1ap;
  mac_rrc->ue_context_modification_required = ue_context_modification_required_f1ap;
  mac_rrc->ue_context_release_request = ue_context_release_request_f1ap;
  mac_rrc->ue_context_release_complete = ue_context_release_complete_f1ap;
  mac_rrc->initial_ul_rrc_message_transfer = initial_ul_rrc_message_transfer_f1ap;
}

