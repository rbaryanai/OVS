/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014, 2016, 2017 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>
#include "netdev-rte-offloads.h"
#include "netdev-offload-api.h"
#include "fatal-signal.h"
#include "netdev-provider.h"
#include "netdev-vport.h"
#include "odp-util.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/list.h"
#include "openvswitch/ofp-print.h"
#include "openvswitch/vlog.h"
#include "openvswitch/match.h"
#include "openvswitch/netdev.h"
#include "openvswitch/types.h"
#include "openvswitch/thread.h"
#include "cmap.h"
#include "netdev-dpdk.h"
#include "id-pool.h"
#include "uuid.h"
#include "netdev.h"
#include <rte_flow.h>


VLOG_DEFINE_THIS_MODULE(netdev_rte_offload);

#define RTE_FLOW_MAX_TABLES (31)
#define HW_OFFLOAD_MAX_PHY (128)
#define INVALID_ODP_PORT (-1)

struct rte_flow;
struct netdev_rte_port ;

static int netdev_dpdk_validate_flow(const struct match *match);
static struct rte_flow * 
netdev_dpdk_add_rte_flow_offload(struct netdev_rte_port * rte_port,struct netdev *netdev,
                                 const struct match *match,
                                 struct nlattr *nl_actions OVS_UNUSED,
                                 size_t actions_len OVS_UNUSED,
                                 const ovs_u128 *ufid,
                                 struct offload_info *info);


struct netdev_rte_offload_table_ids {
    struct ovs_mutex mutex;
    struct id_pool * table_id_pool;
    struct id_pool * mark_pool;
};

static struct netdev_rte_offload_table_ids netdev_rte_offload_table_id = {
    .mutex = OVS_MUTEX_INITIALIZER,
    .table_id_pool = NULL,
    .mark_pool = NULL
};

enum rte_port_type {
     RTE_PORT_TYPE_NONE,
     RTE_PORT_TYPE_DPDK,
     RTE_PORT_TYPE_VXLAN
};

/**
 * @brief - struct for holding table represntation of a vport flows.
 */
struct netdev_rte_port {
  struct cmap_node node;      // map by port_no
  odp_port_t  port_no;

  struct cmap_node all_node;  // map by netdev
  struct netdev * netdev;

  enum rte_port_type rte_port_type;
  uint32_t    table_id;
  uint16_t    dpdk_port_id;

  uint32_t    special_mark;
  struct rte_flow * default_rte_flow;

  struct cmap ufid_to_rte;   // map of fuid to all the matching rte_flows 
};

struct rte_flow_data {
     struct rte_flow * flow;
     uint16_t          port_id;
};

struct ufid_hw_offload {
    struct cmap_node node;
    int max_flows;
    int curr_idx;
    ovs_u128 ufid;
    struct rte_flow_data rte_flow_data[1];
}; 

static struct cmap vport_map = CMAP_INITIALIZER;

static struct cmap dpdk_map = CMAP_INITIALIZER;

static struct cmap rte_port_by_netdev = CMAP_INITIALIZER; // in some cases such as when deleting flows we have only netdev, no port number.


struct ufid_to_odp {
    struct cmap_node node;
    ovs_u128 ufid;
    odp_port_t port_no;
};


static struct cmap ufid_to_portid_map = CMAP_INITIALIZER; // in some cases such as when deleting flows we have only netdev, no port number

static struct ufid_to_odp * ufid_to_portid_get(const ovs_u128 * ufid)
{
    size_t hash = hash_bytes(ufid, sizeof(*ufid), 0);
    struct ufid_to_odp * data;

    CMAP_FOR_EACH_WITH_HASH (data, node, hash, &ufid_to_portid_map) {
        if (ovs_u128_equals(*ufid, data->ufid)) {
            return data;
        }
    }

    return NULL;
}



static odp_port_t ufid_to_portid_search(const ovs_u128 * ufid)
{
   struct ufid_to_odp * data = ufid_to_portid_get(ufid);

   return (data != NULL)?data->port_no:INVALID_ODP_PORT;
}


static odp_port_t ufid_to_portid_add(const ovs_u128 * ufid, odp_port_t port_no)
{
    size_t hash = hash_bytes(ufid, sizeof(*ufid), 0);
    struct ufid_to_odp * data;

    if(ufid_to_portid_search(ufid) != INVALID_ODP_PORT){
        return port_no;
    }

    data = xzalloc(sizeof(*data));

    if(data == NULL){
        VLOG_WARN("failed to add fuid to odp, OOM");
        return INVALID_ODP_PORT;
    }

    data->ufid = *ufid;
    data->port_no = port_no;

    cmap_insert(&ufid_to_portid_map,
                CONST_CAST(struct cmap_node *, &data->node), hash);

    return port_no;
}

static void ufid_to_portid_remove(const ovs_u128 * ufid)
{
    size_t hash = hash_bytes(ufid, sizeof(*ufid), 0);
    struct ufid_to_odp * data = ufid_to_portid_get(ufid);

    if(data != NULL){
        cmap_remove(&ufid_to_portid_map,
                        CONST_CAST(struct cmap_node *, &data->node),
                        hash);
        free(data);
    }


    return;
}

/**
 * @brief - allocate RTE_FLOW table from id pool.
 *
 * @param id - OUR
 * @return true on success and false on failure.
 */
static bool netdev_rte_alloc_reserved_mark(uint32_t *id)
{
    bool ret;

    // ids can be allocated on different triggers (but few), so we must protect.
    ovs_mutex_lock(&netdev_rte_offload_table_id.mutex);

    if(netdev_rte_offload_table_id.mark_pool == NULL){
        netdev_rte_offload_table_id.mark_pool = id_pool_create(1, OFFLOAD_RESERVED_MARK);
        if(netdev_rte_offload_table_id.mark_pool == NULL){
            VLOG_WARN("failed to allocate pool for rte table id");
            ovs_mutex_unlock(&netdev_rte_offload_table_id.mutex);
            return false;
        }
    }

    ret = id_pool_alloc_id(netdev_rte_offload_table_id.mark_pool, id);
    ovs_mutex_unlock(&netdev_rte_offload_table_id.mutex);
    
    return ret;
}

/**
 * @brief - allocate RTE_FLOW table from id pool.
 *
 * @param id - OUR
 * @return true on success and false on failure.
 */
static bool netdev_rte_alloc_table_id(uint32_t *id)
{
    bool ret;

    // ids can be allocated on different triggers (but few), so we must protect.
    ovs_mutex_lock(&netdev_rte_offload_table_id.mutex);

    if(netdev_rte_offload_table_id.table_id_pool == NULL){
        netdev_rte_offload_table_id.table_id_pool = id_pool_create(0, RTE_FLOW_MAX_TABLES);
        if(netdev_rte_offload_table_id.table_id_pool == NULL){
            VLOG_WARN("failed to allocate pool for rte table id");
            ovs_mutex_unlock(&netdev_rte_offload_table_id.mutex);
            return false;
        }
    }

    ret = id_pool_alloc_id(netdev_rte_offload_table_id.table_id_pool, id);
    ovs_mutex_unlock(&netdev_rte_offload_table_id.mutex);
    
    return ret;
}


static void netdev_rte_free_table_id(uint32_t id)
{

    // ids can be allocated on different triggers (but few), so we must protect.
    ovs_mutex_lock(&netdev_rte_offload_table_id.mutex);
    ovs_assert(netdev_rte_offload_table_id.table_id_pool != NULL);

    if(netdev_rte_offload_table_id.table_id_pool != NULL){
        id_pool_free_id( netdev_rte_offload_table_id.table_id_pool, id);
    }

    ovs_mutex_unlock(&netdev_rte_offload_table_id.mutex);
    
    return;
}

/**
 * @brief - fuid hw offload struct contains array of pointers to RTE FLOWS.
 *  in case of vxlan offload we need rule per phy port. in other cases we might need only one.
 *
 * @param size  - number of expected max rte for this fuids. 
 * @param ufid  - the fuid
 *
 * @return new struct on NULL if OOM
 */
static struct ufid_hw_offload * netdev_rte_port_ufid_hw_offload_alloc(int size, const ovs_u128 * ufid)
{
    struct ufid_hw_offload * ret = xzalloc(sizeof(struct  ufid_hw_offload) + sizeof(struct rte_flow_data) * size);
    if(ret != NULL){
        ret->max_flows = size;
        ret->curr_idx = 0;
        ret->ufid = *ufid;
    }

    return ret;
}

/**
 * @brief - if hw rules were interducedm we make sure we clean them before we free the struct.
 *
 * @param hw_offload
 */
static int netdev_rte_port_ufid_hw_offload_free(struct ufid_hw_offload * hw_offload)
{
    VLOG_DBG("clean all rte flows for fuid "UUID_FMT" \n", UUID_ARGS((struct uuid *)&hw_offload->ufid));

    for(int i = 0 ; i < hw_offload->curr_idx ; i++){
    // TODO: free RTE object
        if(hw_offload->rte_flow_data[i].flow != NULL){
            struct rte_flow_error error;
            int ret;
            ret = rte_flow_destroy(hw_offload->rte_flow_data[i].port_id, 
                        hw_offload->rte_flow_data[i].flow, &error);

            VLOG_DBG("rte_destory for flow "UUID_FMT" on port %d, was called",UUID_ARGS((struct uuid *)&hw_offload->ufid),hw_offload->rte_flow_data[i].port_id );

            // TODO: think better what we do here.
            if (ret != 0) {
                VLOG_ERR("rte flow destroy error: %u : message : %s\n",
                     error.type, error.message);
                return ret;

            }
        }

        hw_offload->rte_flow_data[i].flow = NULL;
    }      

    free(hw_offload);
    return 0;
}


/**
 * vport conaines a hash with data that also should be cleaned.
 *
 **/
static void netdev_rte_port_clean_all(struct netdev_rte_port * rte_vport)
{
     //TODO: CLEAN ALL INSIDE DATA
    struct cmap_cursor cursor;
    struct ufid_hw_offload * data;

    CMAP_CURSOR_FOR_EACH (data, node, &cursor, &rte_vport->ufid_to_rte) {
        netdev_rte_port_ufid_hw_offload_free(data);
    }

    return;
}

/*static struct netdev_rte_port * netdev_rte_port_search_by_netdev(struct netdev * netdev)
{
    size_t hash = hash_bytes(&netdev, sizeof(struct netdev *), 0);
    struct netdev_rte_port * rte_port = NULL;

    CMAP_FOR_EACH_WITH_HASH (rte_port, all_node, hash, &rte_port_by_netdev) {
        if ( rte_port->netdev ==  netdev) {
            return rte_port;
        }
    }

    return NULL;
}*/

/**
 * @brief - release the rte_port.
 *   rte_port might contain refrences to offloaded rte_flow's that should be cleaned.
 *
 * @param rte_port
 */
static void netdev_rte_port_free(struct netdev_rte_port * rte_port)
{
    size_t hash     = hash_bytes(&rte_port->port_no, sizeof(odp_port_t), 0);
    size_t hash_all = hash_bytes(&rte_port->netdev, sizeof(struct netdev *), 0);

    netdev_rte_port_clean_all(rte_port);
    cmap_remove(&rte_port_by_netdev,
                        CONST_CAST(struct cmap_node *, &rte_port->all_node),
                        hash_all);

    switch(rte_port->rte_port_type){
        case RTE_PORT_TYPE_VXLAN:
            VLOG_DBG("remove vlxan port %d",rte_port->port_no);
            cmap_remove(&vport_map,
                        CONST_CAST(struct cmap_node *, &rte_port->node), hash);
            netdev_rte_free_table_id(rte_port->table_id);
            break;
        case RTE_PORT_TYPE_DPDK:
            VLOG_DBG("remove dpdk port %d",rte_port->port_no);
            cmap_remove(&dpdk_map,
                        CONST_CAST(struct cmap_node *, &rte_port->node), hash);
            break;
        case RTE_PORT_TYPE_NONE:
            // nothig
            break;
    }

   free(rte_port);
   return;
}

/**
 * @brief - allocate new rte_port.
 *   all rte ports are kept in map by netdev, and are kept per thier type in another map.
 *   in offload flows we have only the port_id, and flow del we have only the netdev.
 *
 * @param port_no  
 * @param netdev
 * @param map        - specific map by type, dpdk, vport..etc.
 *
 * @return the new allocated port. already initialized for common params.
 */
static struct netdev_rte_port * netdev_rte_port_alloc(odp_port_t port_no, struct netdev * netdev, struct cmap * map)
{
    size_t hash = hash_bytes(&port_no, sizeof(odp_port_t), 0);
    size_t hash_all = hash_bytes(&netdev, sizeof(struct netdev *), 0);
    struct netdev_rte_port * ret_port = xzalloc(sizeof(struct netdev_rte_port));

    if(ret_port == NULL){
      VLOG_ERR("failed to alloctae ret_port, OOM");
      return NULL;
    }
   
   memset(ret_port,0,sizeof(*ret_port));
   ret_port->port_no = port_no;
   ret_port->netdev  = netdev;
   ret_port->default_rte_flow = NULL;
   cmap_init(&ret_port->ufid_to_rte);

   cmap_insert(map,
                CONST_CAST(struct cmap_node *, &ret_port->node), hash);
   cmap_insert(&rte_port_by_netdev,
                CONST_CAST(struct cmap_node *, &ret_port->all_node), hash_all);


   return ret_port;
}


/**
 * search for offloaed voprt by odp port no.
 *
 **/
static struct netdev_rte_port * netdev_rte_port_search(odp_port_t port_no, struct cmap * map)
{
    size_t hash = hash_bytes(&port_no, sizeof(odp_port_t), 0);
    struct netdev_rte_port * data;

    VLOG_DBG("search for port %d",port_no);

    CMAP_FOR_EACH_WITH_HASH (data, node, hash, map) {
        if ( port_no ==  data->port_no) {
            return data;
        }
    }

    return NULL;
}

/**
 * @brief 0 find hw_offload of specific fuid.
 *
 * @param ufid   
 * @param map    - map is bounded to interface
 *
 * @return if found on NULL if doesn't exists.
 */
static struct ufid_hw_offload * ufid_hw_offload_find(const ovs_u128 *ufid, struct cmap * map)
{
    size_t hash = hash_bytes(ufid, sizeof(*ufid), 0);
    struct ufid_hw_offload * data;

    CMAP_FOR_EACH_WITH_HASH (data, node, hash, map) {
        if (ovs_u128_equals(*ufid, data->ufid)) {
            return data;
        }
    }

    return NULL;
}


static struct ufid_hw_offload * ufid_hw_offload_remove(const ovs_u128 *ufid, struct cmap * map)
{
    size_t hash = hash_bytes(ufid, sizeof(*ufid), 0);
    struct ufid_hw_offload * data = ufid_hw_offload_find(ufid,map);

    if(data != NULL){
        cmap_remove(map, CONST_CAST(struct cmap_node *, &data->node),
                        hash);

    }
    return data;
}

static void ufid_hw_offload_add(struct ufid_hw_offload * hw_offload, struct cmap * map)
{
    size_t hash = hash_bytes(&hw_offload->ufid, sizeof(ovs_u128), 0);

    cmap_insert(map,
                CONST_CAST(struct cmap_node *, &hw_offload->node), hash);

    return;
}

static void ufid_hw_offload_add_rte_flow(struct ufid_hw_offload * hw_offload, 
                                         struct rte_flow * rte_flow, 
                                         int dpdk_port_id)
{
    if(hw_offload->curr_idx < hw_offload->max_flows){
        hw_offload->rte_flow_data[hw_offload->curr_idx].flow = rte_flow;
        hw_offload->rte_flow_data[hw_offload->curr_idx].port_id = dpdk_port_id;
        hw_offload->curr_idx++;
    } else {
        struct rte_flow_error error;
        int ret;
        ret = rte_flow_destroy(dpdk_port_id, rte_flow, &error);
        if (ret != 0) {
                VLOG_ERR("rte flow destroy error: %u : message : %s\n",
                     error.type, error.message);
        }
        VLOG_WARN("failed to add rte_flow, releasing");
    }
    return;
}

static int netdev_rte_port_offload_vxlan(struct netdev_rte_port * rte_port, struct netdev * netdev OVS_UNUSED, struct match * match OVS_UNUSED,
                       struct nlattr *actions OVS_UNUSED, size_t actions_len OVS_UNUSED,
                       const ovs_u128 * ufid , struct offload_info * info OVS_UNUSED,
                       struct dpif_flow_stats * flow_stats  OVS_UNUSED)
{

    int n_phy = (int) cmap_count(&dpdk_map);
    struct ufid_hw_offload * ufid_hw_offload = ufid_hw_offload_find(ufid, &rte_port->ufid_to_rte);
    //struct rte_flow * rte_flow;

    if(ufid_hw_offload != NULL){
        //TODO: what to do on modificaiton
        VLOG_WARN("got modification. not supprted");
        return 0; // return success because we don't remove the flow yet.
    }

    if(n_phy < 1 || n_phy > HW_OFFLOAD_MAX_PHY){
        VLOG_WARN("offload while no phy ports %d",(int)n_phy);
        return -1;
    }

    ufid_hw_offload = netdev_rte_port_ufid_hw_offload_alloc(n_phy, ufid);  
    if(ufid_hw_offload == NULL){
        VLOG_WARN("failed to alloctae ufid_hw_offlaod, OOM");
        return -1;
    }

    for(int i = 0 ; i < n_phy ; i++){
        //struct rte_flow * dummy = dummy_rte_flow_alloc();
        //dummy->ufid = *ufid;
        //ufid_hw_offload_insert(ufid_hw_offload, dummy);
    }

    ufid_hw_offload_add(ufid_hw_offload, &rte_port->ufid_to_rte);
    ufid_to_portid_add(ufid, rte_port->port_no);
    
    return 0;
}


int netdev_vport_flow_put(struct netdev * netdev OVS_UNUSED, struct match * match,
                       struct nlattr *actions OVS_UNUSED, size_t actions_len OVS_UNUSED,
                       const ovs_u128 * ufid , struct offload_info * info OVS_UNUSED,
                       struct dpif_flow_stats * flow_stats  OVS_UNUSED)
{
    odp_port_t in_port = match->flow.in_port.odp_port;   
    struct netdev_rte_port * rte_port = netdev_rte_port_search(in_port, &vport_map);
    
    if ( netdev_dpdk_validate_flow(match) ){
        return -1;
    }

    if(rte_port != NULL){
         switch(rte_port->rte_port_type){
             case RTE_PORT_TYPE_VXLAN:
                   //TODO called the offload code.
                   VLOG_DBG("vxlan offload ufid"UUID_FMT" \n", UUID_ARGS((struct uuid *)ufid));
                   netdev_rte_port_offload_vxlan(rte_port, netdev, match, actions, actions_len ,
                       ufid , info ,flow_stats  );
                   break;
             case RTE_PORT_TYPE_DPDK:
                   VLOG_WARN("offload of vport could on dpdk port");
                   return -1;
             case RTE_PORT_TYPE_NONE:
             default:
                  VLOG_DBG("unsupported tunnel type");
             return -1;
         }
    }

    return 0;
}


int netdev_vport_flow_del(struct netdev * netdev OVS_UNUSED, const ovs_u128 * ufid ,
                        struct dpif_flow_stats * flow_stats OVS_UNUSED)
{
    struct netdev_rte_port * rte_port;
    odp_port_t port_no = ufid_to_portid_search(ufid);
    struct ufid_hw_offload * ufid_hw_offload;

    if(port_no == INVALID_ODP_PORT){
        VLOG_ERR("could not find port.");
        return -1;
    }

    rte_port = netdev_rte_port_search(port_no,&vport_map);

    ufid_to_portid_remove(ufid);

    ufid_hw_offload = ufid_hw_offload_remove(ufid, &rte_port->ufid_to_rte);
    if(ufid_hw_offload){
        netdev_rte_port_ufid_hw_offload_free(ufid_hw_offload );
    }

    return 0;
}
int netdev_vport_init_flow_api(struct netdev * netdev OVS_UNUSED)
{
            return 0;
}

/**
 * @brief - called when dpif netdev is added to the DPIF. 
 *    we create rte_port for the netdev is hw-offload can be supported.
 *
 * @param dp_port
 * @param netdev
 *
 * @return 0 on success 
 */
int netdev_rte_offload_add_port(odp_port_t dp_port, struct netdev * netdev)
{
    const char *type = netdev_get_type(netdev);

    if( netdev_vport_is_vport_class(netdev->netdev_class)){
         
         struct netdev_rte_port * rte_vport = netdev_rte_port_search(dp_port, &vport_map);
         if(rte_vport == NULL){
            uint32_t table_id;
            uint32_t mark;
            enum rte_port_type rte_port_type = RTE_PORT_TYPE_NONE;

            if(!strcmp("vxlan", type)){
                rte_port_type = RTE_PORT_TYPE_VXLAN;
            } else {
                VLOG_WARN("type %s is not supported currently", type);
                return -1;
            }
            if(!netdev_rte_alloc_table_id(&table_id)){
                VLOG_WARN("failed to allocate table id for vport %d",dp_port);
                return -1;
            }

            if(!netdev_rte_alloc_reserved_mark(&mark)){
                VLOG_WARN("failed to allocate mark for vport %d",dp_port);
                return -1;

            }

            rte_vport = netdev_rte_port_alloc(dp_port, netdev, &vport_map);
            rte_vport->rte_port_type = rte_port_type;
            rte_vport->table_id      = table_id;
            rte_vport->special_mark  = mark;
           
            VLOG_INFO("rte port for vport %d allocated, table id %d", dp_port, table_id); 
            
         }

         return 0;
    }

    if (netdev_dpdk_is_dpdk_class(netdev->netdev_class)){
        struct netdev_rte_port * rte_vport = netdev_rte_port_search(dp_port, &dpdk_map);
        if(rte_vport == NULL){
            enum rte_port_type rte_port_type = RTE_PORT_TYPE_NONE;

            if(!strcmp("dpdk", type)){ 
                rte_port_type = RTE_PORT_TYPE_DPDK;
            } else {
                VLOG_WARN("type %s offload is not supported currently",type);
                return -1;
            }

            rte_vport = netdev_rte_port_alloc(dp_port, netdev, &dpdk_map);
            rte_vport->rte_port_type = rte_port_type;
            rte_vport->dpdk_port_id = netdev_dpdk_get_port_id(netdev);
           
            VLOG_INFO("rte_port allocated dpdk port %d, dpdk port id %d",dp_port, netdev_dpdk_get_port_id(netdev)); 
            
         }
        return 0;
    }

    VLOG_INFO("port %s is not supported",type);

    return 0;
}

static struct netdev_rte_port * netdev_rte_port_search_by_port_no(odp_port_t port_no)
{
    struct netdev_rte_port * rte_port = NULL;

    rte_port = netdev_rte_port_search(port_no,  &vport_map);
    if(rte_port == NULL){
        rte_port = netdev_rte_port_search(port_no,  &dpdk_map);
    }

    return rte_port;
}

int netdev_rte_offload_del_port(odp_port_t port_no)
{
      struct netdev_rte_port * rte_port = netdev_rte_port_search_by_port_no(port_no);
      if(rte_port == NULL){
        VLOG_WARN("port %d has no rte_port",port_no);
        return -1;
      }

      netdev_rte_port_free(rte_port);
      return 0;
}


// RTE_FLOW


/*
 * To avoid individual xrealloc calls for each new element, a 'curent_max'
 * is used to keep track of current allocated number of elements. Starts
 * by 8 and doubles on each xrealloc call
 */
struct flow_patterns {
    struct rte_flow_item *items;
    int cnt;
    int current_max;
};

struct flow_actions {
    struct rte_flow_action *actions;
    int cnt;
    int current_max;
};

static void
dump_flow_pattern(struct rte_flow_item *item)
{
    if (item->type == RTE_FLOW_ITEM_TYPE_ETH) {
        const struct rte_flow_item_eth *eth_spec = item->spec;
        const struct rte_flow_item_eth *eth_mask = item->mask;

        VLOG_DBG("rte flow eth pattern:\n");
        if (eth_spec) {
            VLOG_DBG("  Spec: src="ETH_ADDR_FMT", dst="ETH_ADDR_FMT", "
                     "type=0x%04" PRIx16"\n",
                     ETH_ADDR_BYTES_ARGS(eth_spec->src.addr_bytes),
                     ETH_ADDR_BYTES_ARGS(eth_spec->dst.addr_bytes),
                     ntohs(eth_spec->type));
        } else {
            VLOG_DBG("  Spec = null\n");
        }
        if (eth_mask) {
            VLOG_DBG("  Mask: src="ETH_ADDR_FMT", dst="ETH_ADDR_FMT", "
                     "type=0x%04"PRIx16"\n",
                     ETH_ADDR_BYTES_ARGS(eth_mask->src.addr_bytes),
                     ETH_ADDR_BYTES_ARGS(eth_mask->dst.addr_bytes),
                     eth_mask->type);
        } else {
            VLOG_DBG("  Mask = null\n");
        }
    }

    if (item->type == RTE_FLOW_ITEM_TYPE_VLAN) {
        const struct rte_flow_item_vlan *vlan_spec = item->spec;
        const struct rte_flow_item_vlan *vlan_mask = item->mask;

        VLOG_DBG("rte flow vlan pattern:\n");
        if (vlan_spec) {
            VLOG_DBG("  Spec: tpid=0x%"PRIx16", tci=0x%"PRIx16"\n",
                     ntohs(vlan_spec->tpid), ntohs(vlan_spec->tci));
        } else {
            VLOG_DBG("  Spec = null\n");
        }

        if (vlan_mask) {
            VLOG_DBG("  Mask: tpid=0x%"PRIx16", tci=0x%"PRIx16"\n",
                     vlan_mask->tpid, vlan_mask->tci);
        } else {
            VLOG_DBG("  Mask = null\n");
        }
    }

    if (item->type == RTE_FLOW_ITEM_TYPE_IPV4) {
        const struct rte_flow_item_ipv4 *ipv4_spec = item->spec;
        const struct rte_flow_item_ipv4 *ipv4_mask = item->mask;

        VLOG_DBG("rte flow ipv4 pattern:\n");
        if (ipv4_spec) {
            VLOG_DBG("  Spec: tos=0x%"PRIx8", ttl=%"PRIx8", proto=0x%"PRIx8
                     ", src="IP_FMT", dst="IP_FMT"\n",
                     ipv4_spec->hdr.type_of_service,
                     ipv4_spec->hdr.time_to_live,
                     ipv4_spec->hdr.next_proto_id,
                     IP_ARGS(ipv4_spec->hdr.src_addr),
                     IP_ARGS(ipv4_spec->hdr.dst_addr));
        } else {
            VLOG_DBG("  Spec = null\n");
        }
        if (ipv4_mask) {
            VLOG_DBG("  Mask: tos=0x%"PRIx8", ttl=%"PRIx8", proto=0x%"PRIx8
                     ", src="IP_FMT", dst="IP_FMT"\n",
                     ipv4_mask->hdr.type_of_service,
                     ipv4_mask->hdr.time_to_live,
                     ipv4_mask->hdr.next_proto_id,
                     IP_ARGS(ipv4_mask->hdr.src_addr),
                     IP_ARGS(ipv4_mask->hdr.dst_addr));
        } else {
            VLOG_DBG("  Mask = null\n");
        }
    }

    if (item->type == RTE_FLOW_ITEM_TYPE_UDP) {
        const struct rte_flow_item_udp *udp_spec = item->spec;
        const struct rte_flow_item_udp *udp_mask = item->mask;

        VLOG_DBG("rte flow udp pattern:\n");
        if (udp_spec) {
            VLOG_DBG("  Spec: src_port=%"PRIu16", dst_port=%"PRIu16"\n",
                     ntohs(udp_spec->hdr.src_port),
                     ntohs(udp_spec->hdr.dst_port));
        } else {
            VLOG_DBG("  Spec = null\n");
        }
        if (udp_mask) {
            VLOG_DBG("  Mask: src_port=0x%"PRIx16", dst_port=0x%"PRIx16"\n",
                     udp_mask->hdr.src_port,
                     udp_mask->hdr.dst_port);
        } else {
            VLOG_DBG("  Mask = null\n");
        }
    }

    if (item->type == RTE_FLOW_ITEM_TYPE_SCTP) {
        const struct rte_flow_item_sctp *sctp_spec = item->spec;
        const struct rte_flow_item_sctp *sctp_mask = item->mask;

        VLOG_DBG("rte flow sctp pattern:\n");
        if (sctp_spec) {
            VLOG_DBG("  Spec: src_port=%"PRIu16", dst_port=%"PRIu16"\n",
                     ntohs(sctp_spec->hdr.src_port),
                     ntohs(sctp_spec->hdr.dst_port));
        } else {
            VLOG_DBG("  Spec = null\n");
        }
        if (sctp_mask) {
            VLOG_DBG("  Mask: src_port=0x%"PRIx16", dst_port=0x%"PRIx16"\n",
                     sctp_mask->hdr.src_port,
                     sctp_mask->hdr.dst_port);
        } else {
            VLOG_DBG("  Mask = null\n");
        }
    }

    if (item->type == RTE_FLOW_ITEM_TYPE_ICMP) {
        const struct rte_flow_item_icmp *icmp_spec = item->spec;
        const struct rte_flow_item_icmp *icmp_mask = item->mask;

        VLOG_DBG("rte flow icmp pattern:\n");
        if (icmp_spec) {
            VLOG_DBG("  Spec: icmp_type=%"PRIu8", icmp_code=%"PRIu8"\n",
                     icmp_spec->hdr.icmp_type,
                     icmp_spec->hdr.icmp_code);
        } else {
            VLOG_DBG("  Spec = null\n");
        }
        if (icmp_mask) {
            VLOG_DBG("  Mask: icmp_type=0x%"PRIx8", icmp_code=0x%"PRIx8"\n",
                     icmp_spec->hdr.icmp_type,
                     icmp_spec->hdr.icmp_code);
        } else {
            VLOG_DBG("  Mask = null\n");
        }
    }

    if (item->type == RTE_FLOW_ITEM_TYPE_TCP) {
        const struct rte_flow_item_tcp *tcp_spec = item->spec;
        const struct rte_flow_item_tcp *tcp_mask = item->mask;

        VLOG_DBG("rte flow tcp pattern:\n");
        if (tcp_spec) {
            VLOG_DBG("  Spec: src_port=%"PRIu16", dst_port=%"PRIu16
                     ", data_off=0x%"PRIx8", tcp_flags=0x%"PRIx8"\n",
                     ntohs(tcp_spec->hdr.src_port),
                     ntohs(tcp_spec->hdr.dst_port),
                     tcp_spec->hdr.data_off,
                     tcp_spec->hdr.tcp_flags);
        } else {
            VLOG_DBG("  Spec = null\n");
        }
        if (tcp_mask) {
            VLOG_DBG("  Mask: src_port=%"PRIx16", dst_port=%"PRIx16
                     ", data_off=0x%"PRIx8", tcp_flags=0x%"PRIx8"\n",
                     tcp_mask->hdr.src_port,
                     tcp_mask->hdr.dst_port,
                     tcp_mask->hdr.data_off,
                     tcp_mask->hdr.tcp_flags);
        } else {
            VLOG_DBG("  Mask = null\n");
        }
    }
}

static void
add_flow_pattern(struct flow_patterns *patterns, enum rte_flow_item_type type,
                 const void *spec, const void *mask) {
    int cnt = patterns->cnt;

    if (cnt == 0) {
        patterns->current_max = 8;
        patterns->items = xcalloc(patterns->current_max,
                                  sizeof(struct rte_flow_item));
    } else if (cnt == patterns->current_max) {
        patterns->current_max *= 2;
        patterns->items = xrealloc(patterns->items, patterns->current_max *
                                   sizeof(struct rte_flow_item));
    }

    patterns->items[cnt].type = type;
    patterns->items[cnt].spec = spec;
    patterns->items[cnt].mask = mask;
    patterns->items[cnt].last = NULL;
    dump_flow_pattern(&patterns->items[cnt]);
    patterns->cnt++;
}

static void
add_flow_action(struct flow_actions *actions, enum rte_flow_action_type type,
                const void *conf)
{
    int cnt = actions->cnt;

    if (cnt == 0) {
        actions->current_max = 8;
        actions->actions = xcalloc(actions->current_max,
                                   sizeof(struct rte_flow_action));
    } else if (cnt == actions->current_max) {
        actions->current_max *= 2;
        actions->actions = xrealloc(actions->actions, actions->current_max *
                                    sizeof(struct rte_flow_action));
    }

    actions->actions[cnt].type = type;
    actions->actions[cnt].conf = conf;
    actions->cnt++;
}

static struct rte_flow_action_rss *
add_flow_rss_action(struct flow_actions *actions,
                    struct netdev *netdev) {
    int i;
    struct rte_flow_action_rss *rss;

    rss = xmalloc(sizeof(*rss) + sizeof(uint16_t) * netdev->n_rxq);
    /*
     * Setting it to NULL will let the driver use the default RSS
     * configuration we have set: &port_conf.rx_adv_conf.rss_conf.
     */
    rss->rss_conf = NULL;
    rss->num = netdev->n_rxq;

    for (i = 0; i < rss->num; i++) {
        rss->queue[i] = i;
    }

    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_RSS, rss);

    return rss;
}



static bool
is_all_zero(const void *addr, size_t n) {
    size_t i = 0;
    const uint8_t *p = (uint8_t *)addr;

    for (i = 0; i < n; i++) {
        if (p[i] != 0) {
            return false;
        }
    }

    return true;
}



/*
 * Check if any unsupported flow patterns are specified.
 */
static int
netdev_dpdk_validate_flow(const struct match *match) {
    struct match match_zero_wc;

    /* Create a wc-zeroed version of flow */
    match_init(&match_zero_wc, &match->flow, &match->wc);

    if (!is_all_zero(&match_zero_wc.flow.tunnel,
                     sizeof(match_zero_wc.flow.tunnel))) {
        VLOG_DBG("cannot hw offload because of flow.tunnel exists");
        goto err;
    }

    if (match->wc.masks.metadata ||
        match->wc.masks.skb_priority ||
        match->wc.masks.pkt_mark ||
        match->wc.masks.dp_hash) {
        goto err;
    }

    /* recirc id must be zero */
    if (match_zero_wc.flow.recirc_id) {
        goto err;
    }

    if (match->wc.masks.ct_state ||
        match->wc.masks.ct_nw_proto ||
        match->wc.masks.ct_zone ||
        match->wc.masks.ct_mark ||
        match->wc.masks.ct_label.u64.hi ||
        match->wc.masks.ct_label.u64.lo) {
        goto err;
    }

    if (match->wc.masks.conj_id ||
        match->wc.masks.actset_output) {
        goto err;
    }

    /* unsupported L2 */
    if (!is_all_zero(&match->wc.masks.mpls_lse,
                     sizeof(match_zero_wc.flow.mpls_lse))) {
        goto err;
    }

    /* unsupported L3 */
    if (match->wc.masks.ipv6_label ||
        match->wc.masks.ct_nw_src ||
        match->wc.masks.ct_nw_dst ||
        !is_all_zero(&match->wc.masks.ipv6_src, sizeof(struct in6_addr)) ||
        !is_all_zero(&match->wc.masks.ipv6_dst, sizeof(struct in6_addr)) ||
        !is_all_zero(&match->wc.masks.ct_ipv6_src, sizeof(struct in6_addr)) ||
        !is_all_zero(&match->wc.masks.ct_ipv6_dst, sizeof(struct in6_addr)) ||
        !is_all_zero(&match->wc.masks.nd_target, sizeof(struct in6_addr)) ||
        !is_all_zero(&match->wc.masks.nsh, sizeof(struct ovs_key_nsh)) ||
        !is_all_zero(&match->wc.masks.arp_sha, sizeof(struct eth_addr)) ||
        !is_all_zero(&match->wc.masks.arp_tha, sizeof(struct eth_addr))) {
        goto err;
    }

    /* If fragmented, then don't HW accelerate - for now */
    if (match_zero_wc.flow.nw_frag) {
        goto err;
    }

    /* unsupported L4 */
    if (match->wc.masks.igmp_group_ip4 ||
        match->wc.masks.ct_tp_src ||
        match->wc.masks.ct_tp_dst) {
        goto err;
    }

    return 0;

err:
    VLOG_ERR("cannot HW accelerate this flow due to unsupported protocols");
    return -1;
}

static struct rte_flow * 
netdev_dpdk_add_rte_flow_offload(struct netdev_rte_port * rte_port,struct netdev *netdev,
                                 const struct match *match,
                                 struct nlattr *nl_actions OVS_UNUSED,
                                 size_t actions_len OVS_UNUSED,
                                 const ovs_u128 *ufid,
                                 struct offload_info *info) {
    const struct rte_flow_attr flow_attr = {
        .group = 0,
        .priority = 0,
        .ingress = 1,
        .egress = 0
    };
    struct flow_patterns patterns = { .items = NULL, .cnt = 0 };
    struct flow_actions actions = { .actions = NULL, .cnt = 0 };
    struct rte_flow *flow = NULL;
    struct rte_flow_error error;
    uint8_t *ipv4_next_proto_mask = NULL;

    /* Eth */
    struct rte_flow_item_eth eth_spec;
    struct rte_flow_item_eth eth_mask;
    memset(&eth_spec, 0, sizeof(eth_spec));
    memset(&eth_mask, 0, sizeof(eth_mask));
    if (!eth_addr_is_zero(match->wc.masks.dl_src) ||
        !eth_addr_is_zero(match->wc.masks.dl_dst)) {
        rte_memcpy(&eth_spec.dst, &match->flow.dl_dst, sizeof(eth_spec.dst));
        rte_memcpy(&eth_spec.src, &match->flow.dl_src, sizeof(eth_spec.src));
        eth_spec.type = match->flow.dl_type;

        rte_memcpy(&eth_mask.dst, &match->wc.masks.dl_dst,
                   sizeof(eth_mask.dst));
        rte_memcpy(&eth_mask.src, &match->wc.masks.dl_src,
                   sizeof(eth_mask.src));
        eth_mask.type = match->wc.masks.dl_type;

        add_flow_pattern(&patterns, RTE_FLOW_ITEM_TYPE_ETH,
                         &eth_spec, &eth_mask);
    } else {
        /*
         * If user specifies a flow (like UDP flow) without L2 patterns,
         * OVS will at least set the dl_type. Normally, it's enough to
         * create an eth pattern just with it. Unluckily, some Intel's
         * NIC (such as XL710) doesn't support that. Below is a workaround,
         * which simply matches any L2 pkts.
         */
        add_flow_pattern(&patterns, RTE_FLOW_ITEM_TYPE_ETH, NULL, NULL);
    }

    /* VLAN */
    struct rte_flow_item_vlan vlan_spec;
    struct rte_flow_item_vlan vlan_mask;
    memset(&vlan_spec, 0, sizeof(vlan_spec));
    memset(&vlan_mask, 0, sizeof(vlan_mask));
    if (match->wc.masks.vlans[0].tci && match->flow.vlans[0].tci) {
        vlan_spec.tci  = match->flow.vlans[0].tci & ~htons(VLAN_CFI);
        vlan_mask.tci  = match->wc.masks.vlans[0].tci & ~htons(VLAN_CFI);

        /* match any protocols */
        vlan_mask.tpid = 0;

        add_flow_pattern(&patterns, RTE_FLOW_ITEM_TYPE_VLAN,
                         &vlan_spec, &vlan_mask);
    }

    /* IP v4 */
    uint8_t proto = 0;
    struct rte_flow_item_ipv4 ipv4_spec;
    struct rte_flow_item_ipv4 ipv4_mask;
    memset(&ipv4_spec, 0, sizeof(ipv4_spec));
    memset(&ipv4_mask, 0, sizeof(ipv4_mask));
    if (match->flow.dl_type == htons(ETH_TYPE_IP)) {

        ipv4_spec.hdr.type_of_service = match->flow.nw_tos;
        ipv4_spec.hdr.time_to_live    = match->flow.nw_ttl;
        ipv4_spec.hdr.next_proto_id   = match->flow.nw_proto;
        ipv4_spec.hdr.src_addr        = match->flow.nw_src;
        ipv4_spec.hdr.dst_addr        = match->flow.nw_dst;

        ipv4_mask.hdr.type_of_service = match->wc.masks.nw_tos;
        ipv4_mask.hdr.time_to_live    = match->wc.masks.nw_ttl;
        ipv4_mask.hdr.next_proto_id   = match->wc.masks.nw_proto;
        ipv4_mask.hdr.src_addr        = match->wc.masks.nw_src;
        ipv4_mask.hdr.dst_addr        = match->wc.masks.nw_dst;

        add_flow_pattern(&patterns, RTE_FLOW_ITEM_TYPE_IPV4,
                         &ipv4_spec, &ipv4_mask);

        /* Save proto for L4 protocol setup */
        proto = ipv4_spec.hdr.next_proto_id &
                ipv4_mask.hdr.next_proto_id;

        /* Remember proto mask address for later modification */
        ipv4_next_proto_mask = &ipv4_mask.hdr.next_proto_id;
    }

    if (proto != IPPROTO_ICMP && proto != IPPROTO_UDP  &&
        proto != IPPROTO_SCTP && proto != IPPROTO_TCP  &&
        (match->wc.masks.tp_src ||
         match->wc.masks.tp_dst ||
         match->wc.masks.tcp_flags)) {
        VLOG_DBG("L4 Protocol (%u) not supported", proto);
        goto out;
    }

    if ((match->wc.masks.tp_src && match->wc.masks.tp_src != OVS_BE16_MAX) ||
        (match->wc.masks.tp_dst && match->wc.masks.tp_dst != OVS_BE16_MAX)) {
        goto out;
    }

    struct rte_flow_item_tcp tcp_spec;
    struct rte_flow_item_tcp tcp_mask;
    memset(&tcp_spec, 0, sizeof(tcp_spec));
    memset(&tcp_mask, 0, sizeof(tcp_mask));
    if (proto == IPPROTO_TCP) {
        tcp_spec.hdr.src_port  = match->flow.tp_src;
        tcp_spec.hdr.dst_port  = match->flow.tp_dst;
        tcp_spec.hdr.data_off  = ntohs(match->flow.tcp_flags) >> 8;
        tcp_spec.hdr.tcp_flags = ntohs(match->flow.tcp_flags) & 0xff;

        tcp_mask.hdr.src_port  = match->wc.masks.tp_src;
        tcp_mask.hdr.dst_port  = match->wc.masks.tp_dst;
        tcp_mask.hdr.data_off  = ntohs(match->wc.masks.tcp_flags) >> 8;
        tcp_mask.hdr.tcp_flags = ntohs(match->wc.masks.tcp_flags) & 0xff;

        add_flow_pattern(&patterns, RTE_FLOW_ITEM_TYPE_TCP,
                         &tcp_spec, &tcp_mask);

        /* proto == TCP and ITEM_TYPE_TCP, thus no need for proto match */
        if (ipv4_next_proto_mask) {
            *ipv4_next_proto_mask = 0;
        }
        goto end_proto_check;
    }

    struct rte_flow_item_udp udp_spec;
    struct rte_flow_item_udp udp_mask;
    memset(&udp_spec, 0, sizeof(udp_spec));
    memset(&udp_mask, 0, sizeof(udp_mask));
    if (proto == IPPROTO_UDP) {
        udp_spec.hdr.src_port = match->flow.tp_src;
        udp_spec.hdr.dst_port = match->flow.tp_dst;

        udp_mask.hdr.src_port = match->wc.masks.tp_src;
        udp_mask.hdr.dst_port = match->wc.masks.tp_dst;

        add_flow_pattern(&patterns, RTE_FLOW_ITEM_TYPE_UDP,
                         &udp_spec, &udp_mask);

        /* proto == UDP and ITEM_TYPE_UDP, thus no need for proto match */
        if (ipv4_next_proto_mask) {
            *ipv4_next_proto_mask = 0;
        }
        goto end_proto_check;
    }

    struct rte_flow_item_sctp sctp_spec;
    struct rte_flow_item_sctp sctp_mask;
    memset(&sctp_spec, 0, sizeof(sctp_spec));
    memset(&sctp_mask, 0, sizeof(sctp_mask));
    if (proto == IPPROTO_SCTP) {
        sctp_spec.hdr.src_port = match->flow.tp_src;
        sctp_spec.hdr.dst_port = match->flow.tp_dst;

        sctp_mask.hdr.src_port = match->wc.masks.tp_src;
        sctp_mask.hdr.dst_port = match->wc.masks.tp_dst;

        add_flow_pattern(&patterns, RTE_FLOW_ITEM_TYPE_SCTP,
                         &sctp_spec, &sctp_mask);

        /* proto == SCTP and ITEM_TYPE_SCTP, thus no need for proto match */
        if (ipv4_next_proto_mask) {
            *ipv4_next_proto_mask = 0;
        }
        goto end_proto_check;
    }

    struct rte_flow_item_icmp icmp_spec;
    struct rte_flow_item_icmp icmp_mask;
    memset(&icmp_spec, 0, sizeof(icmp_spec));
    memset(&icmp_mask, 0, sizeof(icmp_mask));
    if (proto == IPPROTO_ICMP) {
        icmp_spec.hdr.icmp_type = (uint8_t)ntohs(match->flow.tp_src);
        icmp_spec.hdr.icmp_code = (uint8_t)ntohs(match->flow.tp_dst);

        icmp_mask.hdr.icmp_type = (uint8_t)ntohs(match->wc.masks.tp_src);
        icmp_mask.hdr.icmp_code = (uint8_t)ntohs(match->wc.masks.tp_dst);

        add_flow_pattern(&patterns, RTE_FLOW_ITEM_TYPE_ICMP,
                         &icmp_spec, &icmp_mask);

        /* proto == ICMP and ITEM_TYPE_ICMP, thus no need for proto match */
        if (ipv4_next_proto_mask) {
            *ipv4_next_proto_mask = 0;
        }
        goto end_proto_check;
    }

end_proto_check:

    add_flow_pattern(&patterns, RTE_FLOW_ITEM_TYPE_END, NULL, NULL);

    struct rte_flow_action_mark mark;
    mark.id = info->flow_mark;
    add_flow_action(&actions, RTE_FLOW_ACTION_TYPE_MARK, &mark);

    struct rte_flow_action_rss *rss;
    rss = add_flow_rss_action(&actions, netdev);
    add_flow_action(&actions, RTE_FLOW_ACTION_TYPE_END, NULL);

    flow = rte_flow_create(rte_port->dpdk_port_id, &flow_attr, patterns.items,
                           actions.actions, &error);
    free(rss);
    if (!flow) {
        VLOG_ERR("rte flow creat error: %u : message : %s\n",
                 error.type, error.message);
        goto out;
    }

    VLOG_DBG("installed flow %p by ufid "UUID_FMT" mark %u\n",
             flow, UUID_ARGS((struct uuid *)ufid), mark.id);

out:
    free(patterns.items);
    free(actions.actions);
    return flow;
}


/**
 * @brief - offload flow attached to dpdk port.
 *
 *
 * @return 
 */
int
netdev_dpdk_flow_put(struct netdev *netdev , struct match *match ,
                     struct nlattr *actions OVS_UNUSED, size_t actions_len OVS_UNUSED,
                     const ovs_u128 *ufid OVS_UNUSED, struct offload_info *info OVS_UNUSED,
                     struct dpif_flow_stats *stats OVS_UNUSED) {
    struct rte_flow *rte_flow;
    int ret;
    odp_port_t in_port = match->flow.in_port.odp_port;   
    struct netdev_rte_port * rte_port = netdev_rte_port_search(in_port, &dpdk_map);
    struct ufid_hw_offload * ufid_hw_offload;

    if(rte_port == NULL){
        VLOG_WARN("failed to find port dpdk no %d",in_port);
        return -1;
    }
    
    ufid_hw_offload = ufid_hw_offload_find(ufid, &rte_port->ufid_to_rte);

    /*
     * If an old rte_flow exists, it means it's a flow modification.
     * Here destroy the old rte flow first before adding a new one.
     */
    if(ufid_hw_offload){
        VLOG_DBG("got modification. destroy previous rte_flow");
        ufid_hw_offload_remove(ufid, &rte_port->ufid_to_rte);
        ret = netdev_rte_port_ufid_hw_offload_free(ufid_hw_offload);
       if (ret < 0) {
           return ret;
       }
        return 0;
    }

    // we create fuid_to_rte map for the fuid.
    ufid_hw_offload = netdev_rte_port_ufid_hw_offload_alloc(1, ufid);  
    if(ufid_hw_offload == NULL){
        VLOG_WARN("failed to alloctae ufid_hw_offlaod, OOM");
        return -1;
    }

    ufid_hw_offload_add(ufid_hw_offload, &rte_port->ufid_to_rte);
    ufid_to_portid_add(ufid, rte_port->port_no);

    // generate HW offload.
    ret = netdev_dpdk_validate_flow(match);
    if (ret < 0) {
        return ret;
    }

    rte_flow = netdev_dpdk_add_rte_flow_offload(rte_port, netdev, match, actions,
                                            actions_len, ufid, info);

    if(rte_flow){
        ufid_hw_offload_add_rte_flow(ufid_hw_offload, rte_flow, rte_port->dpdk_port_id);
    }
    return ret;
}

int
/**
 * @brief - del HW offlaod for ufid if exists.
 *
 * @param OVS_UNUSED
 * @param ufid
 * @param OVS_UNUSED
 */
netdev_dpdk_flow_del(struct netdev *netdev OVS_UNUSED, const ovs_u128 *ufid,
                     struct dpif_flow_stats *stats OVS_UNUSED) {

    struct netdev_rte_port * rte_port;
    odp_port_t port_no = ufid_to_portid_search(ufid);
    struct ufid_hw_offload * ufid_hw_offload;

    // no such fuid
    if(port_no == INVALID_ODP_PORT){
        return -1;
    }

    rte_port = netdev_rte_port_search(port_no,&dpdk_map);

    if(rte_port == NULL){
        VLOG_ERR("failed to find dpdk port for port %d",port_no);
        return -1;
    }
        
    ufid_to_portid_remove(ufid);
    ufid_hw_offload = ufid_hw_offload_remove(ufid, &rte_port->ufid_to_rte);

    if(ufid_hw_offload){
        netdev_rte_port_ufid_hw_offload_free(ufid_hw_offload );
    }

    return -1;
}

