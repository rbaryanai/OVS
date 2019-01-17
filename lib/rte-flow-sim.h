#ifndef _RTE_FLOW_SIM_H
#define _RTE_FLOW_SIM_H 1
#include <rte_flow.h>

struct dp_packet;

struct rte_flow_action_count {
    int id;
    uint64_t shared;
};

struct rte_flow_action_jump {
    uint32_t group;
};

#ifndef RTE_FLOW_ACTION_TYPE_JUMP
    #define RTE_FLOW_ACTION_TYPE_JUMP 100
    #define RTE_FLOW_ACTION_TYPE_VXLAN_DECAP 200
#endif


void rte_flow_sim_preprocess_pkt(struct dp_packet * pkt);

struct rte_flow * rte_flow_create_(uint16_t port_id,
         const struct rte_flow_attr *attr,
         const struct rte_flow_item pattern[],
         const struct rte_flow_action actions[],
         struct rte_flow_error *error);


int rte_flow_destroy_(uint16_t port_id, struct rte_flow * flow,struct rte_flow_error * error );

#endif
