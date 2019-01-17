#include <config.h>
#include "rte-flow-sim.h"
#include "dp-packet.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(rte_sim);

#define MAX_SIM_RULES (4096)


static void rte_flow_sim_search_tables(struct dp_packet * pkt, int group);

struct rte_flow_sim_rule
{
    bool is_delete;
    int id;
    int group;
    int priority;

    bool has_eth;
    bool has_ipv4;
    bool has_l4;

    struct eth_addr dl_dst;     /* Ethernet destination address. */
    struct eth_addr dl_dst_mask;/* Ethernet destination address. */
    struct eth_addr dl_src;     /* Ethernet source address. */
    struct eth_addr dl_src_mask;     /* Ethernet source address. */
    ovs_be16 dl_type;           /* Ethernet frame type.*/
    ovs_be16 dl_type_mask;           /* Ethernet frame type.*/


    ovs_be32 nw_src;            /* IPv4 source address or ARP SPA. */
    ovs_be32 nw_src_mask;            /* IPv4 source address or ARP SPA. */
    ovs_be32 nw_dst;            /* IPv4 destination address or ARP TPA. */
    ovs_be32 nw_dst_mask;            /* IPv4 destination address or ARP TPA. */

    int proto;

    uint16_t src_port;
    uint16_t src_port_mask;
    uint16_t dst_port;
    uint16_t dst_port_mask;

    int gorup;
    uint32_t mark;

    int actions[10];
    int actions_len;

    int jump_to;
};


struct hw_offload_sim {
    int curr;
    int max;



    struct rte_flow_sim_rule * rules[0];
};


static struct hw_offload_sim * hw_sim = NULL;
static int rules_id_cntr = 0; 

static void rte_flow_sim_fill_eth(struct rte_flow_sim_rule * rule, 
                                  const struct rte_flow_item_eth * spec,
                                  const struct rte_flow_item_eth * mask)
{
    if(rule->has_eth || rule->has_ipv4){
        //TODO 
        return;
    }   
    memcpy(&rule->dl_dst,&spec->dst,sizeof(struct eth_addr));
    memcpy(&rule->dl_dst_mask,&mask->dst,sizeof(struct eth_addr));
    memcpy(&rule->dl_src,&spec->src,sizeof(struct eth_addr));
    memcpy(&rule->dl_src_mask,&mask->src,sizeof(struct eth_addr));

    rule->has_eth = true;
    return;
}


static void rte_flow_sim_fill_ipv4(struct rte_flow_sim_rule * rule,
                                const struct rte_flow_item_ipv4 *ipv4_spec,
                                const struct rte_flow_item_ipv4 *ipv4_mask)
{
    if(rule->has_ipv4){
        return; //TODO
    }
    memcpy(&rule->nw_src, &ipv4_spec->hdr.src_addr,sizeof(uint32_t));
    memcpy(&rule->nw_src_mask, &ipv4_mask->hdr.src_addr,sizeof(uint32_t));
    memcpy(&rule->nw_dst, &ipv4_spec->hdr.dst_addr,sizeof(uint32_t));
    memcpy(&rule->nw_dst_mask, &ipv4_mask->hdr.dst_addr,sizeof(uint32_t));

    rule->has_ipv4 = true;

    return;
}

static void rte_flow_sim_fill_udp(struct rte_flow_sim_rule * rule,
                                const struct rte_flow_item_udp *udp_spec,
                                const struct rte_flow_item_udp *udp_mask)
{
    if(rule->has_l4){
        return; //TODO
    }

    rule->src_port = udp_spec->hdr.src_port;
    rule->dst_port = udp_spec->hdr.dst_port;
    rule->dst_port_mask = udp_mask->hdr.dst_port;
    rule->src_port_mask = udp_mask->hdr.src_port;

    rule->proto = 0x11;
    rule->has_l4 = true;

    return;
}




struct rte_flow * rte_flow_create_(uint16_t port_id OVS_UNUSED,
         const struct rte_flow_attr *attr OVS_UNUSED,
         const struct rte_flow_item pattern[] OVS_UNUSED,
         const struct rte_flow_action actions[] OVS_UNUSED,
         struct rte_flow_error *error OVS_UNUSED)
{
    int total = 0;
    int tactions = 0;

    if(hw_sim == NULL){
        hw_sim = xzalloc(sizeof(struct hw_offload_sim) + sizeof(struct rte_flow_sim_rule*) * MAX_SIM_RULES);
        memset(hw_sim,0 , sizeof(struct hw_offload_sim) + sizeof(struct rte_flow_sim_rule*) * MAX_SIM_RULES);

    } 

    struct rte_flow_sim_rule * rule = xzalloc(sizeof(*rule));
    if(rule == NULL){
        VLOG_ERR("OOM, failed to alloc rule");
        return NULL;
    }
    memset(rule, 0, sizeof(*rule));
    rule->group = attr->group;
    rule->priority = attr->priority;
    rule->id = rules_id_cntr++;
    VLOG_DBG("group = %d, priority = %d, rule id %d",rule->group, rule->priority,rule->id);

    while(pattern->type != RTE_FLOW_ITEM_TYPE_END){
        switch((*pattern).type){
            case RTE_FLOW_ITEM_TYPE_ETH:
                {
                VLOG_DBG("got ether type");
                const struct rte_flow_item_eth * eth_spec = (*pattern).spec;
                const struct rte_flow_item_eth * eth_mask = (*pattern).mask;
                rte_flow_sim_fill_eth(rule,eth_spec, eth_mask);
                }
                break;
            case RTE_FLOW_ITEM_TYPE_IPV4:
                {
                VLOG_DBG("Got IPV4");
                const struct rte_flow_item_ipv4 * ipv4_spec = (*pattern).spec;
                const struct rte_flow_item_ipv4 *ipv4_mask = (*pattern).mask;
                rte_flow_sim_fill_ipv4(rule, ipv4_spec, ipv4_mask);
                }
                break;
            case RTE_FLOW_ITEM_TYPE_UDP:
                {
                VLOG_DBG("got udp");
                const struct rte_flow_item_udp *udp_spec = (*pattern).spec;
                const struct rte_flow_item_udp *udp_mask = (*pattern).mask;
                rte_flow_sim_fill_udp(rule, udp_spec, udp_mask);
                }

            case RTE_FLOW_ITEM_TYPE_TCP:

                break;

            case RTE_FLOW_ITEM_TYPE_VXLAN:

                break;

            case RTE_FLOW_ITEM_TYPE_VOID:
            case RTE_FLOW_ITEM_TYPE_INVERT:
            case RTE_FLOW_ITEM_TYPE_ANY:
            case RTE_FLOW_ITEM_TYPE_PF:
            case RTE_FLOW_ITEM_TYPE_VF:
            case RTE_FLOW_ITEM_TYPE_PORT:
            case RTE_FLOW_ITEM_TYPE_RAW:
            case RTE_FLOW_ITEM_TYPE_VLAN:
            case RTE_FLOW_ITEM_TYPE_ICMP:
            case RTE_FLOW_ITEM_TYPE_IPV6:
            case RTE_FLOW_ITEM_TYPE_SCTP:
            case RTE_FLOW_ITEM_TYPE_NVGRE:
            case RTE_FLOW_ITEM_TYPE_MPLS:
            case RTE_FLOW_ITEM_TYPE_GRE:
            case RTE_FLOW_ITEM_TYPE_GTP:
            case RTE_FLOW_ITEM_TYPE_GTPC:
            case RTE_FLOW_ITEM_TYPE_GTPU:
            case RTE_FLOW_ITEM_TYPE_E_TAG:
            case RTE_FLOW_ITEM_TYPE_FUZZY:
            case RTE_FLOW_ITEM_TYPE_ESP:
                VLOG_WARN("iten %d, is currently not supported\n",pattern->type);
                goto fail;
                break;
            case RTE_FLOW_ITEM_TYPE_END:
                break;
            default:
            break;
        }
        total++;
        pattern++;
    }

    while(actions->type != RTE_FLOW_ACTION_TYPE_END){
        switch (actions->type){
            case RTE_FLOW_ACTION_TYPE_END:
                break;
            case RTE_FLOW_ACTION_TYPE_MARK:
            {
                const struct rte_flow_action_mark  * mark = (*actions).conf;
                rule->mark = mark->id;
                rule->actions[rule->actions_len++] = (int) actions->type;
                VLOG_DBG("got set for mark %d",rule->mark);
            }
                break;
            case RTE_FLOW_ACTION_TYPE_RSS:
                // nothing to do
                break;
            case RTE_FLOW_ACTION_TYPE_VXLAN_DECAP:
                rule->actions[rule->actions_len++] = (int) actions->type;
                break;

            case RTE_FLOW_ACTION_TYPE_COUNT:
                VLOG_WARN("action COUNT, is not supported in simulartor, skipping it");
                break;
            case RTE_FLOW_ACTION_TYPE_VOID:
            case RTE_FLOW_ACTION_TYPE_PASSTHRU:
            case RTE_FLOW_ACTION_TYPE_FLAG:
            case RTE_FLOW_ACTION_TYPE_QUEUE:
            case RTE_FLOW_ACTION_TYPE_DROP:
            case RTE_FLOW_ACTION_TYPE_DUP:
            case RTE_FLOW_ACTION_TYPE_PF:
            case RTE_FLOW_ACTION_TYPE_VF:
            case RTE_FLOW_ACTION_TYPE_METER:
            case RTE_FLOW_ACTION_TYPE_SECURITY:

                VLOG_WARN("action %d, is not supported in simulartor",actions->type);
                break;
            case RTE_FLOW_ACTION_TYPE_JUMP:
                rule->actions[rule->actions_len++] = (int) actions->type;
                struct rte_flow_action_jump * jump = (struct rte_flow_action_jump *) actions->conf;
                rule->jump_to = jump->group;
                VLOG_DBG("set jump to %d",rule->jump_to);
                break;
            default:
                VLOG_ERR("don't have support %d",actions->type);

        }
        actions++;
        tactions++;
    }

    VLOG_DBG("got %d pattenrs actions %d",total,tactions);
    hw_sim->rules[hw_sim->curr++] = rule;
    return (struct rte_flow *) rule;
fail:
    if(rule){
        free(rule);
    }
    return NULL;
}


static bool cmp_with_mask(uint8_t * a,uint8_t * b, uint8_t * mask, int len)
{
    for(int i = 0 ; i < len ; i++){

        if((*a & *mask) != (*b & *mask)){
            return false;
        }
    }

    return true;
}

static void ret_flow_do_actions(struct rte_flow_sim_rule * rule, struct dp_packet * p)
{
    for(int i = 0 ; i < rule->actions_len ; i++){
        switch(rule->actions[i]){
            case RTE_FLOW_ACTION_TYPE_MARK:
            {
                if(rule->mark != 0){
                    VLOG_DBG("set mark %d",rule->mark);
                    p->mbuf.hash.fdir.hi = rule->mark;
                    p->mbuf.ol_flags |= PKT_RX_FDIR_ID;
                }
            }
                break;
            case RTE_FLOW_ACTION_TYPE_RSS:
                // nothing to do
                break;

            case RTE_FLOW_ACTION_TYPE_COUNT:
                VLOG_WARN("action COUNT, is not supported in simulartor, skipping it");
                break;
            case RTE_FLOW_ACTION_TYPE_JUMP:
                VLOG_DBG("GOT JUMP TO %d",rule->jump_to );
                rte_flow_sim_search_tables(p, rule->jump_to);
                return;
            case RTE_FLOW_ACTION_TYPE_VXLAN_DECAP:
                VLOG_DBG("GOT VXLAN DECAP ");
                dp_packet_reset_packet(p, 50);
                break;

            default:
            VLOG_ERR("action %d, not supported",rule->actions[i]);
        }
    }

}

static bool rte_flow_sim_match(struct rte_flow_sim_rule * rule, struct dp_packet * pkt)
{
    uint8_t * p = dp_packet_data(pkt);
    int len     = dp_packet_size(pkt);
    struct ipv4_hdr * ipv4hdr;
    struct udp_hdr * udp;
    uint16_t * eth_type;
    int ip_hdrlen = 0;

    VLOG_DBG("search rule , gorup %d, priority %d, id %d", rule->group, rule->priority,rule->id);

    if (rule == NULL || len <14) {
        return false;
    }


    if(cmp_with_mask((uint8_t *)&rule->dl_dst, p, (uint8_t *)&rule->dl_dst_mask, 6) &&
     cmp_with_mask((uint8_t *)&rule->dl_src, p + 6, (uint8_t *)&rule->dl_src_mask, 6) ){
        VLOG_DBG("  match eth src="ETH_ADDR_FMT", dst="ETH_ADDR_FMT", "
                     ,
                     ETH_ADDR_BYTES_ARGS( (uint8_t *) p),
                     ETH_ADDR_BYTES_ARGS((uint8_t *) (p + 6)));

    } else {
        return false;
    }

    // very ugly stuff need to do it right.
    // anyway, we support only ipv4 for now.
    eth_type = (uint16_t *)(p+12);
    if(*eth_type != htons(0x800)){
        return false;
    }
    // skip eth header (need to see vlan.etc)
    p+=14;
    len-=14;
    if(len < 20){
        return false;
    }
    ipv4hdr = (struct ipv4_hdr *)p;
    ip_hdrlen = (ipv4hdr->version_ihl & 0xf) << 2;

    if(cmp_with_mask((uint8_t *)&rule->nw_src, (uint8_t *) &ipv4hdr->src_addr, (uint8_t *)&rule->nw_src_mask, 4) &&
       cmp_with_mask((uint8_t *)&rule->nw_dst, (uint8_t *) &ipv4hdr->dst_addr, (uint8_t *)&rule->nw_dst_mask, 4)){
        VLOG_DBG("  match ips: , src="IP_FMT", dst="IP_FMT"\n",
                     IP_ARGS(ipv4hdr->src_addr),
                     IP_ARGS(ipv4hdr->dst_addr));

    } else {
        VLOG_DBG("  failed ips: , src="IP_FMT", dst="IP_FMT"\n",
                     IP_ARGS(ipv4hdr->src_addr),
                     IP_ARGS(ipv4hdr->dst_addr));

        VLOG_DBG("  was looking ips: , src="IP_FMT", dst="IP_FMT"\n",
                     IP_ARGS(rule->nw_src),
                     IP_ARGS(rule->nw_dst));


        return false;
    }

    p+=ip_hdrlen;

    if(rule->proto == ipv4hdr->next_proto_id){
        switch(rule->proto){
            case 0x11:
                {
                    udp = (struct udp_hdr *) p;
                    if(cmp_with_mask((uint8_t *)&rule->src_port,(uint8_t*) &udp->src_port, (uint8_t *)&rule->src_port_mask, 2) &&
                       cmp_with_mask((uint8_t *)&rule->dst_port, (uint8_t*) &udp->dst_port, (uint8_t *)&rule->dst_port_mask, 2)){
                            VLOG_DBG("got match on udp port src=%d, dst=%d ",ntohs(udp->src_port),ntohs(udp->dst_port));    
                            break;
                    }
                    return false;

                }
            default:
                return false;
        }

    }



    return true;
}
    
static void rte_flow_sim_search_tables(struct dp_packet * pkt, int group)
{
    struct rte_flow_sim_rule * best_rule = NULL;
    if(hw_sim == NULL){
        return;
    }
    
    for(int i = 0 ; i < hw_sim->curr ; i++){
        if (hw_sim->rules[i]->group == group &&  rte_flow_sim_match(hw_sim->rules[i], pkt)){
            if(!best_rule || best_rule->priority < hw_sim->rules[i]->priority) {
                best_rule = hw_sim->rules[i];
            } 
        }
    }

    if(best_rule){
        VLOG_DBG("We have a match on rule %d, lets do the actions",best_rule->id);
        ret_flow_do_actions(best_rule, pkt);
    }

    return;
}


void rte_flow_sim_preprocess_pkt(struct dp_packet * pkt)
{
    if(hw_sim == NULL){
        return;
    }
    VLOG_DBG("----------start search on packet-------------");
    rte_flow_sim_search_tables(pkt, 0);
    VLOG_DBG("----------end search on packet-------------");

    return;
}


int rte_flow_destroy_(uint16_t port_id, struct rte_flow * flow,struct rte_flow_error * error )
{
    if(hw_sim->curr == 0){
        return -1;
    }

    for(int i = 0 ; i < hw_sim->curr && i < 5; i++){
        if(hw_sim->rules[i] == (struct rte_flow_sim_rule *) flow){
            hw_sim->rules[i]  =  hw_sim->rules[hw_sim->curr-1];
            hw_sim->curr--;
            return 0;
        }
    }
    return 0;
}

