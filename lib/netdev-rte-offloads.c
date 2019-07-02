/*
 * Copyright (c) 2014, 2015, 2016, 2017 Nicira, Inc.
 * Copyright (c) 2019 Mellanox Technologies, Ltd.
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

#include <rte_flow.h>
#include "cmap.h"
#include "conntrack.h"
#include "dpif-netdev.h"
#include "id-pool.h"
#include "netdev-provider.h"
#include "openvswitch/match.h"
#include "openvswitch/vlog.h"
#include "packets.h"
#include "uuid.h"

VLOG_DEFINE_THIS_MODULE(netdev_rte_offloads);

static void
netdev_dpdk_offload_put_handle(struct match *match, struct nlattr *actions,
        size_t actions_len, uint32_t flow_mark);


/*
 * A mapping from ufid to dpdk rte_flow.
 */
static struct cmap ufid_to_rte_flow = CMAP_INITIALIZER;

struct ufid_to_rte_flow_data {
    struct cmap_node node;
    ovs_u128 ufid;
    struct rte_flow *rte_flow;
};

/* Find rte_flow with @ufid. */
static struct rte_flow *
ufid_to_rte_flow_find(const ovs_u128 *ufid)
{
    size_t hash = hash_bytes(ufid, sizeof *ufid, 0);
    struct ufid_to_rte_flow_data *data;

    CMAP_FOR_EACH_WITH_HASH (data, node, hash, &ufid_to_rte_flow) {
        if (ovs_u128_equals(*ufid, data->ufid)) {
            return data->rte_flow;
        }
    }

    return NULL;
}

static inline void
ufid_to_rte_flow_associate(const ovs_u128 *ufid,
                           struct rte_flow *rte_flow)
{
    size_t hash = hash_bytes(ufid, sizeof *ufid, 0);
    struct ufid_to_rte_flow_data *data = xzalloc(sizeof *data);

    /*
     * We should not simply overwrite an existing rte flow.
     * We should have deleted it first before re-adding it.
     * Thus, if following assert triggers, something is wrong:
     * the rte_flow is not destroyed.
     */
    ovs_assert(ufid_to_rte_flow_find(ufid) == NULL);

    data->ufid = *ufid;
    data->rte_flow = rte_flow;

    cmap_insert(&ufid_to_rte_flow,
                CONST_CAST(struct cmap_node *, &data->node), hash);
}

static inline void
ufid_to_rte_flow_disassociate(const ovs_u128 *ufid)
{
    size_t hash = hash_bytes(ufid, sizeof *ufid, 0);
    struct ufid_to_rte_flow_data *data;

    CMAP_FOR_EACH_WITH_HASH (data, node, hash, &ufid_to_rte_flow) {
        if (ovs_u128_equals(*ufid, data->ufid)) {
            cmap_remove(&ufid_to_rte_flow,
                        CONST_CAST(struct cmap_node *, &data->node), hash);
            ovsrcu_postpone(free, data);
            return;
        }
    }

    VLOG_WARN("ufid "UUID_FMT" is not associated with an rte flow\n",
              UUID_ARGS((struct uuid *) ufid));
}

/*
 * To avoid individual xrealloc calls for each new element, a 'curent_max'
 * is used to keep track of current allocated number of elements. Starts
 * by 8 and doubles on each xrealloc call.
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
    struct ds s;

    if (!VLOG_IS_DBG_ENABLED() || item->type == RTE_FLOW_ITEM_TYPE_END) {
        return;
    }

    ds_init(&s);

    if (item->type == RTE_FLOW_ITEM_TYPE_ETH) {
        const struct rte_flow_item_eth *eth_spec = item->spec;
        const struct rte_flow_item_eth *eth_mask = item->mask;

        ds_put_cstr(&s, "rte flow eth pattern:\n");
        if (eth_spec) {
            ds_put_format(&s,
                          "  Spec: src="ETH_ADDR_FMT", dst="ETH_ADDR_FMT", "
                          "type=0x%04" PRIx16"\n",
                          ETH_ADDR_BYTES_ARGS(eth_spec->src.addr_bytes),
                          ETH_ADDR_BYTES_ARGS(eth_spec->dst.addr_bytes),
                          ntohs(eth_spec->type));
        } else {
            ds_put_cstr(&s, "  Spec = null\n");
        }
        if (eth_mask) {
            ds_put_format(&s,
                          "  Mask: src="ETH_ADDR_FMT", dst="ETH_ADDR_FMT", "
                          "type=0x%04"PRIx16"\n",
                          ETH_ADDR_BYTES_ARGS(eth_mask->src.addr_bytes),
                          ETH_ADDR_BYTES_ARGS(eth_mask->dst.addr_bytes),
                          ntohs(eth_mask->type));
        } else {
            ds_put_cstr(&s, "  Mask = null\n");
        }
    }

    if (item->type == RTE_FLOW_ITEM_TYPE_VLAN) {
        const struct rte_flow_item_vlan *vlan_spec = item->spec;
        const struct rte_flow_item_vlan *vlan_mask = item->mask;

        ds_put_cstr(&s, "rte flow vlan pattern:\n");
        if (vlan_spec) {
            ds_put_format(&s,
                          "  Spec: inner_type=0x%"PRIx16", tci=0x%"PRIx16"\n",
                          ntohs(vlan_spec->inner_type), ntohs(vlan_spec->tci));
        } else {
            ds_put_cstr(&s, "  Spec = null\n");
        }

        if (vlan_mask) {
            ds_put_format(&s,
                          "  Mask: inner_type=0x%"PRIx16", tci=0x%"PRIx16"\n",
                          ntohs(vlan_mask->inner_type), ntohs(vlan_mask->tci));
        } else {
            ds_put_cstr(&s, "  Mask = null\n");
        }
    }

    if (item->type == RTE_FLOW_ITEM_TYPE_IPV4) {
        const struct rte_flow_item_ipv4 *ipv4_spec = item->spec;
        const struct rte_flow_item_ipv4 *ipv4_mask = item->mask;

        ds_put_cstr(&s, "rte flow ipv4 pattern:\n");
        if (ipv4_spec) {
            ds_put_format(&s,
                          "  Spec: tos=0x%"PRIx8", ttl=%"PRIx8
                          ", proto=0x%"PRIx8
                          ", src="IP_FMT", dst="IP_FMT"\n",
                          ipv4_spec->hdr.type_of_service,
                          ipv4_spec->hdr.time_to_live,
                          ipv4_spec->hdr.next_proto_id,
                          IP_ARGS(ipv4_spec->hdr.src_addr),
                          IP_ARGS(ipv4_spec->hdr.dst_addr));
        } else {
            ds_put_cstr(&s, "  Spec = null\n");
        }
        if (ipv4_mask) {
            ds_put_format(&s,
                          "  Mask: tos=0x%"PRIx8", ttl=%"PRIx8
                          ", proto=0x%"PRIx8
                          ", src="IP_FMT", dst="IP_FMT"\n",
                          ipv4_mask->hdr.type_of_service,
                          ipv4_mask->hdr.time_to_live,
                          ipv4_mask->hdr.next_proto_id,
                          IP_ARGS(ipv4_mask->hdr.src_addr),
                          IP_ARGS(ipv4_mask->hdr.dst_addr));
        } else {
            ds_put_cstr(&s, "  Mask = null\n");
        }
    }

    if (item->type == RTE_FLOW_ITEM_TYPE_UDP) {
        const struct rte_flow_item_udp *udp_spec = item->spec;
        const struct rte_flow_item_udp *udp_mask = item->mask;

        ds_put_cstr(&s, "rte flow udp pattern:\n");
        if (udp_spec) {
            ds_put_format(&s,
                          "  Spec: src_port=%"PRIu16", dst_port=%"PRIu16"\n",
                          ntohs(udp_spec->hdr.src_port),
                          ntohs(udp_spec->hdr.dst_port));
        } else {
            ds_put_cstr(&s, "  Spec = null\n");
        }
        if (udp_mask) {
            ds_put_format(&s,
                          "  Mask: src_port=0x%"PRIx16
                          ", dst_port=0x%"PRIx16"\n",
                          ntohs(udp_mask->hdr.src_port),
                          ntohs(udp_mask->hdr.dst_port));
        } else {
            ds_put_cstr(&s, "  Mask = null\n");
        }
    }

    if (item->type == RTE_FLOW_ITEM_TYPE_SCTP) {
        const struct rte_flow_item_sctp *sctp_spec = item->spec;
        const struct rte_flow_item_sctp *sctp_mask = item->mask;

        ds_put_cstr(&s, "rte flow sctp pattern:\n");
        if (sctp_spec) {
            ds_put_format(&s,
                          "  Spec: src_port=%"PRIu16", dst_port=%"PRIu16"\n",
                          ntohs(sctp_spec->hdr.src_port),
                          ntohs(sctp_spec->hdr.dst_port));
        } else {
            ds_put_cstr(&s, "  Spec = null\n");
        }
        if (sctp_mask) {
            ds_put_format(&s,
                          "  Mask: src_port=0x%"PRIx16
                          ", dst_port=0x%"PRIx16"\n",
                          ntohs(sctp_mask->hdr.src_port),
                          ntohs(sctp_mask->hdr.dst_port));
        } else {
            ds_put_cstr(&s, "  Mask = null\n");
        }
    }

    if (item->type == RTE_FLOW_ITEM_TYPE_ICMP) {
        const struct rte_flow_item_icmp *icmp_spec = item->spec;
        const struct rte_flow_item_icmp *icmp_mask = item->mask;

        ds_put_cstr(&s, "rte flow icmp pattern:\n");
        if (icmp_spec) {
            ds_put_format(&s,
                          "  Spec: icmp_type=%"PRIu8", icmp_code=%"PRIu8"\n",
                          icmp_spec->hdr.icmp_type,
                          icmp_spec->hdr.icmp_code);
        } else {
            ds_put_cstr(&s, "  Spec = null\n");
        }
        if (icmp_mask) {
            ds_put_format(&s,
                          "  Mask: icmp_type=0x%"PRIx8
                          ", icmp_code=0x%"PRIx8"\n",
                          icmp_spec->hdr.icmp_type,
                          icmp_spec->hdr.icmp_code);
        } else {
            ds_put_cstr(&s, "  Mask = null\n");
        }
    }

    if (item->type == RTE_FLOW_ITEM_TYPE_TCP) {
        const struct rte_flow_item_tcp *tcp_spec = item->spec;
        const struct rte_flow_item_tcp *tcp_mask = item->mask;

        ds_put_cstr(&s, "rte flow tcp pattern:\n");
        if (tcp_spec) {
            ds_put_format(&s,
                          "  Spec: src_port=%"PRIu16", dst_port=%"PRIu16
                          ", data_off=0x%"PRIx8", tcp_flags=0x%"PRIx8"\n",
                          ntohs(tcp_spec->hdr.src_port),
                          ntohs(tcp_spec->hdr.dst_port),
                          tcp_spec->hdr.data_off,
                          tcp_spec->hdr.tcp_flags);
        } else {
            ds_put_cstr(&s, "  Spec = null\n");
        }
        if (tcp_mask) {
            ds_put_format(&s,
                          "  Mask: src_port=%"PRIx16", dst_port=%"PRIx16
                          ", data_off=0x%"PRIx8", tcp_flags=0x%"PRIx8"\n",
                          ntohs(tcp_mask->hdr.src_port),
                          ntohs(tcp_mask->hdr.dst_port),
                          tcp_mask->hdr.data_off,
                          tcp_mask->hdr.tcp_flags);
        } else {
            ds_put_cstr(&s, "  Mask = null\n");
        }
    }

    VLOG_DBG("%s", ds_cstr(&s));
    ds_destroy(&s);
}

static void
add_flow_pattern(struct flow_patterns *patterns, enum rte_flow_item_type type,
                 const void *spec, const void *mask)
{
    int cnt = patterns->cnt;

    if (cnt == 0) {
        patterns->current_max = 8;
        patterns->items = xcalloc(patterns->current_max,
                                  sizeof *patterns->items);
    } else if (cnt == patterns->current_max) {
        patterns->current_max *= 2;
        patterns->items = xrealloc(patterns->items, patterns->current_max *
                                   sizeof *patterns->items);
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
                                   sizeof *actions->actions);
    } else if (cnt == actions->current_max) {
        actions->current_max *= 2;
        actions->actions = xrealloc(actions->actions, actions->current_max *
                                    sizeof *actions->actions);
    }

    actions->actions[cnt].type = type;
    actions->actions[cnt].conf = conf;
    actions->cnt++;
}

struct action_rss_data {
    struct rte_flow_action_rss conf;
    uint16_t queue[0];
};

static struct action_rss_data *
add_flow_rss_action(struct flow_actions *actions,
                    struct netdev *netdev)
{
    int i;
    struct action_rss_data *rss_data;

    rss_data = xmalloc(sizeof *rss_data +
                       netdev_n_rxq(netdev) * sizeof rss_data->queue[0]);
    *rss_data = (struct action_rss_data) {
        .conf = (struct rte_flow_action_rss) {
            .func = RTE_ETH_HASH_FUNCTION_DEFAULT,
            .level = 0,
            .types = 0,
            .queue_num = netdev_n_rxq(netdev),
            .queue = rss_data->queue,
            .key_len = 0,
            .key  = NULL
        },
    };

    /* Override queue array with default. */
    for (i = 0; i < netdev_n_rxq(netdev); i++) {
       rss_data->queue[i] = i;
    }

    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_RSS, &rss_data->conf);

    return rss_data;
}

static int
netdev_rte_offloads_add_flow(struct netdev *netdev,
                             const struct match *match,
                             struct nlattr *nl_actions OVS_UNUSED,
                             size_t actions_len OVS_UNUSED,
                             const ovs_u128 *ufid,
                             struct offload_info *info)
{
    const struct rte_flow_attr flow_attr = {
        .group = 0,
        .priority = 0,
        .ingress = 1,
        .egress = 0
    };
    struct flow_patterns patterns = { .items = NULL, .cnt = 0 };
    struct flow_actions actions = { .actions = NULL, .cnt = 0 };
    struct rte_flow *flow;
    struct rte_flow_error error;
    uint8_t proto = 0;
    int ret = 0;
    struct flow_items {
        struct rte_flow_item_eth  eth;
        struct rte_flow_item_vlan vlan;
        struct rte_flow_item_ipv4 ipv4;
        union {
            struct rte_flow_item_tcp  tcp;
            struct rte_flow_item_udp  udp;
            struct rte_flow_item_sctp sctp;
            struct rte_flow_item_icmp icmp;
        };
    } spec, mask;

    memset(&spec, 0, sizeof spec);
    memset(&mask, 0, sizeof mask);

    /* Eth */
    if (!eth_addr_is_zero(match->wc.masks.dl_src) ||
        !eth_addr_is_zero(match->wc.masks.dl_dst)) {
        memcpy(&spec.eth.dst, &match->flow.dl_dst, sizeof spec.eth.dst);
        memcpy(&spec.eth.src, &match->flow.dl_src, sizeof spec.eth.src);
        spec.eth.type = match->flow.dl_type;

        memcpy(&mask.eth.dst, &match->wc.masks.dl_dst, sizeof mask.eth.dst);
        memcpy(&mask.eth.src, &match->wc.masks.dl_src, sizeof mask.eth.src);
        mask.eth.type = match->wc.masks.dl_type;

        add_flow_pattern(&patterns, RTE_FLOW_ITEM_TYPE_ETH,
                         &spec.eth, &mask.eth);
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
    if (match->wc.masks.vlans[0].tci && match->flow.vlans[0].tci) {
        spec.vlan.tci  = match->flow.vlans[0].tci & ~htons(VLAN_CFI);
        mask.vlan.tci  = match->wc.masks.vlans[0].tci & ~htons(VLAN_CFI);

        /* Match any protocols. */
        mask.vlan.inner_type = 0;

        add_flow_pattern(&patterns, RTE_FLOW_ITEM_TYPE_VLAN,
                         &spec.vlan, &mask.vlan);
    }

    /* IP v4 */
    if (match->flow.dl_type == htons(ETH_TYPE_IP)) {
        spec.ipv4.hdr.type_of_service = match->flow.nw_tos;
        spec.ipv4.hdr.time_to_live    = match->flow.nw_ttl;
        spec.ipv4.hdr.next_proto_id   = match->flow.nw_proto;
        spec.ipv4.hdr.src_addr        = match->flow.nw_src;
        spec.ipv4.hdr.dst_addr        = match->flow.nw_dst;

        mask.ipv4.hdr.type_of_service = match->wc.masks.nw_tos;
        mask.ipv4.hdr.time_to_live    = match->wc.masks.nw_ttl;
        mask.ipv4.hdr.next_proto_id   = match->wc.masks.nw_proto;
        mask.ipv4.hdr.src_addr        = match->wc.masks.nw_src;
        mask.ipv4.hdr.dst_addr        = match->wc.masks.nw_dst;

        add_flow_pattern(&patterns, RTE_FLOW_ITEM_TYPE_IPV4,
                         &spec.ipv4, &mask.ipv4);

        /* Save proto for L4 protocol setup. */
        proto = spec.ipv4.hdr.next_proto_id &
                mask.ipv4.hdr.next_proto_id;
    }

    if (proto != IPPROTO_ICMP && proto != IPPROTO_UDP  &&
        proto != IPPROTO_SCTP && proto != IPPROTO_TCP  &&
        (match->wc.masks.tp_src ||
         match->wc.masks.tp_dst ||
         match->wc.masks.tcp_flags)) {
        VLOG_DBG("L4 Protocol (%u) not supported", proto);
        ret = -1;
        goto out;
    }

    if ((match->wc.masks.tp_src && match->wc.masks.tp_src != OVS_BE16_MAX) ||
        (match->wc.masks.tp_dst && match->wc.masks.tp_dst != OVS_BE16_MAX)) {
        ret = -1;
        goto out;
    }

    switch (proto) {
    case IPPROTO_TCP:
        spec.tcp.hdr.src_port  = match->flow.tp_src;
        spec.tcp.hdr.dst_port  = match->flow.tp_dst;
        spec.tcp.hdr.data_off  = ntohs(match->flow.tcp_flags) >> 8;
        spec.tcp.hdr.tcp_flags = ntohs(match->flow.tcp_flags) & 0xff;

        mask.tcp.hdr.src_port  = match->wc.masks.tp_src;
        mask.tcp.hdr.dst_port  = match->wc.masks.tp_dst;
        mask.tcp.hdr.data_off  = ntohs(match->wc.masks.tcp_flags) >> 8;
        mask.tcp.hdr.tcp_flags = ntohs(match->wc.masks.tcp_flags) & 0xff;

        add_flow_pattern(&patterns, RTE_FLOW_ITEM_TYPE_TCP,
                         &spec.tcp, &mask.tcp);

        /* proto == TCP and ITEM_TYPE_TCP, thus no need for proto match. */
        mask.ipv4.hdr.next_proto_id = 0;
        break;

    case IPPROTO_UDP:
        spec.udp.hdr.src_port = match->flow.tp_src;
        spec.udp.hdr.dst_port = match->flow.tp_dst;

        mask.udp.hdr.src_port = match->wc.masks.tp_src;
        mask.udp.hdr.dst_port = match->wc.masks.tp_dst;

        add_flow_pattern(&patterns, RTE_FLOW_ITEM_TYPE_UDP,
                         &spec.udp, &mask.udp);

        /* proto == UDP and ITEM_TYPE_UDP, thus no need for proto match. */
        mask.ipv4.hdr.next_proto_id = 0;
        break;

    case IPPROTO_SCTP:
        spec.sctp.hdr.src_port = match->flow.tp_src;
        spec.sctp.hdr.dst_port = match->flow.tp_dst;

        mask.sctp.hdr.src_port = match->wc.masks.tp_src;
        mask.sctp.hdr.dst_port = match->wc.masks.tp_dst;

        add_flow_pattern(&patterns, RTE_FLOW_ITEM_TYPE_SCTP,
                         &spec.sctp, &mask.sctp);

        /* proto == SCTP and ITEM_TYPE_SCTP, thus no need for proto match. */
        mask.ipv4.hdr.next_proto_id = 0;
        break;

    case IPPROTO_ICMP:
        spec.icmp.hdr.icmp_type = (uint8_t) ntohs(match->flow.tp_src);
        spec.icmp.hdr.icmp_code = (uint8_t) ntohs(match->flow.tp_dst);

        mask.icmp.hdr.icmp_type = (uint8_t) ntohs(match->wc.masks.tp_src);
        mask.icmp.hdr.icmp_code = (uint8_t) ntohs(match->wc.masks.tp_dst);

        add_flow_pattern(&patterns, RTE_FLOW_ITEM_TYPE_ICMP,
                         &spec.icmp, &mask.icmp);

        /* proto == ICMP and ITEM_TYPE_ICMP, thus no need for proto match. */
        mask.ipv4.hdr.next_proto_id = 0;
        break;
    }

    add_flow_pattern(&patterns, RTE_FLOW_ITEM_TYPE_END, NULL, NULL);

    struct rte_flow_action_mark mark;
    struct action_rss_data *rss;

    mark.id = info->flow_mark;
    add_flow_action(&actions, RTE_FLOW_ACTION_TYPE_MARK, &mark);

    rss = add_flow_rss_action(&actions, netdev);
    add_flow_action(&actions, RTE_FLOW_ACTION_TYPE_END, NULL);

    flow = netdev_dpdk_rte_flow_create(netdev, &flow_attr,
                                       patterns.items,
                                       actions.actions, &error);

    free(rss);
    if (!flow) {
        VLOG_ERR("%s: rte flow creat error: %u : message : %s\n",
                 netdev_get_name(netdev), error.type, error.message);
        ret = -1;
        goto out;
    }
    ufid_to_rte_flow_associate(ufid, flow);
    VLOG_DBG("%s: installed flow %p by ufid "UUID_FMT"\n",
             netdev_get_name(netdev), flow, UUID_ARGS((struct uuid *)ufid));

out:
    free(patterns.items);
    free(actions.actions);
    return ret;
}

/*
 * Check if any unsupported flow patterns are specified.
 */
static int
netdev_rte_offloads_validate_flow(const struct match *match, bool ct_offload,
                                 bool tun_offload)
{
    struct match match_zero_wc;
    const struct flow *masks = &match->wc.masks;

    /* Create a wc-zeroed version of flow. */
    match_init(&match_zero_wc, &match->flow, &match->wc);

    if (!tun_offload && !is_all_zeros(&match_zero_wc.flow.tunnel,
                      sizeof match_zero_wc.flow.tunnel)) {
        goto err;
    }

    if (masks->metadata || masks->skb_priority ||
        masks->pkt_mark || masks->dp_hash) {
        goto err;
    }

    /* recirc id must be zero. */
    if (!ct_offload && match_zero_wc.flow.recirc_id) {
        goto err;
    }

    if (!ct_offload && (masks->ct_state || masks->ct_nw_proto ||
        masks->ct_zone  || masks->ct_mark     ||
        !ovs_u128_is_zero(masks->ct_label))) {
        goto err;
    }

    if (masks->conj_id || masks->actset_output) {
        goto err;
    }

    /* Unsupported L2. */
    if (!is_all_zeros(masks->mpls_lse, sizeof masks->mpls_lse)) {
        goto err;
    }

    /* Unsupported L3. */
    if (masks->ipv6_label || masks->ct_nw_src || masks->ct_nw_dst     ||
        !is_all_zeros(&masks->ipv6_src,    sizeof masks->ipv6_src)    ||
        !is_all_zeros(&masks->ipv6_dst,    sizeof masks->ipv6_dst)    ||
        !is_all_zeros(&masks->ct_ipv6_src, sizeof masks->ct_ipv6_src) ||
        !is_all_zeros(&masks->ct_ipv6_dst, sizeof masks->ct_ipv6_dst) ||
        !is_all_zeros(&masks->nd_target,   sizeof masks->nd_target)   ||
        !is_all_zeros(&masks->nsh,         sizeof masks->nsh)         ||
        !is_all_zeros(&masks->arp_sha,     sizeof masks->arp_sha)     ||
        !is_all_zeros(&masks->arp_tha,     sizeof masks->arp_tha)) {
        goto err;
    }

    /* If fragmented, then don't HW accelerate - for now. */
    if (match_zero_wc.flow.nw_frag) {
        goto err;
    }

    /* Unsupported L4. */
    if (masks->igmp_group_ip4 || masks->ct_tp_src || masks->ct_tp_dst) {
        goto err;
    }

    return 0;

err:
    VLOG_ERR("cannot HW accelerate this flow due to unsupported protocols");
    return -1;
}

static int
netdev_rte_offloads_destroy_flow(struct netdev *netdev,
                                 const ovs_u128 *ufid,
                                 struct rte_flow *rte_flow)
{
    struct rte_flow_error error;
    int ret = netdev_dpdk_rte_flow_destroy(netdev, rte_flow, &error);

    if (ret == 0) {
        ufid_to_rte_flow_disassociate(ufid);
        VLOG_DBG("%s: removed rte flow %p associated with ufid " UUID_FMT "\n",
                 netdev_get_name(netdev), rte_flow,
                 UUID_ARGS((struct uuid *)ufid));
    } else {
        VLOG_ERR("%s: rte flow destroy error: %u : message : %s\n",
                 netdev_get_name(netdev), error.type, error.message);
    }

    return ret;
}

int
netdev_rte_offloads_flow_put(struct netdev *netdev, struct match *match,
                             struct nlattr *actions, size_t actions_len,
                             const ovs_u128 *ufid, struct offload_info *info,
                             struct dpif_flow_stats *stats OVS_UNUSED)
{
    struct rte_flow *rte_flow;
    int ret;

    /*
     * If an old rte_flow exists, it means it's a flow modification.
     * Here destroy the old rte flow first before adding a new one.
     */
    rte_flow = ufid_to_rte_flow_find(ufid);
    if (rte_flow) {
        ret = netdev_rte_offloads_destroy_flow(netdev, ufid, rte_flow);
        if (ret < 0) {
            return ret;
        }
    }

    netdev_dpdk_offload_put_handle(match, actions,
        actions_len,0);



    ret = netdev_rte_offloads_validate_flow(match, false, false);
    if (ret < 0) {
        return ret;
    }

    return netdev_rte_offloads_add_flow(netdev, match, actions,
                                        actions_len, ufid, info);
}

int
netdev_rte_offloads_flow_del(struct netdev *netdev, const ovs_u128 *ufid,
                             struct dpif_flow_stats *stats OVS_UNUSED)
{
    struct rte_flow *rte_flow = ufid_to_rte_flow_find(ufid);

    if (!rte_flow) {
        return -1;
    }

    return netdev_rte_offloads_destroy_flow(netdev, ufid, rte_flow);
}

/* TEMPORAL should be del once ready on dpdk */
struct rte_flow_action_set_tag {
       uint32_t data;
       uint32_t mask;
       uint8_t index;
};

struct rte_flow_item_tag {
       uint32_t data;
       uint32_t mask;
       uint8_t index;
};
/* TEMPORAL should be del once ready on dpdk */

enum {
    REG_RECIRC_ID = 0,
    REG_ZONE = 1,
    REG_MARK =2 ,
    REG_OUTER_ID =3,
    REG_STATE = 4,
    REG_MAX = 5
};

static int reg_indexs[] = {2,2,3,4,2};
static int reg_mask  [] = {2,2,3,4,2};
static int reg_shift [] = {0,16,0,0,24};

static void
netdev_dpdk_add_pattern_match_reg(struct flow_patterns *patterns, int reg_type,
                                                                  uint32_t val)
{
    if (reg_type > REG_MAX ) {
        VLOG_ERR("reg type %d is out of range",reg_type);
        return;
    }

    struct flow_items {
        struct rte_flow_item_tag tag;
    } spec, mask;
      
    /* TODO: once API is ready should put here the real spec and mask */    
    spec.tag.index = reg_indexs[reg_type];
    spec.tag.data   = val << reg_shift[reg_type];
    spec.tag.mask   = reg_mask[reg_type];

    //add_flow_pattern(patterns,
}

static int
netdev_dpdk_add_action_set_reg(struct flow_actions *actions, int reg_type,
                                                                  uint32_t val)
{
    if (reg_type > REG_MAX ) {
        VLOG_ERR("reg type %d is out of range",reg_type);
        return -1;
    }

    struct flow_items {
        struct rte_flow_action_set_tag tag;
    } spec, mask;

    /* TODO: once API is ready should put here the real spec and mask */    
    spec.tag.index = reg_indexs[reg_type];
    spec.tag.data   = val << reg_shift[reg_type];
    spec.tag.mask   = reg_mask[reg_type];

    return 0;
}
#define INVALID_OUTER_ID  0Xffffffff
#define INVALID_HW_ID     0Xffffffff
#define MAX_OUTER_ID  0xffff
#define MAX_HW_TABLE (0xff00)

struct tun_ctx_outer_id_data {
    struct cmap_node node;
    uint32_t outer_id;
    ovs_be32 ip_dst;
    ovs_be32 ip_src;
    ovs_be64 tun_id;
    int      ref_count;
};

struct tun_ctx_outer_id {
    struct cmap outer_id_to_tun_map;
    struct cmap tun_to_outer_id_map;
    struct id_pool *pool;
};

struct tun_ctx_outer_id tun_ctx_outer_id = {
    .outer_id_to_tun_map = CMAP_INITIALIZER,
    .tun_to_outer_id_map = CMAP_INITIALIZER,
};

static struct
tun_ctx_outer_id_data *netdev_dpdk_tun_data_find(uint32_t outer_id)
{
    size_t hash = hash_add(0,outer_id);
    struct tun_ctx_outer_id_data *data;

    CMAP_FOR_EACH_WITH_HASH (data, node, hash,
             &tun_ctx_outer_id.outer_id_to_tun_map) {
        if (data->outer_id == outer_id) {
            return data;
        }
    }

    return NULL;
}

static void
netdev_dpdk_tun_data_del(uint32_t outer_id)
{
    size_t hash = hash_add(0,outer_id);
    struct tun_ctx_outer_id_data *data;

    CMAP_FOR_EACH_WITH_HASH (data, node, hash,
            &tun_ctx_outer_id.outer_id_to_tun_map) {
        if (data->outer_id == outer_id) {
                cmap_remove(&tun_ctx_outer_id.outer_id_to_tun_map,
                        CONST_CAST(struct cmap_node *, &data->node), hash);
                ovsrcu_postpone(free, data);
                return;
        }
    }
}

static void
netdev_dpdk_tun_data_insert(uint32_t outer_id, ovs_be32 ip_dst,
                               ovs_be32 ip_src, ovs_be64 tun_id)
{
    size_t hash = hash_add(0,outer_id);
    struct tun_ctx_outer_id_data *data = xzalloc(sizeof *data);

    data->outer_id = outer_id;
    data->ip_dst = ip_dst;
    data->ip_src = ip_src;
    data->tun_id = tun_id;

    cmap_insert(&tun_ctx_outer_id.outer_id_to_tun_map,
                CONST_CAST(struct cmap_node *, &data->node), hash);
}

static inline uint32_t netdev_dpdk_tun_hash(ovs_be32 ip_dst, ovs_be32 ip_src,
                              ovs_be64 tun_id)
{
    uint32_t hash = 0;
    hash = hash_add(hash,ip_dst);
    hash = hash_add(hash,ip_src);
    hash = hash_add64(hash,tun_id);
    return hash;
}

static uint32_t
netdev_dpdk_tun_outer_id_get_ref(ovs_be32 ip_dst, ovs_be32 ip_src,
                              ovs_be64 tun_id)
{
    struct tun_ctx_outer_id_data *data;
    uint32_t hash = netdev_dpdk_tun_hash(ip_dst, ip_src, tun_id);

    CMAP_FOR_EACH_WITH_HASH (data, node, hash,
                    &tun_ctx_outer_id.tun_to_outer_id_map) {
        if (data->tun_id == tun_id && data->ip_dst == ip_dst
                        && data->ip_src == ip_src) {
            data->ref_count++;
            return data->outer_id;
        }
    }

    return INVALID_OUTER_ID;
}

static uint32_t
netdev_dpdk_tun_outer_id_alloc(ovs_be32 ip_dst, ovs_be32 ip_src,
                              ovs_be64 tun_id)
{
    struct tun_ctx_outer_id_data *data;
    uint32_t outer_id;
    uint32_t hash = 0;

    if (!tun_ctx_outer_id.pool) {
        tun_ctx_outer_id.pool = id_pool_create(1, MAX_OUTER_ID);
    }

    if (!id_pool_alloc_id(tun_ctx_outer_id.pool, &outer_id)) {
        return INVALID_OUTER_ID;
    }

    hash = netdev_dpdk_tun_hash(ip_dst, ip_src, tun_id);

    data = xzalloc(sizeof *data);
    data->ip_dst = ip_dst;
    data->ip_src = ip_src;
    data->tun_id = tun_id;
    data->outer_id = outer_id;
    data->ref_count  = 1;

    cmap_insert(&tun_ctx_outer_id.tun_to_outer_id_map,
                CONST_CAST(struct cmap_node *, &data->node), hash);

    netdev_dpdk_tun_data_insert(outer_id, ip_dst, ip_src, tun_id);

    return outer_id;
}

static void
netdev_dpdk_tun_outer_id_unref(ovs_be32 ip_dst, ovs_be32 ip_src,
                                       ovs_be64 tun_id)
{
    struct tun_ctx_outer_id_data *data;
    uint32_t hash = netdev_dpdk_tun_hash(ip_dst, ip_src, tun_id);

    CMAP_FOR_EACH_WITH_HASH (data, node, hash,
                    &tun_ctx_outer_id.tun_to_outer_id_map) {
        if (data->tun_id == tun_id && data->ip_dst == ip_dst
                        && data->ip_src == ip_src) {
            data->ref_count--;
            if (data->ref_count == 0) {
                netdev_dpdk_tun_data_del(data->outer_id);
                cmap_remove(&tun_ctx_outer_id.tun_to_outer_id_map,
                        CONST_CAST(struct cmap_node *, &data->node), hash);
                id_pool_free_id(tun_ctx_outer_id.pool, data->outer_id);
                ovsrcu_postpone(free, data);
            }
            return;
        }
    }
}

/* A tunnel meta data has 3 tuple. src ip, dst ip and tun.
 * We need to replace each 3-tuple with an id.
 * If we have already allocated outer_id for the tun we just inc the refcnt.
 * If no such tun exits we allocate a new outer id and set refcnt to 1.
 * every offloaded flow that has tun on match should use outer_id
 */
static uint32_t
netdev_dpdk_tun_id_get_ref(ovs_be32 ip_dst, ovs_be32 ip_src,
                                       ovs_be64 tun_id)
{
    uint32_t outer_id = netdev_dpdk_tun_outer_id_get_ref(ip_dst,
                                                   ip_src, tun_id);
    if (outer_id == INVALID_OUTER_ID) {
        return netdev_dpdk_tun_outer_id_alloc(ip_dst, ip_src, tun_id);
    }
    return outer_id;
}

/* Unref and a tun. if refcnt is zero we free the outer_id.
 * Every offloaded flow that used outer_id should unref it when del called.
 */
static void
netdev_dpdk_tun_id_unref(ovs_be32 ip_dst, ovs_be32 ip_src,
                                       ovs_be64 tun_id)
{
    netdev_dpdk_tun_outer_id_unref(ip_dst, ip_src, tun_id);
}

static void
netdev_dpdk_outer_id_unref(uint32_t outer_id)
{
    struct tun_ctx_outer_id_data *data = netdev_dpdk_tun_data_find(outer_id);
    if (data) {
        netdev_dpdk_tun_outer_id_unref(data->ip_dst, data->ip_src,
                                       data->tun_id);
    }
}

enum ct_offload_dir {
    CT_OFFLOAD_DIR_INIT = 0,
    CT_OFFLOAD_DIR_REP =  1,
    CT_OFFLOAD_NUM = 2
};


enum mark_preprocess_type {
    MARK_PREPROCESS_CT = 1 << 0,
    MARK_PREPROCESS_FLOW_CT = 1 << 1,
    MARK_PREPROCESS_FLOW = 1 << 2,
    MARK_PREPROCESS_VXLAN = 1 << 3
};

/*
 * A mapping from ufid to to CT rte_flow.
 */
static struct cmap mark_to_ct_ctx = CMAP_INITIALIZER;

struct mark_preprocess_info {
    struct cmap mark_to_ct_ctx;
};

struct mark_preprocess_info mark_preprocess_info = {
    .mark_to_ct_ctx = CMAP_INITIALIZER,
};

#define INVALID_IN_PORT 0xffff

struct mark_to_miss_ctx_data {
    struct cmap_node node;
    uint32_t mark;
    int type;
    union {
        struct {
            uint32_t ct_mark;
            uint16_t ct_zone;
            uint8_t  ct_state;
            struct ct_flow_offload_item *ct_offload[CT_OFFLOAD_NUM];
            uint32_t outer_id[CT_OFFLOAD_NUM];
            uint16_t odp_port[CT_OFFLOAD_NUM];
            struct rte_flow *rte_flow[CT_OFFLOAD_NUM];
         } ct;
        struct {
            uint16_t outer_id;
            uint32_t hw_id;
            bool     is_port;
            uint32_t in_port;
        } flow;
    };
};

static inline void
netdev_dpdk_release_ct_flow(struct mark_to_miss_ctx_data *data,
                            enum ct_offload_dir dir)
{
    if (data->ct.rte_flow[dir]) {
        /* TODO: destroy rte_flow */
        data->ct.rte_flow[dir] = NULL;
    }
    data->ct.odp_port[dir] = INVALID_IN_PORT;
    if (data->ct.outer_id[dir] != INVALID_OUTER_ID) {
        netdev_dpdk_outer_id_unref(data->ct.outer_id[dir]);
        data->ct.outer_id[dir] = INVALID_OUTER_ID;
    }
    if (data->ct.ct_offload[dir]) {
        free(data->ct.ct_offload[dir]);
        data->ct.ct_offload[dir] = NULL;
    }
}

static bool
netdev_dpdk_find_miss_ctx(uint32_t mark, struct mark_to_miss_ctx_data **ctx)
{
    size_t hash = hash_add(0,mark);
    struct mark_to_miss_ctx_data *data;

    CMAP_FOR_EACH_WITH_HASH (data, node, hash,
            &mark_preprocess_info.mark_to_ct_ctx) {
        if (data->mark == mark) {
            *ctx = data;
            return true;
        }
    }

    return false;
}

static struct mark_to_miss_ctx_data *
netdev_dpdk_get_flow_miss_ctx(uint32_t mark)
{
    struct mark_to_miss_ctx_data * data = NULL;

    if (!netdev_dpdk_find_miss_ctx(mark, &data)) {
        size_t hash = hash_add(0,mark);
        data = xzalloc(sizeof *data);
        data->mark = mark;
        data->ct.outer_id[CT_OFFLOAD_DIR_REP] = INVALID_OUTER_ID;
        data->ct.outer_id[CT_OFFLOAD_DIR_INIT] = INVALID_OUTER_ID;
        data->ct.odp_port[CT_OFFLOAD_DIR_REP] = INVALID_IN_PORT;
        data->ct.odp_port[CT_OFFLOAD_DIR_INIT] = INVALID_IN_PORT;
        cmap_insert(&mark_to_ct_ctx,
                CONST_CAST(struct cmap_node *, &data->node), hash);
    }

   return data;
}

static int
netdev_dpdk_save_flow_miss_ctx(uint32_t mark, uint32_t hw_id, bool is_port,
                               uint32_t outer_id, uint32_t in_port,
                               bool has_ct)
{
    struct mark_to_miss_ctx_data * data = netdev_dpdk_get_flow_miss_ctx(mark);
    if (!data) {
        return -1;
    }

    data->type = has_ct?MARK_PREPROCESS_FLOW_CT:MARK_PREPROCESS_FLOW;
    data->mark = mark;
    data->flow.outer_id = outer_id;
    data->flow.hw_id = hw_id;
    data->flow.is_port = is_port;
    data->flow.in_port = in_port;
    return 0;
}

static int
netdev_dpdk_save_ct_miss_ctx(uint32_t mark, struct rte_flow *flow,
                        uint32_t ct_mark, uint16_t ct_zone,
                        uint8_t  ct_state, uint16_t  outer_id, bool reply)
{
    int idx;
    struct mark_to_miss_ctx_data * data = netdev_dpdk_get_flow_miss_ctx(mark);
    if (!data) {
        return -1;
    }

    data->type = MARK_PREPROCESS_CT;
    data->mark = mark;
    data->ct.ct_mark = ct_mark;
    data->ct.ct_zone = ct_zone;
    data->ct.ct_state = ct_state;
    data->ct.outer_id[idx] = outer_id;
    idx = reply?CT_OFFLOAD_DIR_REP:CT_OFFLOAD_DIR_INIT;
    if (data->ct.rte_flow[idx]) {
        VLOG_WARN("flow already exist");
        return -1;
    }
    data->ct.rte_flow[idx] = flow;
    return 0;
}

static void
netdev_dpdk_del_miss_ctx(uint32_t mark)
{
    size_t hash = hash_add(0,mark);
    struct mark_to_miss_ctx_data *data;

    CMAP_FOR_EACH_WITH_HASH (data, node, hash,
                      &mark_preprocess_info.mark_to_ct_ctx) {
        if (data->mark == mark) {
                cmap_remove(&mark_to_ct_ctx,
                        CONST_CAST(struct cmap_node *, &data->node), hash);
                ovsrcu_postpone(free, data);
                return;
        }
    }
}

static inline void
netdev_dpdk_tun_recover_meta_data(struct dp_packet *p, uint32_t outer_id)
{
    struct tun_ctx_outer_id_data *data = netdev_dpdk_tun_data_find(outer_id);
    if (data) {
        p->md.tunnel.ip_dst = data->ip_dst;
        p->md.tunnel.ip_src = data->ip_src;
        p->md.tunnel.tun_id = data->tun_id;
    }
}

static void
netdev_dpdk_ct_recover_metadata(struct dp_packet *p,
                           struct  mark_to_miss_ctx_data *ct_ctx)
{
    int dir = CT_OFFLOAD_DIR_INIT;
    if (p->md.in_port.odp_port == ct_ctx->ct.odp_port[CT_OFFLOAD_DIR_REP]) {
        dir = CT_OFFLOAD_DIR_REP;
    }
    if (ct_ctx->ct.outer_id) {
        netdev_dpdk_tun_recover_meta_data(p, ct_ctx->ct.outer_id[dir]);
    }

    /*uint32_t recirc_id;*/
    p->md.ct_state = ct_ctx->ct.ct_state;
    p->md.ct_zone  = ct_ctx->ct.ct_zone;
    p->md.ct_mark  = ct_ctx->ct.ct_mark;
    p->md.ct_state = ct_ctx->ct.ct_state;
}

void
netdev_dpdk_offload_preprocess(struct dp_packet *p)
{
    uint32_t mark;
    struct mark_to_miss_ctx_data *ct_ctx;

    if (!dp_packet_has_flow_mark(p, &mark)) {
        return;
    }

    if (netdev_dpdk_find_miss_ctx(mark, &ct_ctx)) {
        switch (ct_ctx->type) {
            case MARK_PREPROCESS_CT:
                netdev_dpdk_ct_recover_metadata(p,ct_ctx);
                break;
            case MARK_PREPROCESS_FLOW_CT:
                VLOG_WARN("not supported yet");
                break;
            case MARK_PREPROCESS_VXLAN:
                VLOG_WARN("not supported yet");
                break;
        }
    }
}

struct hw_table_id_node {
    struct cmap_node node;
    uint32_t id;
    int      hw_id;
    int      is_port;
    int      ref_cnt;
};

struct hw_table_id {
    struct cmap recirc_id_to_tbl_id_map;
    struct cmap port_id_to_tbl_id_map;
    struct id_pool *pool;
    uint32_t hw_id_to_sw[MAX_OUTER_ID];
};

struct hw_table_id hw_table_id = {
    .recirc_id_to_tbl_id_map = CMAP_INITIALIZER,
    .port_id_to_tbl_id_map = CMAP_INITIALIZER,
};

static int
netdev_dpdk_get_hw_id(uint32_t id, uint32_t *hw_id, bool is_port)
{
    size_t hash = hash_add(0,id);
    struct hw_table_id_node *data;
    struct cmap *smap = is_port ?&hw_table_id.port_id_to_tbl_id_map:
                               &hw_table_id.recirc_id_to_tbl_id_map;

    CMAP_FOR_EACH_WITH_HASH (data, node, hash, smap) {
        if (data->id == id && data->is_port == is_port) {
            *hw_id = data->hw_id;
            data->ref_cnt++;
            return 0;
        }
    }

    return -1;
}

static void
netdev_dpdk_put_hw_id(uint32_t id, bool is_port)
{
    size_t hash = hash_add(0,id);
    struct hw_table_id_node *data;
    struct cmap *smap = is_port? &hw_table_id.port_id_to_tbl_id_map:
                               &hw_table_id.recirc_id_to_tbl_id_map;

    CMAP_FOR_EACH_WITH_HASH (data, node, hash, smap) {
        if (data->id == id && data->is_port == is_port) {
            data->ref_cnt--;
            if (data->ref_cnt == 0) {
                /*TODO: delete table (if recirc_id*/
                /*TODO: update mapping table.*/
                id_pool_free_id(hw_table_id.pool, data->hw_id);
                ovsrcu_postpone(free, data);
            }
            return;
        }
    }
}

static int
netdev_dpdk_alloc_hw_id(uint32_t id, bool is_port)
{
    size_t hash = hash_add(0,id);
    uint32_t hw_id;
    struct cmap *smap = is_port? &hw_table_id.port_id_to_tbl_id_map:
                               &hw_table_id.recirc_id_to_tbl_id_map;
    struct hw_table_id_node *data;

    if (!id_pool_alloc_id(hw_table_id.pool, &hw_id)) {
        return INVALID_HW_ID;
    }

    data = xzalloc(sizeof *data);
    data->hw_id = hw_id;
    data->is_port = is_port;
    data->id = id;
    data->ref_cnt = 1;

    cmap_insert(smap, CONST_CAST(struct cmap_node *, &data->node), hash);

    /*  create HW table with the id. update mapping table */
   /*TODO: create new table in HW with that id (if not port).*/
   /*TODO: fill mapping table with the new informatio.*/


    return hw_id;
}

static inline void
netdev_dpdk_hw_id_init(void)
{
     if (!hw_table_id.pool) {
        /*TODO: set it default, also make sure we don't overflow*/
        hw_table_id.pool = id_pool_create(64, MAX_HW_TABLE);
        memset(hw_table_id.hw_id_to_sw, 0, sizeof hw_table_id.hw_id_to_sw);
    }
}

static int
netdev_dpdk_get_recirc_id_hw_id(uint32_t recirc_id, uint32_t *hw_id)
{
    netdev_dpdk_hw_id_init();
    if (netdev_dpdk_get_hw_id(recirc_id, hw_id, false)) {
        return *hw_id;
    }

    return netdev_dpdk_alloc_hw_id(recirc_id, false);
}

static int
netdev_dpdk_get_port_id_hw_id(uint32_t port_id, uint32_t *hw_id)
{
    netdev_dpdk_hw_id_init();

    if (netdev_dpdk_get_hw_id(port_id, hw_id, true)) {
        return *hw_id;
    }

    return netdev_dpdk_alloc_hw_id(port_id, true);
}

static void
netdev_dpdk_put_recirc_id_hw_id(uint32_t recirc_id)
{
    netdev_dpdk_put_hw_id(recirc_id, false);
}
static void
netdev_dpdk_put_port_id_hw_id(uint32_t port_id)
{
    netdev_dpdk_put_hw_id(port_id, true);
}

static int
netdev_dpdk_get_sw_id_from_hw_id(uint16_t hw_id)
{
    return hw_table_id.hw_id_to_sw[hw_id];
}

enum {
  MATCH_OFFLOAD_TYPE_UNDEFINED    =  0,
  MATCH_OFFLOAD_TYPE_ROOT         =  1 << 0,
  MATCH_OFFLOAD_TYPE_VPORT_ROOT   =  1 << 1,
  MATCH_OFFLOAD_TYPE_RECIRC       =  1 << 2,
  ACTION_OFFLOAD_TYPE_TNL_POP     =  1 << 3,
  ACTION_OFFLOAD_TYPE_CT          =  1 << 4,
  ACTION_OFFLOAD_TYPE_OUTPUT      =  1 << 5,
};

struct offload_item_cls_info {
    struct {
        uint32_t recirc_id;
        ovs_be32 ip_dst;
        ovs_be32 ip_src;
        ovs_be64 tun_id;
        int type;
        bool vport;
        uint32_t outer_id;
        uint32_t hw_id;
    } match;

    struct {
        bool has_ct;
        bool has_nat;
        uint16_t zone;
        uint32_t recirc_id;
        uint32_t hw_id;
        uint32_t odp_port;
        bool valid;
        int type;
        bool pop_tnl;
    } actions;
};

static void
netdev_dpdk_offload_fill_cls_info(struct offload_item_cls_info *cls_info,
                             struct match *match, struct nlattr *actions,
                             size_t actions_len)

{
    unsigned int left;
    const struct nlattr *a;
    struct match match_zero_wc;

    /*TODO: find if in_port is vport or not.*/
    /* cls_info.match.vport = find_is_vport(match->flow.in_port.odp_port);*/
    /* Create a wc-zeroed version of flow. */
    match_init(&match_zero_wc, &match->flow, &match->wc);

    /* if we have recirc_id in match */
    if (match_zero_wc.flow.recirc_id) {
        cls_info->match.recirc_id = match->flow.recirc_id;
    }

    if (!is_all_zeros(&match_zero_wc.flow.tunnel,
                      sizeof match_zero_wc.flow.tunnel)) {
        cls_info->match.ip_dst = match->flow.tunnel.ip_dst;
        cls_info->match.ip_src = match->flow.tunnel.ip_src;
        cls_info->match.tun_id = match->flow.tunnel.tun_id;
    }

    NL_ATTR_FOR_EACH_UNSAFE (a, left, actions, actions_len) {
        int type = nl_attr_type(a);
        bool last_action = (left <= NLA_ALIGN(a->nla_len));

        switch ((enum ovs_action_attr) type) {
            case OVS_ACTION_ATTR_CT: {
                unsigned int left_ct;
                const struct nlattr *b;
                cls_info->actions.has_ct = true;

                NL_ATTR_FOR_EACH_UNSAFE (b, left_ct, nl_attr_get(a),
                                 nl_attr_get_size(a)) {
                    enum ovs_ct_attr sub_type = nl_attr_type(b);

                    switch (sub_type) {
                            case OVS_CT_ATTR_NAT:
                                cls_info->actions.has_nat = true;
                                break;
                            case OVS_CT_ATTR_FORCE_COMMIT:
                                break;
                            case OVS_CT_ATTR_COMMIT:
                                break;
                            case OVS_CT_ATTR_ZONE:
                                cls_info->actions.zone = nl_attr_get_u16(b);
                                break;
                            case OVS_CT_ATTR_HELPER:
                            case OVS_CT_ATTR_MARK:
                            case OVS_CT_ATTR_LABELS:
                            case OVS_CT_ATTR_EVENTMASK:
                            case OVS_CT_ATTR_UNSPEC:
                            case __OVS_CT_ATTR_MAX:
                            default:
                                break;
                       }
                    }
                }
                break;
            case OVS_ACTION_ATTR_OUTPUT:
                cls_info->actions.odp_port = nl_attr_get_odp_port(a);
                if (!last_action) {
                    cls_info->actions.valid = false;
                }
                break;
            case OVS_ACTION_ATTR_RECIRC:
                    cls_info->actions.recirc_id = nl_attr_get_u32(a);
                if (!last_action) {
                    cls_info->actions.valid = false;
                }
                break;

                case OVS_ACTION_ATTR_PUSH_VLAN:
                /*TODO: need it*/
                    break;
                case OVS_ACTION_ATTR_POP_VLAN:     /* No argument. */
                /*TODO: need it*/
                    break;
                case OVS_ACTION_ATTR_TUNNEL_POP:    /* u32 port number. */
                    cls_info->actions.pop_tnl = true;
                    cls_info->actions.odp_port = nl_attr_get_odp_port(a);
                    break;;
                case OVS_ACTION_ATTR_SET:
                /*TODO: set baidu set eth here.*/

                break;
                case OVS_ACTION_ATTR_CLONE:
                /*TODO: verify if tnl_pop or tnl_push,*/
                break;
                case OVS_ACTION_ATTR_HASH:
                case OVS_ACTION_ATTR_UNSPEC:
                case OVS_ACTION_ATTR_USERSPACE:
                case OVS_ACTION_ATTR_SAMPLE:
                case OVS_ACTION_ATTR_PUSH_MPLS:
                case OVS_ACTION_ATTR_POP_MPLS:
                case OVS_ACTION_ATTR_SET_MASKED:
                case OVS_ACTION_ATTR_TRUNC:
                case OVS_ACTION_ATTR_PUSH_ETH:
                case OVS_ACTION_ATTR_POP_ETH:
                case OVS_ACTION_ATTR_CT_CLEAR:
                case OVS_ACTION_ATTR_PUSH_NSH:
                case OVS_ACTION_ATTR_POP_NSH:
                case OVS_ACTION_ATTR_METER:
                case OVS_ACTION_ATTR_CHECK_PKT_LEN:
                case OVS_ACTION_ATTR_TUNNEL_PUSH:
                    /*TODO: replace with counter. so log won't be flooded */
                    VLOG_WARN("unsupported offload action %d",type);
                    cls_info->actions.valid = false;
                    break;
                case __OVS_ACTION_ATTR_MAX:
                default:
                    VLOG_ERR("action %d",type);
        }
    }
}


static int
netdev_dpdk_offload_classify(struct offload_item_cls_info *cls_info,
                             struct match *match, struct nlattr *actions,
                             size_t actions_len)

{
    int ret = 0;

    if (!netdev_rte_offloads_validate_flow(match, false, false)) {
        return -1;
    }

    netdev_dpdk_offload_fill_cls_info(cls_info, match, actions, actions_len);

    /* some scenario we cannot support */
    if (cls_info->actions.valid) {
        return -1;
    }

    if (cls_info->match.recirc_id == 0) {
        if (cls_info->match.vport) {
            cls_info->match.type = MATCH_OFFLOAD_TYPE_VPORT_ROOT;
            /*todo: NEED TO VALIDATE THIS IS VXLAN PORT OR ELSE */
            /*OFFLOAD IS NOT VALID */
        } else {
            cls_info->match.type = MATCH_OFFLOAD_TYPE_ROOT;
        }
    } else {
            cls_info->match.type = MATCH_OFFLOAD_TYPE_RECIRC;
    }

    if (cls_info->actions.pop_tnl) {
        cls_info->actions.type = ACTION_OFFLOAD_TYPE_TNL_POP;
        /*TODO: validate tnl pop type (VXLAN/GRE....) is supported and we*/
    } else if (cls_info->actions.has_ct) {
        cls_info->actions.type = ACTION_OFFLOAD_TYPE_CT;
    } else if (cls_info->actions.odp_port) {
        cls_info->actions.type = ACTION_OFFLOAD_TYPE_OUTPUT;
    }
    return ret;
}

static int
netdev_dpdk_offload_add_root_patterns(struct flow_patterns *patterns,
                             struct match *match)
{
    /*TODO: here we should add all eth/ip/....etc patterns*/
    return 0;
}

static int
netdev_dpdk_offload_add_vport_root_patterns(struct flow_patterns *patterns,
                             struct match *match,
                             struct offload_item_cls_info *cls_info)
{
    cls_info->match.outer_id = netdev_dpdk_tun_id_get_ref(
                                       cls_info->match.ip_dst,
                                       cls_info->match.ip_src,
                                       cls_info->match.tun_id);

    if (cls_info->match.outer_id == INVALID_OUTER_ID) {
        return -1;
    }

    /*TODO: here we add all TUN info (match->flow.tnl....)*/
    /*TODO: we then call the regular root to add the rest*/
    netdev_dpdk_offload_add_root_patterns(patterns, match);
    return 0;
}

static int
netdev_dpdk_offload_add_recirc_patterns(struct flow_patterns *patterns,
                             struct match *match,
                             struct offload_item_cls_info *cls_info)
{
    const struct flow *masks = &match->wc.masks;

    /* find available hw_id for recirc_id */
    if (netdev_dpdk_get_recirc_id_hw_id(cls_info->match.recirc_id,
                                        &cls_info->match.hw_id) ==
                                        INVALID_HW_ID) {
        return -1;
    }

    if (cls_info->match.tun_id) {
        /* if we should match tun id */
        cls_info->match.outer_id = netdev_dpdk_tun_id_get_ref(
                                       cls_info->match.ip_dst,
                                       cls_info->match.ip_src,
                                       cls_info->match.tun_id);
        if (cls_info->match.outer_id == INVALID_OUTER_ID) {
            return -1;
        }
        netdev_dpdk_add_pattern_match_reg(patterns, REG_OUTER_ID,
                                          cls_info->match.outer_id);
    }

    netdev_dpdk_offload_add_root_patterns(patterns, match);
    /* replace md matches with reg matches */
    if (masks->ct_state ||
        masks->ct_zone  || masks->ct_mark) {
        if (masks->ct_state) {
            netdev_dpdk_add_pattern_match_reg(patterns, REG_STATE,
                                              match->flow.ct_state);
        }
        if (masks->ct_zone) {
            netdev_dpdk_add_pattern_match_reg(patterns, REG_ZONE,
                                              match->flow.ct_zone);
        }

        if (masks->ct_mark) {
            netdev_dpdk_add_pattern_match_reg(patterns, REG_MARK,
                                              match->flow.ct_mark);
        }
    }
    return 0;
}

static int
netdev_dpdk_offload_vxlan_actions(struct flow_actions *flow_actions,
                                  struct offload_item_cls_info *cls_info)
{
    int ret = 0;
    /*TODO: getv xlan portt id, create table for the port.*/
    /*TODO: add counter on flow */
    /*TODO: add jump to vport table. */
    return ret;
}

static inline int
netdev_dpdk_offload_get_hw_id(struct offload_item_cls_info *cls_info)
{
    int ret =0;
    if (cls_info->actions.recirc_id) {
        if (netdev_dpdk_get_recirc_id_hw_id(cls_info->actions.recirc_id,
                                        &cls_info->actions.hw_id) ==
                                        INVALID_HW_ID) {
            ret = -1;
        }
    } else {
        if (netdev_dpdk_get_port_id_hw_id(cls_info->actions.odp_port,
                                        &cls_info->actions.hw_id) ==
                                        INVALID_HW_ID) {
            ret = -1;
        }
    }
    return ret;
}


static int
netdev_dpdk_offload_ct_actions(struct flow_actions *flow_actions,
                               struct offload_item_cls_info *cls_info,
                                                struct nlattr *actions,
                                                size_t actions_len)
{
    int ret = 0;
    /* match on vport recirc_id = 0, we must decap first */
    if (cls_info->match.type == MATCH_OFFLOAD_TYPE_VPORT_ROOT) {
        /*TODO: add decap */
    }

    /*TODO: set mark cls_info->mark*/
    /*TODO: add counter */
    /* translate recirc_id or port_id to hw_id */
    if (!netdev_dpdk_offload_get_hw_id(cls_info)) {
        return -1;
    }
    /* TODO: set hw_id in reg_recirc , will be used by mapping table */
    if (!netdev_dpdk_add_action_set_reg(flow_actions, REG_RECIRC_ID,
                                        cls_info->actions.hw_id)) {
        return -1;
    }
    /* TODO: add all actions until CT
     * read all actions for actions and add them to rte_flow 
     * can push_vlan, set_eth...etc */
    if (cls_info->actions.has_nat) {
        /* TODO: we need to create the table if doesn't exists */
        /* TODO: jump to nat table */
    } else {
        /*TODO: we need to create the table if doesn't exists */
        /*TODO: jump to CT table */
    }
    return ret;
}

static int
netdev_dpdk_offload_output_actions(struct flow_actions *flow_actions,
                               struct offload_item_cls_info *cls_info,
                                                struct nlattr *actions,
                                                size_t actions_len)
{
    int ret = 0;
    /* match on vport recirc_id = 0, we must decap first */
    if (cls_info->match.type == MATCH_OFFLOAD_TYPE_VPORT_ROOT) {
        /*TODO: add decap */
    }

    /* TODO: add counter */
    /* TODO: add all actions including output */
    return ret;
}

static int
netdev_dpdk_offload_put_add_patterns(struct flow_patterns *patterns,
                                  struct match *match,
                                  struct offload_item_cls_info *cls_info)
{
    switch (cls_info->match.type) {
        case MATCH_OFFLOAD_TYPE_ROOT:
            return netdev_dpdk_offload_add_root_patterns(patterns, match);
        case MATCH_OFFLOAD_TYPE_VPORT_ROOT:
            return netdev_dpdk_offload_add_vport_root_patterns(patterns, match,
                                                              cls_info);
        case MATCH_OFFLOAD_TYPE_RECIRC:
            return netdev_dpdk_offload_add_recirc_patterns(patterns, match,
                                                          cls_info);
    }

    VLOG_WARN("unexpected offload match type %d",cls_info->match.type);
    return -1;
}

static int
netdev_dpdk_offload_put_add_actions(struct flow_actions *flow_actions,
                                    struct match *match,
                                    struct nlattr *actions,
                                    size_t actions_len,
                                    struct offload_item_cls_info *cls_info)
{
    switch (cls_info->actions.type) {
        case ACTION_OFFLOAD_TYPE_TNL_POP:
            /*TODO: need to verify the POP is the only action here.*/
            return  netdev_dpdk_offload_vxlan_actions(flow_actions, cls_info);
        case ACTION_OFFLOAD_TYPE_CT:
            return netdev_dpdk_offload_ct_actions(flow_actions, cls_info,
                                                 actions, actions_len);
            break;
        case ACTION_OFFLOAD_TYPE_OUTPUT:
            return netdev_dpdk_offload_output_actions(flow_actions, cls_info,
                                                    actions, actions_len);
    }
    VLOG_WARN("unexpected offload action type %d",cls_info->actions.type);
    return -1;
}


static void
netdev_dpdk_offload_put_handle(struct match *match, struct nlattr *actions,
                             size_t actions_len, uint32_t flow_mark)
{
    struct offload_item_cls_info cls_info;
    memset(&cls_info, 0, sizeof cls_info);
    int ret = 0;

    struct flow_patterns patterns = { .items = NULL, .cnt = 0 };
    struct flow_actions  flow_actions = { .actions = NULL, .cnt = 0 };

    if (!netdev_dpdk_offload_classify(&cls_info, match,
                                       actions, actions_len)) {
        return;
    }

    if (!netdev_dpdk_offload_put_add_patterns(&patterns, match, &cls_info)) {
        goto roll_back;
    }

    if (!netdev_dpdk_offload_put_add_actions(&flow_actions, match,
                                    actions, actions_len, &cls_info)) {
        goto roll_back;
    }

    /* handle miss in HW in CT need special handling */
    /* for all cases, we need to save all resources allocated */
    if (cls_info.actions.type == ACTION_OFFLOAD_TYPE_CT) {
            ret = netdev_dpdk_save_flow_miss_ctx(flow_mark,
                             cls_info.actions.hw_id,
                             !cls_info.actions.recirc_id,
                             cls_info.match.outer_id,
                             match->flow.in_port.odp_port,
                             cls_info.actions.type == ACTION_OFFLOAD_TYPE_CT);
    }

    if (!ret) {
        goto roll_back;
    }

    /* TODO: OFFLOAD FLOW HERE */
    /* if fail goto roleback. */


    return;
roll_back:
    /* release references that were allocated */
    if (cls_info.match.outer_id != INVALID_OUTER_ID) {
        netdev_dpdk_tun_outer_id_unref(cls_info.match.ip_dst,
                                       cls_info.match.ip_src,
                                       cls_info.match.tun_id);
    }

    if (cls_info.match.hw_id != INVALID_HW_ID) {
        netdev_dpdk_put_recirc_id_hw_id(cls_info.match.hw_id);
    }

    if (cls_info.actions.hw_id != INVALID_HW_ID) {
        if (cls_info.actions.recirc_id) {
            netdev_dpdk_put_recirc_id_hw_id(cls_info.actions.hw_id);
        } else {
            netdev_dpdk_put_port_id_hw_id(cls_info.actions.hw_id);
        }
    }
    netdev_dpdk_del_miss_ctx(flow_mark);
}

static void
netdev_dpdk_offload_del_handle(uint32_t mark)
{
     /* from the mark we get also the in_port.. */
     struct mark_to_miss_ctx_data *data = netdev_dpdk_get_flow_miss_ctx(mark);
     if (!data) {
        /* TODO: need to think if we need warn here. */
        return;
     }

    if (data->flow.outer_id) {
        netdev_dpdk_outer_id_unref(data->flow.outer_id);
    }

    if (data->flow.hw_id) {
        uint32_t sw_id = netdev_dpdk_get_sw_id_from_hw_id(data->flow.hw_id);
        if (data->flow.is_port) {
            netdev_dpdk_put_port_id_hw_id(sw_id);
        } else {
            netdev_dpdk_put_recirc_id_hw_id(sw_id);
        }
    }

    netdev_dpdk_del_miss_ctx(mark);
}

static inline enum ct_offload_dir
netdev_dpdk_offload_ct_opposite_dir(enum ct_offload_dir dir)
{
    return dir == CT_OFFLOAD_DIR_INIT?CT_OFFLOAD_DIR_REP:CT_OFFLOAD_DIR_INIT;
}

static struct ct_flow_offload_item *
netdev_dpdk_offload_ct_dup(struct ct_flow_offload_item *ct_offload)
{
    struct ct_flow_offload_item *data = xzalloc(sizeof *data);
    if (data) {
        memcpy(data, ct_offload, sizeof *data);
    }
    return data;
}

static int
netdev_dpdk_ct_add_ipv4_5tuple_pattern(struct flow_patterns *patterns,
                                        struct ovs_key_ct_tuple_ipv4 *ct_match)
{
    struct flow_items {
        struct rte_flow_item_ipv4 ipv4;
        union {
            struct rte_flow_item_tcp  tcp;
            struct rte_flow_item_udp  udp;
            struct rte_flow_item_icmp icmp;
        };
    } spec, mask;

    spec.ipv4.hdr.next_proto_id   = ct_match->ipv4_proto;
    spec.ipv4.hdr.src_addr        = ct_match->ipv4_src;
    spec.ipv4.hdr.dst_addr        = ct_match->ipv4_dst;

    /* TODO: this can be unified with other matches, providing mask */
    mask.ipv4.hdr.type_of_service = 0;
    mask.ipv4.hdr.time_to_live    = 0;
    mask.ipv4.hdr.next_proto_id   = 0;
    mask.ipv4.hdr.src_addr        = 0xffffffff;
    mask.ipv4.hdr.dst_addr        = 0xffffffff;

    add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_IPV4,
                     &spec.ipv4, &mask.ipv4);

    switch (ct_match->ipv4_proto) {
    case IPPROTO_TCP:
        spec.tcp.hdr.src_port  = ct_match->src_port;
        spec.tcp.hdr.dst_port  = ct_match->dst_port;
        /* TODO: need to skip rst/fin */
        /*spec.tcp.hdr.tcp_flags = ntohs(match->flow.tcp_flags) & 0xff;*/

        mask.tcp.hdr.src_port  = 0xffff;
        mask.tcp.hdr.dst_port  = 0xffff;
        mask.tcp.hdr.data_off  = 0;
        mask.tcp.hdr.tcp_flags = 0; /* FLAGS & 0xff */
        mask.ipv4.hdr.next_proto_id = 0;

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_TCP,
                     &spec.tcp, &mask.tcp);
    break;

    case IPPROTO_UDP:
        spec.udp.hdr.src_port = ct_match->src_port;
        spec.udp.hdr.dst_port = ct_match->dst_port;

        mask.udp.hdr.src_port = 0xffff;
        mask.udp.hdr.dst_port = 0xffff;

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_UDP,
                         &spec.udp, &mask.udp);

        /* proto == UDP and ITEM_TYPE_UDP, thus no need for proto match. */
        break;

    case IPPROTO_SCTP:
        /* We don't support in CT */
        return -1;
       break;

    case IPPROTO_ICMP:
       /* We don't support, might need to */
        return -1;
        break;
    }

    add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_END, NULL, NULL);
    return 0;
}

static int
netdev_dpdk_add_jump_to_mapping_actions(struct flow_actions *actions
                                        /*, rte_port */)
{
    struct rte_flow_action_jump jump = {0};
    /* TODO: fill the right mapping table id */
    /* TODO: since we hhave one, better to just alloc 
     * one per port on start, no need for ref count! */
    int hw_map_tbl_id = 0; 
    jump.group = hw_map_tbl_id;
    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_JUMP, &jump);
    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_END, NULL);
    return 0;
}

static inline void
netdev_dpdk_reset_patterns(struct flow_patterns *patterns)
{
    free(patterns->items);
    patterns->cnt = 0;
    patterns->items = NULL;
}

static inline void
netdev_dpdk_reset_actions(struct flow_actions *actions)
{
    free(actions->actions);
    actions->cnt = 0;
    actions->actions = NULL;
}


static struct rte_flow *
netdev_dpdk_ct_build_session_offload(struct ct_flow_offload_item *item, 
                                     uint16_t outer_id)
{
    struct rte_flow * flow = NULL;
    int ret = 0;
    struct flow_patterns patterns = { .items = NULL, .cnt = 0 };
    struct flow_actions  actions = { .actions = NULL, .cnt = 0 };

    if (item->ct_ipv6) {
        /* TODO: offload ipv6 */
        VLOG_ERR("IPV6 not suppored yet");
        return NULL;
    } else {
        ret |= netdev_dpdk_ct_add_ipv4_5tuple_pattern(&patterns,
                                           &item->ct_match.ipv4);
        /* if outer_id != INVALID we need to set register */
        ret |= netdev_dpdk_add_jump_to_mapping_actions(&actions);
    }

    if (!ret) {
    /* offload here
    * offload the flow to the in_port if not a VXLAN , if
    * it is vxlan port, we need to offload to pf!!!!
    * TODO: offload rte flow in rte_port and with mark */
    }
    netdev_dpdk_reset_patterns(&patterns);
    netdev_dpdk_reset_actions(&actions);

    return flow;
}

static int
netdev_dpdk_ct_ctx_get_ref_outer_id(struct mark_to_miss_ctx_data *data,
                                    struct ct_flow_offload_item *ct_offload1,
                                    struct ct_flow_offload_item *ct_offload2)
{
    int dir1 = ct_offload1->reply?CT_OFFLOAD_DIR_REP:CT_OFFLOAD_DIR_INIT;
    int dir2 = ct_offload2->reply?CT_OFFLOAD_DIR_REP:CT_OFFLOAD_DIR_INIT;

    if (ct_offload1->tun.ip_dst) {
        data->ct.outer_id[dir1] = netdev_dpdk_tun_id_get_ref(
                                       ct_offload1->tun.ip_dst,
                                       ct_offload1->tun.ip_src,
                                       ct_offload1->tun.tun_id);
        if (data->ct.outer_id[dir1] == INVALID_OUTER_ID) {
            /* TODO: warn or counter, we can't offload */
            return -1;
        }
    }
    if (ct_offload1->tun.ip_dst) {
        data->ct.outer_id[dir2] = netdev_dpdk_tun_id_get_ref(
                                       ct_offload2->tun.ip_dst,
                                       ct_offload2->tun.ip_src,
                                       ct_offload2->tun.tun_id);
        if (data->ct.outer_id[dir2] == INVALID_OUTER_ID) {
            /* TODO: warn or counter, we can't offload */
            return -1;
        }
    }
    return 0;
}

/* Build 2 HW flows, one per direction and offload to relevant port.
 * (Each side of the flow will be offloded to different port id).
 * If NAT is also configured than two additional flows should be
 * configured.
 *
 * resource allocation:
 * if offload has TUN data, an outer_id should be allocated and used.
 *
 */
static int
netdev_dpdk_offload_ct_session(struct mark_to_miss_ctx_data *data,
                               struct ct_flow_offload_item *ct_offload1,
                               struct ct_flow_offload_item *ct_offload2)
{
    struct rte_flow * flow = NULL;
    int dir1 = ct_offload1->reply?CT_OFFLOAD_DIR_REP:CT_OFFLOAD_DIR_INIT;
    int dir2 = ct_offload2->reply?CT_OFFLOAD_DIR_REP:CT_OFFLOAD_DIR_INIT;

    if (dir1 == dir2) {
        /* TODO: add warning */
        VLOG_ERR("got two established events on same dir");
        goto fail;
    }

    if (!netdev_dpdk_ct_ctx_get_ref_outer_id(data, ct_offload1, ct_offload2)) {
        goto fail;
    }

    flow = netdev_dpdk_ct_build_session_offload(ct_offload1, 
                                                data->ct.outer_id[dir1]);
    if (flow) {
        goto fail;
    }
    data->ct.rte_flow[dir1] = flow;
    data->ct.odp_port[dir1] = ct_offload1->odp_port;

    flow = netdev_dpdk_ct_build_session_offload(ct_offload2, 
                                                data->ct.outer_id[dir2]);
    if (!flow) {
        goto fail;
    }
    data->ct.rte_flow[dir2] = flow;
    data->ct.odp_port[dir2] = ct_offload2->odp_port;

    /* TODO: hanlde NAT 
     * for nat we need the exact same match, but we need to add
     * modify action on the needed header fields */
    return 0;
fail:
    netdev_dpdk_release_ct_flow(data, dir1);
    netdev_dpdk_release_ct_flow(data, dir2);
    return -1;
}

static void
netdev_dpdk_offload_ct_ctx_update(struct mark_to_miss_ctx_data *data,
                               struct ct_flow_offload_item *ct_offload1,
                               struct ct_flow_offload_item *ct_offload2)
{
    /* all are paremeters of the session ctx, if it is not zero
     * it is expedted that both will have same value */
    data->ct.ct_zone = ct_offload1->zone?ct_offload1->zone:ct_offload2->zone;
    data->ct.ct_mark = ct_offload1->setmark?
                       ct_offload1->setmark:ct_offload2->setmark;
    data->ct.ct_state = ct_offload1->ct_state | ct_offload2->ct_state;
}


/* Offload connection tracking session event.
 * We offload both directions on same time, so
 * first message on a session we just need to store.
 * We don't allocate any resource before the offload.
 * */
int
netdev_dpdk_offload_ct_put(struct ct_flow_offload_item *ct_offload,
                           struct offload_info *info)
{
    struct mark_to_miss_ctx_data *data =
                        netdev_dpdk_get_flow_miss_ctx(info->flow_mark);
    int dir = ct_offload->reply?CT_OFFLOAD_DIR_REP:CT_OFFLOAD_DIR_INIT;
    int dir_opp = netdev_dpdk_offload_ct_opposite_dir(dir);
    if (!data) {
        return -1;
    }

    if (data->ct.rte_flow[dir]) {
        /* TODO: maybe add warn here because it shouldn't happen */
        /* TODO: we should offload once on established */
        netdev_dpdk_release_ct_flow(data, dir);
    }

    /* we offload only when we have both sides */
    /* this might need to change if we want to support single dir flow */
    /* but then we should define established differently */
    if (data->ct.ct_offload[dir_opp]) {
        struct ct_flow_offload_item *ct_off_opp = data->ct.ct_offload[dir_opp];
        data->ct.ct_offload[dir_opp] = NULL;

        if (!netdev_dpdk_offload_ct_session(data, ct_off_opp, ct_offload)) {
            free(ct_off_opp);
            return -1;
        }
        netdev_dpdk_offload_ct_ctx_update(data, ct_off_opp, ct_offload);
        free(ct_off_opp);

    } else {
        data->ct.ct_offload[dir] = netdev_dpdk_offload_ct_dup(ct_offload);
    }

    return 0;
}

int
netdev_dpdk_offload_ct_del(struct offload_info *info)
{
    struct mark_to_miss_ctx_data *data;
    if (!netdev_dpdk_find_miss_ctx(info->flow_mark, &data)) {
        return 0;
    }
    netdev_dpdk_release_ct_flow(data, CT_OFFLOAD_DIR_REP);
    netdev_dpdk_release_ct_flow(data, CT_OFFLOAD_DIR_INIT);

    /* Destroy FLOWS  from NAT and CT NAT */
    netdev_dpdk_del_miss_ctx(info->flow_mark);

    return 0;
}
