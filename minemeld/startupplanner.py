import logging
from operator import itemgetter
from collections import defaultdict

import networkx as nx

from minemeld.run.config import CHANGE_INPUT_DELETED, CHANGE_ADDED


LOG = logging.getLogger(__name__)


class CheckpointNodes(object):
    def __init__(self):
        self.nodes = set()
        self.num_sources = 0


def _build_graph(config):
    graph = nx.DiGraph()

    # nodes
    for nodename, _ in config.nodes.iteritems():
        graph.add_node(nodename)

    # edges
    for nodename, nodevalue in config.nodes.iteritems():
        inputs = nodevalue.get('inputs', [])
        graph.add_edges_from([(i, nodename) for i in inputs])

    return graph


def _plan_subgraph(sg, config, state_info):
    LOG.info('state_info: {!r}'.format(state_info))
    LOG.info('planning for subgraph {!r}'.format(sg.nodes()))
    plan = {}

    checkpoints = defaultdict(CheckpointNodes)
    for nodename in sg:
        chkp = state_info[nodename].get('checkpoint', None)
        checkpoints[chkp].nodes.add(nodename)
        if state_info[nodename].get('is_source', False):
            checkpoints[chkp].num_sources += 1

    changes = defaultdict(list)
    for c in config.changes:
        if c.nodename in sg:
            changes[c.nodename].append(c)

    # if there are no checkpoints => reset
    if len(checkpoints) == 1 and None in checkpoints:
        LOG.info('No checkpoints, new graph: reset')
        for nodename in sg:
            plan[nodename] = 'reset'
        return plan

    # if there are no changes and all the nodes are at the same
    # checkpoint => initialize
    if len(checkpoints) == 1 and len(changes) == 0:
        LOG.info('No changes and all nodes have the same checkpoint: initialize')
        for nodename in sg:
            plan[nodename] = 'initialize'
        return plan

    # pick the most common checkpoint among sources as reference point
    scheckpoints = sorted(
        [(c, cn.num_sources) for c, cn in checkpoints.iteritems() if c is not None],
        key=itemgetter(1),
        reverse=True
    )
    quorum_checkpoint = None
    if len(scheckpoints) > 0:
        quorum_checkpoint = scheckpoints[0][0]
    LOG.info('Quorum checkpoint: {}'.format(quorum_checkpoint))

    # invalid nodes are nodes whose current state is not up to
    # date
    # - nodes with an old checkpoint
    # - nodes with no checkpoint but not added
    # - nodes that had an input deleted
    invalid_nodes = []
    for nodename in sg:
        if nodename not in checkpoints[quorum_checkpoint].nodes and nodename not in checkpoints[None].nodes:
            invalid_nodes.append(nodename)
            continue

        added = next((c for c in changes[nodename] if c.change == CHANGE_ADDED), None)
        if added is None and nodename in checkpoints[None].nodes:
            invalid_nodes.append(nodename)
            continue

        ideleted = next((c for c in changes[nodename] if c.change == CHANGE_INPUT_DELETED), None)
        if ideleted is not None:
            invalid_nodes.append(nodename)
            continue

    # there is at least one invalid node, we reset all the nodes except for the
    # sources with checkpoint == quorum_checkpoint
    # XXX this can be improved
    if len(invalid_nodes) > 0:
        for nodename in sg:
            if nodename in invalid_nodes:
                plan[nodename] = 'reset'
                continue

            if not state_info[nodename].get('is_source', False):
                plan[nodename] = 'reset'
                continue

            if nodename not in checkpoints[quorum_checkpoint].nodes:
                plan[nodename] = 'reset'
                continue

            plan[nodename] = 'rebuild'
        LOG.info('Invalid nodes detected ({}): {}'.format(invalid_nodes, plan))
        return plan

    # let's check added nodes, if they have no ancestors we can just
    # initialize
    init_flag = True
    added_nodes = []
    for nodename, clist in changes.iteritems():
        added = next((c for c in clist if c.change == CHANGE_ADDED), None)
        if added is not None:
            if not state_info[nodename].get('is_source', False):
                init_flag = False
                break
            added_nodes.append(nodename)

    if init_flag:
        LOG.info('Only source nodes have been added: initialize')
        for nodename in sg:
            if nodename in added_nodes:
                plan[nodename] = 'reset'
            else:
                plan[nodename] = 'initialize'
        return plan

    for nodename in sg:
        if not state_info[nodename].get('is_source', False):
            plan[nodename] = 'reset'
            continue

        if nodename not in checkpoints[quorum_checkpoint].nodes:
            plan[nodename] = 'reset'
            continue

        plan[nodename] = 'rebuild'
    LOG.info('Non-source nodes added ({}): {}'.format(added_nodes, plan))
    return plan


def plan(config, state_info):
    """Defines a startup plan for the MineMeld graph.

    Args:
        config (MineMeldConfig): config
        state_info (dict): state_info for each node

    Returns a dictionary where keys are node names and
    values the satrtup command for the node.
    """
    plan = {}

    graph = _build_graph(config)

    for subgraph in nx.weakly_connected_component_subgraphs(graph, copy=True):
        plan.update(_plan_subgraph(subgraph, config, state_info))

    return plan
