from minemeld.loader import load, MM_NODES_ENTRYPOINT


def factory(classname, name, chassis, config):
    node_class = load(MM_NODES_ENTRYPOINT, classname)

    return node_class(
        name=name,
        chassis=chassis,
        config=config
    )


class ft_states(object):
    READY = 0
    CONNECTED = 1
    REBUILDING = 2
    RESET = 3
    INIT = 4
    STARTED = 5
    CHECKPOINT = 6
    IDLE = 7
    STOPPED = 8
