Architecture
============

Processing graph
----------------

The core processing engine of MineMeld is based on DAG of nodes. Indicators
are retrieved by source nodes (Sx in the pictures) and then pushed to
downstream nodes via *update* messages. When an indicator stop being considered
live, it is withdrawn sending a *withdraw* message to downstream nodes.

Typically each node maintains its own table of live indicators, where the
definition of *live* could change according to the node implementation. The
processing engine could be thought as a graph of continuosly updating
materialized views.

.. image:: images/dag.png

Node
----

Each node could have 0 or more inputs and 0 or more output. Rather obviuosly
if a node has 0 inputs it is considered a source node, if a node has 0 ouput
it is considered an output node.

Each node also offers a RPC interface, for directed out of band requests, and
a connection to a *management bus* for status checks and management commands
coming from the *management bus master*.

.. image:: images/nodes.png

The connections between nodes are implemented with a pubsub mechanism. Each
node sends its downstream message to a *topic* named as the node, and all
the downstream nodes are subscribers of this topic.

.. image:: images/topics.png

Node messages
-------------

Each node can send downstream the following messages.

update
******

update(indicator, value)

:indicator: string
:value: a dictionary of attributes for the indicator

Notifies a new indicator or an update of the attributes associated to an
indicator.

withdraw
********

withdraw(indicator[, value])

:indicator: string
:value: (optional) a dictionary of attributes for the indicator

Notifies a withdraw of the indicator

checkpoint
**********

checkpoint(id)

Used as a processing barrier for the graph when the graph is being stopped.

Node statistics
---------------

Each node keeps a variable number of statistics to track its internal
operations:

:update.tx: number of update messages transmitted downstream
:update.rx: number of update messages received from upstream
:update.processed: number of update messages recevied and processed
    (not dropped by filters)
:withdraw.tx: number of withdraw messages transmitted downstream
:withdraw.rx: number of withdraw messages received from upstream
:withdraw.processed: number of withdraw messages received from upstream
    and processed (not dropped by filters)
:added: number of indicators added to the node table
:removed: number of indicators removed from the node table
:length: number of indicators in node table

If a statistic is not present its value is 0.
