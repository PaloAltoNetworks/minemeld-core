Messages
========

Intra-node protocol
-------------------

The protocol used between nodes is super simple. There are 3 messages:

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
