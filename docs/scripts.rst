mm-run
=========

mm-run is a simple script that can be used as frontend to the minemeld library.

Usage
-----

::

    $ mm-run --help
    usage: mm-run.py [-h] [--version] [--multiprocessing NP] [--verbose] CONFIG
    
    Low-latency threat indicators processor
    
    positional arguments:
      CONFIG                path of the config file or of the config directory
    
    optional arguments:
      -h, --help            show this help message and exit
      --version             show program's version number and exit
      --multiprocessing NP  enable multiprocessing. NP is the number of processes,
                            0 to use a process per machine core
      --verbose             verbose

Configuration
-------------

CONFIG parameter on the command line can point to a configuration file or to a 
configuration directory. If CONIG is a directory, mm-run will check for 
commited-config.yml and running-config.yml files. If only running-config.yml exists,
mm-run assumes that the config has not been changed and the processing continues
where it was stopped. If only canidate-config.yml exists, mm-run copies the
file to running-config.yml and reinitializes the processing. If both files exist,
candidate-config.yml is copied over running-config.yml and the processing is
reinitialized if the 2 files are different. If CONFIG instead is a path to a
configuration file, the configuration will be considered as new and the processing
is reinitialized.

nodes
~~~~~

The **nodes** section contains the desription of the processing DAG. It is composed
by a list of descriptions of nodes.

Each node config has the following general format:

::

    nodename: # name of the node
      config:
        # list of parameters for the node, depends on the node class
      class: nodeclass # class of the node
      inputs:
        # list of upstream nodes
        - node1
        - node2
      output: true|false # if the node should generate updates & withdraws

Node can also be based on prototypes, in that case the *config* and *class*
sections are omitted as they are specified inside the prototype.

::

    nodename: # name of the node
      prototype: prototype1 # name of the prototype to be used
      inputs:
        # list of upstream nodes
        - node1
        - node2
      output: true|false # if the node should generate updates & withdraws    

Example 1
^^^^^^^^^

::

    spamhaus_DROP:
      config:
        source_name: http://www.spamhaus.org/drop/drop.txt
        attributes:
          type: IPv4
          direction: inbound
        cchar: ;
        split_char: ;
        url: http://www.spamhaus.org/drop/drop.txt
      class: HTTP
      output: true

This describes a node with the following properties:

:name: spamhaus_DROP
:class: HTTP
:inputs: *none*, this is a Miner
:output: enabled, this node will emit indicators
:config: specific configuration for this node class

Example 2
^^^^^^^^^

::

    inboundaggregator:
      config:
        infilters:
          - name: accept inbound IPv4
            conditions:
              - type == 'IPv4'
              - direction == 'inbound'
            actions:
              - accept
          - name: drop all
            actions:
              - drop
      class: AggregatorIPv4
      output: true
      inputs:
        - spamhaus_DROP
        - spamhaus_EDROP
        - dshield_blocklist

:name: inboundaggregator
:class: AggregatorIPv4
:inputs: this node will receive indicators from spamhaus_DROP, spamhaus_EDROP, ...
:output: enabled, this node will emit indicators
:config: specific configuration for this node class

Example 3
^^^^^^^^^

::

    spamhaus_DROP:
      output: true
      prototype: spamhaus.DROP

:name: spamhaus_DROP
:inputs: *none*, this is a Miner
:output: enabled, this node will emit indicators
:prototype: *config* and *class* of this node will be loaded from the spamhaus.DROP prototype
