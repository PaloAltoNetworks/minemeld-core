mm-run.py
=========

mw-run.py is a simple script that can be used as frontend to the mixerwagon library.

Usage
-----

::

    $ mm-run.py --help
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

fabric & mgmtbus
~~~~~~~~~~~~~~~~

**fabric** and **mgmtbus** sections in the configuration file define the class
to be used for the fabric and the mgmtbus, and the optional argumentes to be passed
to the constructors.

FTs
~~~

The **FTs** contains the desription of the processing DAG. It is composed by a list
of descriptions of FTs (processing nodes).

Each FT has the following general format:

::
    nodename: # name of the node
      args:
        # list of parameters for the node, depend on the node class
      class: nodeclass # class of the node
      inputs:
        # list of upstream nodes
        - node1
        - node2
      output: true|false # if the node should generate updates & withdraws
