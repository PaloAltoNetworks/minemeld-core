mw-run.py
=========

mw-run.py is a simple script that can be used as frontend to the mixerwagon library.

Usage
-----

::

    $ mw-run.py --help
    usage: mw-run.py [-h] [--version] [--multiprocessing <np>] [--verbose]
                     <config>
    
    Mixing indicator feeds on the go
    
    positional arguments:
      <config>              path of the config file
    
    optional arguments:
      -h, --help            show this help message and exit
      --version             show program's version number and exit
      --multiprocessing <np>
                            enable multiprocessing. np is the number of processes,
                            -1 to use a process per machine core, 0 to disable
      --verbose             verbose
