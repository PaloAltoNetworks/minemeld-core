Status API
==========

Status API can be used to retrieve status information about minemeld core
engine and the system.

MineMeld status
---------------

::

    $ curl -i -u 'admin:admin' http://127.0.0.1/status/minemeld
    HTTP/1.1 200 OK
    Server: nginx/1.4.6 (Ubuntu)
    Date: Tue, 08 Sep 2015 21:34:47 GMT
    Content-Type: application/json
    Content-Length: 1878
    Connection: keep-alive
    
    {
      "result": {
        "dshield_blocklist": {
          "inputs": [], 
          "length": 20, 
          "output": true, 
          "state": 5, 
          "statistics": {
            "update.tx": 20
          }
        }, 
        [...]
    }

System status
-------------

Reports percent usage of CPUs, disk, memory and swap.

::

    $curl -i -u 'admin:admin' http://127.0.0.1/status/system
    HTTP/1.1 200 OK
    Server: nginx/1.4.6 (Ubuntu)
    Date: Tue, 08 Sep 2015 21:37:31 GMT
    Content-Type: application/json
    Content-Length: 108
    Connection: keep-alive
    
    {
      "result": {
        "cpu": [
          0.0
        ], 
        "disk": 17.7, 
        "memory": 25.1, 
        "swap": 0.0
      }
    }
