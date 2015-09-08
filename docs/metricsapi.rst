Metrics API
===========

Metrics API can be used to retrieve historical statistics of the system and
MineMeld nodes.

Metrics list
------------

::

    $ curl -i -u 'admin:admin' http://127.0.0.1/metrics
    HTTP/1.1 200 OK
    Server: nginx/1.4.6 (Ubuntu)
    Date: Tue, 08 Sep 2015 21:41:07 GMT
    Content-Type: application/json
    Content-Length: 1040
    Connection: keep-alive
    
    {
      "result": [
        "spamhaus_EDROP.update.tx", 
        "df-run", 
        "inboundaggregator.update.rx", 
        "dshield_blocklist.length", 
        "df-run-user", 
        "zeustracker_badips.length", 
        "spamhaus_DROP.length", 
        "df-root", 
        "df-sys-fs-cgroup", 
        "spamhaus_EDROP.length", 
        [...]
      ]
    }

Metric history
--------------

Metric history can be retrieved using /metrics/<metric name> endpoint.

::

    $ curl -i -u 'admin:admin' http://127.0.0.1/metrics/outboundaggregator.length
    HTTP/1.1 200 OK
    Server: nginx/1.4.6 (Ubuntu)
    Date: Tue, 08 Sep 2015 21:42:52 GMT
    Content-Type: application/json
    Content-Length: 1779
    Connection: keep-alive
    
    {
      "result": [
        [
          1441661340, 
          null
        ], 
        [...]
      ]
    }
