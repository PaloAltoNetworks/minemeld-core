Configuration API
=================

Configuration API are used to change a temporary configuration. The temp
configuration is applied when the /config/commit API is called.

The temp configuration has a *version* attribute. The version changes
every time the temp configuration is reinitialized or reloaded from
the current MineMeld running configuration. Some API calls (commit,
create node, ...) require a version parameter, if the supplied version
is different from the current temp config version a 409 error is returned.

Each node has a *version* attribute. The node version changes every time
the node config is changed. Some API calls (set node, ...) require a version
parameter. If the supplied version is different from the current node version
a 409 error is returned. 

Authentication
--------------

Authentication is performed via basic authentication. A 401 error is returned
in case of invalid credentials:

::

    $ curl -u 'admin:goodpassword' -i http://127.0.0.1/config/info
    HTTP/1.1 200 OK
    [...]

    $ curl -u 'admin:baspassword' -i http://127.0.0.1/config/info
    HTTP/1.1 401 UNAUTHORIZED
    [...]

.. DANGER::
   Use HTTPS with a trusted certificate in production !

Configuration information
-------------------------

::

    $ curl -u 'admin:admin' -i http://127.0.0.1/config/info
    HTTP/1.1 200 OK
    Server: nginx/1.4.6 (Ubuntu)
    Date: Sun, 06 Sep 2015 14:51:41 GMT
    Content-Type: application/json
    Content-Length: 141
    Connection: keep-alive
    
    {
      "result": {
        "fabric": false, 
        "mgmtbus": false, 
        "num_nodes": 8, 
        "version": "58102565-1b93-4095-9130-84556496b84b"
      }
    }

Reload configuration
--------------------

Reload current running configuration as temporary configuration. Config version
is changed. Returns new config version.

::

    $ curl -u 'admin:admin' -i http://127.0.0.1/config/reload
    HTTP/1.1 200 OK
    Server: nginx/1.4.6 (Ubuntu)
    Date: Sun, 06 Sep 2015 14:52:46 GMT
    Content-Type: application/json
    Content-Length: 54
    Connection: keep-alive
    
    {
      "result": "b2482473-1e9f-4a24-a8b7-7296f1dfb856"
    }

Create node
-----------

Create a new node. *version* attribute is required, and should be the config
version. Returns the new node id and version.

::

    $ curl -XPOST -H 'Content-Type: application/json' -u 'admin:admin' -i http://127.0.0.1/config/node -d '{
      "name": "spamhaus_EDROP2", 
      "properties": {
        "class": "HTTP", 
        "config": {
          "attributes": {
            "direction": "inbound", 
            "type": "IPv4"
          }, 
          "cchar": ";", 
          "source_name": "http://www.spamhaus.org/drop/edrop.txt", 
          "split_char": ";", 
          "url": "http://www.spamhaus.org/drop/edrop.txt"
        }, 
        "output": true
      }, 
      "version": "b2482473-1e9f-4a24-a8b7-7296f1dfb856"
    }'
    HTTP/1.1 200 OK
    Server: nginx/1.4.6 (Ubuntu)
    Date: Sun, 06 Sep 2015 14:59:28 GMT
    Content-Type: application/json
    Content-Length: 91
    Connection: keep-alive
    
    {
      "result": {
        "id": 9, 
        "version": "b2482473-1e9f-4a24-a8b7-7296f1dfb856+0"
      }
    }

Get node configuration
----------------------

::

    $ curl -u 'admin:admin' -i http://127.0.0.1/config/node/9
    HTTP/1.1 200 OK
    Server: nginx/1.4.6 (Ubuntu)
    Date: Sun, 06 Sep 2015 15:01:00 GMT
    Content-Type: application/json
    Content-Length: 479
    Connection: keep-alive
    
    {
      "result": {
        "name": "spamhaus_EDROP2", 
        "properties": {
          "class": "HTTP", 
          "config": {
            "attributes": {
              "direction": "inbound", 
              "type": "IPv4"
            }, 
            "cchar": ";", 
            "source_name": "http://www.spamhaus.org/drop/edrop.txt", 
            "split_char": ";", 
            "url": "http://www.spamhaus.org/drop/edrop.txt"
          }, 
          "output": true
        }, 
        "version": "b2482473-1e9f-4a24-a8b7-7296f1dfb856+0"
      }
    }

Change node configuration
-------------------------

*version* is the current node version.

::

    $ curl -XPUT -u 'admin:admin' -H 'Content-Type: application/json' -i http://127.0.0.1/config/node/8 -d '{
      "name": "spamhaus_EDROP2", 
      "properties": {
        "class": "HTTP", 
        "config": {
          "attributes": {
            "direction": "inbound", 
            "type": "IPv4"
          }, 
          "cchar": ";", 
          "source_name": "http://www.spamhaus.org/drop/edrop2.txt", 
          "split_char": ";", 
          "url": "http://www.spamhaus.org/drop/edrop.txt"
        }, 
        "output": true
      }, 
      "version": "b2482473-1e9f-4a24-a8b7-7296f1dfb856+0"
    }'
    HTTP/1.1 200 OK
    Server: nginx/1.4.6 (Ubuntu)
    Date: Sun, 06 Sep 2015 15:24:25 GMT
    Content-Type: application/json
    Content-Length: 56
    Connection: keep-alive
    
    {
      "result": "b2482473-1e9f-4a24-a8b7-7296f1dfb856+1"
    }

Delete node
-----------

Delete a node. *version* is the current node version.

::

    $ curl -XDELETE -H 'Content-type: application/json' -u 'admin:admin' -i http://127.0.0.1/config/node/9 -d '{"version": "b2482473-1e9f-4a24-a8b7-7296f1dfb856+0"}'
    HTTP/1.1 200 OK
    Server: nginx/1.4.6 (Ubuntu)
    Date: Sun, 06 Sep 2015 15:17:42 GMT
    Content-Type: application/json
    Content-Length: 20
    Connection: keep-alive
    
    {
      "result": "OK"
    }

Commit configuration
--------------------

*version* is the current configuration version.

::

    $ curl -XPOST -H 'Content-Type: application/json' -u 'admin:admin' -i http://127.0.0.1/config/commit -d '{"version": "b2482473-1e9f-4a24-a8b7-  7296f1dfb856"}'
    HTTP/1.1 200 OK
    Server: nginx/1.4.6 (Ubuntu)
    Date: Sun, 06 Sep 2015 15:31:26 GMT
    Content-Type: application/json
    Content-Length: 20
    Connection: keep-alive
    
    {
      "result": "OK"
    }
