Node config
===========

The set of config parameters supported by a node depends on the node class.

Base class
----------

All nodes support these parameters.

.. note::
    This document has been extracted from the docstrings of the python code.
    For the most updated documentation check the original source code.

Parameters
+++++++++++++++++

:infilters: inbound *filter set*. Filters to be applied to
    received indicators.
:outfilters: outbound *filter set*. Filters to be applied to
    transmitted indicators.

Filter set
++++++++++

Each filter set is a list of filters. Filters are verified from top
to bottom, and the first matching filter is applied. Default action
is **accept**.
Each filter is a dictionary with 3 keys:

:name: name of the filter.
:conditions: list of boolean expressions to match on the
    indicator.
:actions: list of actions to be applied to the indicator.
    Currently the only supported actions are **accept** and **drop**

In addition to the atttributes in the indicator value, filters can
match on 3 special attributes:

:__indicator: the indicator itself.
:__method: the method of the message, **update** or **withdraw**.
:__origin: the name of the node who sent the indicator.

Condition
+++++++++

A condition in the filter, is boolean expression composed by a JMESPath
expression, an operator (<, <=, ==, >=, >, !=) and a value.

Example
+++++++

Example config in YAML::

    infilters:
        - name: accept withdraws
          conditions:
            - __method == 'withdraw'
          actions:
            - accept
        - name: accept URL
          conditions:
            - type == 'URL'
          actions:
            - accept
        - name: drop all
          actions:
            - drop
    outfilters:
        - name: accept all (default)
          actions:
            - accept

Base poller class
-----------------

All the polling miners nodes support these parameters.

Config parameters
+++++++++++++++++

:source_name: name of the source. This is placed in the
    *sources* attribute of the generated indicators. Default: name
    of the node.
:attributes: dictionary of attributes for the generated indicators.
    This dictionary is used as template for the value of the generated
    indicators. Default: empty
:interval: polling interval in seconds. Default: 3600.
:num_retries: in case of failure, how many times the miner should
    try to reach the source. If this number is exceeded, the miner
    waits until the next polling time to try again. Default: 2
:age_out: age out policies to apply to the indicators.
    Default: age out check interval 3600 seconds, sudden death enabled,
    default age out interval 30 days.

Age out policy
++++++++++++++

Age out policy is described by a dictionary with at least 3 keys:

:interval: number of seconds between successive age out checks.
:sudden_death: boolean, if *true* indicators are immediately aged out
    when they disappear from the feed.
:default: age out interval. After this interval an indicator is aged
    out even if it is still present in the feed. If *null*, no age out
    interval is applied.

Additional keys can be used to specify age out interval per indicator
*type*.

Age out interval
++++++++++++++++

Age out intervals have the following format::

    <base attribute>+<interval>

*base attribute* can be *last_seen*, if the age out interval should be
calculated based on the last time the indicator was found in the feed,
or *first_seen*, if instead the age out interval should be based on the
time the indicator was first seen in the feed. If not specified
*first_seen* is used.

*interval* is the length of the interval expressed in seconds. Suffixes
*d*, *h* and *m* can be used to specify days, hours or minutes.

Example
+++++++

Example config in YAML for a feed where indicators should be aged out
only when they are removed from the feed::

    source_name: example.persistent_feed
    interval: 600
    age_out:
        default: null
        sudden_death: true
        interval: 300
    attributes:
        type: IPv4
        confidence: 100
        share_level: green
        direction: inbound

Example config in YAML for a feed where indicators are aged out when
they disappear from the feed and 30 days after they have seen for the
first time in the feed::

    source_name: example.long_running_feed
    interval: 3600
    age_out:
        default: first_seen+30d
        sudden_death: true
        interval: 1800
    attributes:
        type: URL
        confidence: 50
        share_level: green

Example config in YAML for a feed where indicators are aged 30 days
after they have seen for the last time in the feed::

    source_name: example.delta_feed
    interval: 3600
    age_out:
        default: last_seen+30d
        sudden_death: false
        interval: 1800
    attributes:
        type: URL
        confidence: 50
        share_level: green

minemeld.ft.http.HttpFT
-----------------------

Parameters
+++++++++++++++++

:url: URL of the feed.
:polling_timeout: timeout of the polling request in seconds.
    Default: 20
:verify_cert: boolean, if *true* feed HTTPS server certificate is
    verified. Default: *true*
:ignore_regex: Python regular expression for lines that should be
    ignored. Default: *null*
:indicator: an *extraction dictionary* to extract the indicator from
    the line. If *null*, the text until the first whitespace or newline
    character is used as indicator. Default: *null*
:fields: a dicionary of *extraction dictionaries* to extract
    additional attributes from each line. Default: {}

Extraction dictionary
+++++++++++++++++++++

Extraction dictionaries contain the following keys:

:regex: Python regular expression for searching the text.
:transform: template to generate the final value from the result
    of the regular expression. Default: the entire match of the regex
    is used as extracted value.

See Python `re <https://docs.python.org/2/library/re.html>`_ module for
details about Python regular expressions and templates.

Example
+++++++

Example config in YAML where extraction dictionaries are used to
extract the indicator and additional fields::

    url: https://www.dshield.org/block.txt
    ignore_regex: "[#S].*"
    indicator:
        regex: '^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\t([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'
        transform: '\1-\2'
    fields:
        dshield_nattacks:
            regex: '^.*\t.*\t[0-9]+\t([0-9]+)'
            transform: '\1'
        dshield_name:
            regex: '^.*\t.*\t[0-9]+\t[0-9]+\t([^\t]+)'
            transform: '\1'
        dshield_country:
            regex: '^.*\t.*\t[0-9]+\t[0-9]+\t[^\t]+\t([A-Z]+)'
            transform: '\1'
        dshield_email:
            regex: '^.*\t.*\t[0-9]+\t[0-9]+\t[^\t]+\t[A-Z]+\t(\S+)'
            transform: '\1'

Example config in YAML where the text in each line until the first
whitespace is used as indicator::

    url: https://ransomwaretracker.abuse.ch/downloads/CW_C2_URLBL.txt
    ignore_regex: '^#'
