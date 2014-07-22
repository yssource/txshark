txshark
=======

Asynchronous `TShark`_ wrapper for `Twisted`_.

Introduction
------------

**txshark** is based on `pyshark`_.

As pyshark, it uses TShark (Wireshark command-line utility) to analyze
network traffic by simply parsing the TShark pdml output (XML-based format).

Parsing TShark pdml output is not the most efficient way (in terms of
performance) to analyze network traffic. It might not keep up with very
heavy traffic. But it works very well to decode low/specific traffic (using
a capture filter) and allows to take advantage of all the existing
Wireshark dissectors.

This package provides a Twisted service to start and stop TShark.
It allows a Twisted app to decode packets from a live network or a file.

Requirements
------------

- Tool required:

  * TShark! (should be in your PATH)

- Python packages required:

  * Twisted
  * lxml

Usage
-----

TsharkService
+++++++++++++

Create a service that inherits from *TsharkService* and
override the *packetReceived* method to handle incoming packets::

    from twisted.python import log
    from txshark import TsharkService


    class SnifferService(TsharkService):

        def packetReceived(self, packet):
            """Override the TsharkService method"""
            log.msg("Packet received: {}".format(packet)

The interfaces to listen to should be given as a list of
``{"name": <name>, "filter": <filter>}``.
This allows to give a specific filter to each interface::

    service = SnifferService(
        [{"name": "eth0", "filter": "tcp and port 8521"},
         {"name": "eth1", "filter": "tcp and port 8522"}])

To read packets from a  captured file, just give the name of the file
instead of the interface. If a filter is used in this case, it should
be a display filter (syntax different from a capture filter)::

    service = SnifferService(
        [{"name": "test.pcap", "filter": "tcp.port == 8501"}])

The filter is optional in both case.

The service can be started with the *startService* method::

     service.startService()

But as a *Twisted Service*, it is designed to be started automatically by a
*Twisted Application*. Refer to `Twisted`_ documentation for more
information.

Accessing packet data
+++++++++++++++++++++

Data can be accessed in multiple ways. Packets are divided into layers,
first you have to reach the appropriate layer and then you can select your
field.

All of the following work::

    packet['ip'].dst
    >>> 192.168.0.1
    packet.ip.src
    >>> 192.168.0.100
    packet[2].src
    >>> 192.168.0.100


.. _TShark: http://www.wireshark.org/docs/man-pages/tshark.html
.. _Twisted: https://twistedmatrix.com
.. _pyshark: https://github.com/KimiNewt/pyshark
