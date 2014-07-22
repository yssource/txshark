# -*- coding: utf-8 -*-
"""
txshark.protocol
~~~~~~~~~~~~~~~~

This module defines the tshark process protocol.

:license: MIT, see LICENSE for more details.

"""

from twisted.internet import protocol, defer
from twisted.python import log
from txshark.packet import Packet


class TsharkProtocol(protocol.ProcessProtocol):
    """tshark process protocol"""

    def __init__(self, callback=None):
        self._buffer = ''
        self.callback = callback
        self.onProcessEnd = None
        self._processEnded = True

    def connectionMade(self):
        # Only set _processEnded to False when
        # the program is started
        self._processEnded = False

    def _extract_packet(self, data):
        """Try to extract a packet from the data string.

        :param data: string containing pdml data (XML)
        :returns: a tuple (packet, nb of bytes read)
        """
        packet_end = data.find(b'</packet>')
        if packet_end != -1:
            # Add len(b'</packet>') == 9
            packet_end += 9
            packet_start = data.find(b'<packet>')
            return Packet.fromstring(data[packet_start:packet_end]), packet_end
        return None, 0

    def packetReceived(self, packet):
        """Called when a packet is received.

        If a callback was given when creating the TsharkProtocol,
        the callback is called with the packet received

        :param packet: packet received
        """
        if self.callback:
            self.callback(packet)

    def outReceived(self, data):
        """Extract packets from the tshark pdml output format"""
        self._buffer = self._buffer + data
        while self._buffer:
            packet, read = self._extract_packet(self._buffer)
            if read == 0:
                # Not enough data
                return
            self._buffer = self._buffer[read:]
            self.packetReceived(packet)

    def errReceived(self, data):
        # In wireshark 1.10 branch, packet counts are sent to stderr
        # -> filter them ("\r<count>")
        if data and data[0] != '\r':
            log.msg("tshark errReceived: {}".format(data))

    def killProcess(self):
        """Kill the process if it is still running.

        If the process is still running, sends a KILL signal to the transport
        and returns a deferred which fires when processEnded is called.

        :returns: a deferred.
        """
        if self._processEnded:
            return defer.succeed(None)
        self.onProcessEnd = defer.Deferred()
        log.msg("Sending KILL signal to tshark process")
        self.transport.signalProcess('KILL')
        return self.onProcessEnd

    def processEnded(self, reason):
        """Called by Twisted when the tshark process ends"""
        log.msg("tshark processEnded, status {}".format(
            reason.value.exitCode,))
        self._processEnded = True
        if self.onProcessEnd:
            d, self.onProcessEnd = self.onProcessEnd, None
            d.callback(None)
