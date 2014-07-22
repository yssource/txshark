# -*- coding: utf-8 -*-
"""
test_service
~~~~~~~~~~~~

This module tests the txshark.service module.

:license: MIT, see LICENSE for more details.

"""

from twisted.internet import defer
from twisted.trial import unittest
from txshark import TsharkService


class TestTsharkService(TsharkService):

    def __init__(self, *args, **kwargs):
        super(TestTsharkService, self).__init__(*args, **kwargs)
        self.data_received = defer.Deferred()
        self.packets = []

    def packetReceived(self, packet):
        self.packets.append(packet)
        d, self.data_received = self.data_received, defer.Deferred()
        d.callback(None)


class TsharkServiceTestCase(unittest.TestCase):

    def setUp(self):
        self.service = TestTsharkService(
            [{"name": "../txshark/test/capture_test.pcapng"}])
        # Set the timeout to 2 seconds to avoid waiting a long time
        # in case of failure (default trial tiemout is 120s)
        self.timeout = 2

    def tearDown(self):
        return self.service.stopService()

    @defer.inlineCallbacks
    def test_packetReceived(self):
        data_received = self.service.data_received
        self.service.startService()
        for i in range(0, 24):
            yield data_received
            data_received = self.service.data_received
        # 0. If we exited the for loop, we got 24 messages
        # (there would be a timeout otherwise)
        # 1. Check total length
        total_length = sum(packet.length for packet in self.service.packets)
        self.assertEqual(total_length, 2178)
        # 2. Check that correct protocols are reported for known packets
        test_values = [packet.highest_layer for i, packet in enumerate(
            self.service.packets) if i in (0, 5, 6, 13, 14, 17, 23)]
        known_values = ['DNS', 'DNS', 'ICMP', 'ICMP', 'TCP', 'HTTP', 'TCP']
        self.assertEqual(test_values, known_values)
        # 3. Check an ICMP packet
        packet = self.service.packets[11]
        self.assertTrue('ICMP' in packet)
        self.assertEqual(
            packet.icmp.data,
            'abcdefghijklmnopqrstuvwabcdefghi'.encode('hex'))
