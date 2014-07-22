# -*- coding: utf-8 -*-
"""
txshark.service
~~~~~~~~~~~~~~~

This module defines the tshark service.

:license: MIT, see LICENSE for more details.

"""

import os
from twisted.application import service
from twisted.internet import reactor
from twisted.python import log
from txshark.protocol import TsharkProtocol


class TsharkService(service.Service, object):
    """Service to stop and start tshark

    You should extend this class to override the
    packetReceived method.
    """

    def __init__(self, interfaces):
        """Initialize the tshark service.

        Several interfaces can be given for live capture.
        A capture filter can be specified for each interface.
        A file can be given instead of an interface. In this case
        a display filter can be used (syntax different from
        capture filter).

        :param interfaces: list of interfaces to listen to
                           with its associated filter
                           {"name": <name>, "filter": <filter>}
        """
        self.interfaces = interfaces
        self.proto = TsharkProtocol(callback=self.packetReceived)

    def _get_executable(self):
        """Return tshark full path.

        Use the PATH environment variable to find tshark.

        :returns: tshark full path
        """
        path = os.environ.get('PATH', '').split(os.pathsep)
        for directory in path:
            exe = os.path.join(directory, 'tshark')
            if os.path.exists(exe):
                return exe
        return None

    def _get_args(self):
        """Return tshark arguments"""
        args = ['tshark', '-T', 'pdml']
        for interface in self.interfaces:
            name = interface.get('name', '')
            interface_filter = interface.get('filter')
            if os.path.isfile(name):
                args.extend(['-r', name])
                filter_flag = '-Y'
            else:
                args.extend(['-i', name])
                filter_flag = '-f'
            if interface_filter:
                args.extend([filter_flag, interface_filter])
        return args

    def packetReceived(self, packet):
        """Method to override to handle incoming packets"""
        raise NotImplementedError

    def startService(self):
        log.msg("Starting tshark service")
        super(TsharkService, self).startService()
        executable = self._get_executable()
        args = self._get_args()
        log.msg("Running {} {}".format(executable,
                                       ' '.join(args[1:])))
        reactor.spawnProcess(self.proto,
                             executable,
                             args,
                             env={'PATH': os.environ.get('PATH', '')})

    def stopService(self):
        log.msg("Stopping tshark service")
        super(TsharkService, self).stopService()
        return self.proto.killProcess()
