# -*- coding: utf-8 -*-
"""
txshark.packet
~~~~~~~~~~~~~~

This module defines the packet objects.

:license: MIT, see LICENSE for more details.

"""

import datetime
import lxml.objectify
import os

TRANSPORT_LAYERS = ['UDP', 'TCP']


class LayerField(object):
    """
    Holds all data about a field of a layer, both its actual
    value and its name and nice representation.
    """
    # Note: We use this object with slots and not just a dict because
    # it's much more memory-efficient (cuts about a third of the memory).
    __slots__ = ['name', 'showname', 'value', 'show', 'hide',
                 'pos', 'size', 'unmaskedvalue']

    def __init__(self, name=None, showname=None, value=None, show=None,
                 hide=None, pos=None, size=None, unmaskedvalue=None):
        self.name = name
        self.showname = showname
        self.value = value
        self.show = show
        self.pos = pos
        self.size = size
        self.unmaskedvalue = unmaskedvalue

        if hide and hide == 'yes':
            self.hide = True
        else:
            self.hide = False


class Layer(object):
    """
    An object representing a Packet layer.
    """
    DATA_LAYER = 'data'

    def __init__(self, xml_obj=None, raw_mode=False):
        self.raw_mode = raw_mode

        self._layer_name = xml_obj.attrib['name']
        self._all_fields = {}

        # We copy over all the fields from the XML object
        # Note: we don't read lazily from the XML because the lxml objects
        #       are very memory-inefficient so we'd rather not save them.
        for field in xml_obj.findall('.//field'):
            self._all_fields[field.attrib['name']] = LayerField(
                **dict(field.attrib))

    def __getattr__(self, item):
        val = self.get_field_value(item, raw=self.raw_mode)
        if val is None:
            raise AttributeError()
        return val

    def __dir__(self):
        return dir(type(self)) + self.__dict__.keys() + self._field_names

    def get_field(self, name):
        """
        Gets the XML field object of the given name.
        """
        for field_name, field in self._all_fields.iteritems():
            if name == self._sanitize_field_name(field_name):
                return field

    def get_raw_value(self, name):
        """
        Returns the raw value of a given field
        """
        return self.get_field_value(name, raw=True)

    def get_field_value(self, name, raw=False):
        """
        Tries getting the value of the given field.
        Tries it in the following order: show (standard nice display),
        value (raw value), showname (extended nice display).

        :param name: The name of the field
        :param raw: Only return raw value
        :return: str of value
        """
        field = self.get_field(name)
        if field is None:
            return

        if raw:
            return field.value

        val = field.show
        if not val:
            val = field.value
        if not val:
            val = field.showname
        return val

    @property
    def _field_prefix(self):
        """
        Prefix to field names in the XML.
        """
        if self.layer_name == 'geninfo':
            return ''
        return self.layer_name + '.'

    @property
    def _field_names(self):
        """
        Gets all XML field names of this layer.
        :return: list of strings
        """
        return [self._sanitize_field_name(field_name)
                for field_name in self._all_fields]

    @property
    def layer_name(self):
        if self._layer_name == 'fake-field-wrapper':
            return self.DATA_LAYER
        return self._layer_name

    def _sanitize_field_name(self, field_name):
        """
        Sanitizes an XML field name (since it might have characters which
        would make it inaccessible as a python attribute).
        """
        field_name = field_name.replace(self._field_prefix, '')
        return field_name.replace('.', '_')

    def __repr__(self):
        return '<%s Layer>' % self.layer_name.upper()

    def __str__(self):
        if self.layer_name == self.DATA_LAYER:
            return 'DATA'
        s = 'Layer %s:' % self.layer_name.upper() + os.linesep
        for field_line in self._get_all_field_lines():
            s += field_line
        return s

    def _get_all_field_lines(self):
        """
        Returns all lines that represent the fields of the layer
        (both their names and values).
        """
        for field in self._all_fields.values():
            if field.hide:
                continue
            if field.showname:
                field_repr = field.showname
            elif field.show:
                field_repr = field.show
            else:
                continue
            yield '\t' + field_repr + os.linesep


class Packet(object):
    """
    A packet object which contains layers.
    Layers can be accessed via index or name.
    """

    def __init__(self, layers=None, length=None, captured_length=None,
                 sniff_time=None, interface_captured=None):
        """
        Creates a Packet object with the given layers and info.

        :param layers: A list of Layer objects.
        :param length: Length of the actual packet.
        :param captured_length: The length of the packet that was actually
                                captured (could be less then length)
        :param sniff_time: The time the packet was captured (timestamp)
        :param interface_captured: The interface the packet was captured in.
        """
        if layers is None:
            self.layers = []
        else:
            self.layers = layers
        self.interface_captured = interface_captured
        self.captured_length = captured_length
        self.length = length
        self.captured_length = captured_length
        self.sniff_timestamp = sniff_time

    @classmethod
    def fromstring(cls, str_pkt):
        """Create a Packet object from a string

        :param str_pkt: A XML string representing a packet
        :returns: a Packet object
        """
        xml_pkt = lxml.objectify.fromstring(str_pkt)
        layers = [Layer(proto) for proto in xml_pkt.proto]
        geninfo, frame, layers = layers[0], layers[1], layers[2:]
        frame.raw_mode = True
        return cls(layers=layers,
                   length=int(geninfo.get_field_value('len')),
                   captured_length=int(geninfo.get_field_value('caplen')),
                   sniff_time=geninfo.get_field_value('timestamp', raw=True),
                   interface_captured=frame.get_field_value('interface_id'))

    def __getitem__(self, item):
        """
        Gets a layer according to its index or its name

        :param item: layer index or name
        :return: Layer object.
        """
        if isinstance(item, int):
            return self.layers[item]
        for layer in self.layers:
            if layer.layer_name == item.lower():
                return layer
        raise KeyError('Layer does not exist in packet')

    def __contains__(self, item):
        """
        Checks if the layer is inside the packet.

        :param item: name of the layer
        """
        try:
            self[item]
            return True
        except KeyError:
            return False

    def __dir__(self):
        return dir(type(self)) + self.__dict__.keys() \
            + [l.layer_name for l in self.layers]

    @property
    def sniff_time(self):
        try:
            timestamp = float(self.sniff_timestamp)
        except ValueError:
            # If the value after the decimal point is negative, discard it
            # Google: wireshark fractional second
            timestamp = float(self.sniff_timestamp.split(".")[0])
        return datetime.datetime.fromtimestamp(timestamp)

    def __repr__(self):
        transport_protocol = ''
        if self.transport_layer != self.highest_layer and \
                self.transport_layer is not None:
            transport_protocol = self.transport_layer + '/'

        return '<%s%s Packet>' % (transport_protocol, self.highest_layer)

    def __str__(self):
        s = self._packet_string
        for layer in self.layers:
            s += str(layer)
        return s

    @property
    def _packet_string(self):
        """
        A simple pretty string that represents the packet.
        """
        return 'Packet (Length: %s)%s' % (self.length, os.linesep)

    def __getattr__(self, item):
        """
        Allows layers to be retrieved via get attr. For instance: pkt.ip
        """
        for layer in self.layers:
            if layer.layer_name == item:
                return layer
        raise AttributeError()

    @property
    def highest_layer(self):
        return self.layers[-1].layer_name.upper()

    @property
    def transport_layer(self):
        for layer in TRANSPORT_LAYERS:
            if layer in self:
                return layer
