#  Copyright (c) 2018-2019, Jethro Grassie
#  
#  All rights reserved.
#  
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are met:
#  
#  1. Redistributions of source code must retain the above copyright notice, this
#  list of conditions and the following disclaimer.
#  
#  2. Redistributions in binary form must reproduce the above copyright notice,
#  this list of conditions and the following disclaimer in the documentation
#  and/or other materials provided with the distribution.
#  
#  3. Neither the name of the copyright holder nor the names of its contributors
#  may be used to endorse or promote products derived from this software without
#  specific prior written permission.
#  
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
#  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
#  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
#  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
#  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
#  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
#  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import struct
import binascii
import requests
import logging
import pdb
import sys
from ctypes import *

__all__ = ["BinaryRPC"]

if sys.version_info > (3,):
    buffer = memoryview
    long = int

_log = logging.getLogger(__name__)
_log.setLevel(logging.INFO)
logging.basicConfig()

VINT_FORMATS = ["B", "H", "I", "Q"]
VINT_WIDTHS =  [1, 2, 4, 8]
VINT_MASK = 0x03
SERIALIZE_TYPES = {
        c_longlong:  (1, "q"),
        c_int:       (2, "i"),
        c_short:     (3, "h"),
        c_byte:      (4, "b"),
        c_ulonglong: (5, "Q"),
        c_uint:      (6, "I"),
        c_ushort:    (7, "H"),
        c_ubyte:     (8, "B"),
        c_double:    (9, "d"),
        c_char_p:    (10, "s"),
        c_bool:      (11, "?"),
        }
SERIALIZE_TYPE_OBJECT = 12
SERIALIZE_TYPE_ARRAY = 13
SERIALIZE_FLAG_ARRAY = 0x80
STORAGE_SIGNATURE = 0x0111010101010201
STORAGE_VERSION = 1


class PortableArray(Structure):
    """
    Abstract base class for portable storage arrays.

    This class adds slicing and indexing to our concrete array types.
    """
    _fields_ = []

    def __new__(cls, *args, **kwargs):
        if cls is PortableArray:
            raise TypeError("PortableArray cannot be instantiated, subclass instead")
        return Structure.__new__(cls, *args, **kwargs)

    def __init__(self, *args, **kw):
        self.index = 0
        super(PortableArray,self).__init__(*args, **kw)
    
    def __iter__(self):
        return self
    
    def next(self):
        if self.data is None or self.count is None:
            raise StopIteration
        if self.index == self.count:
            raise StopIteration
        rv = self.data[self.index]
        self.index += 1
        return rv

    def __next__(self):
        return self.next()

    def __getitem__(self, sliced):
        return self.data[sliced]
    
    def __len__(self):
        return self.count


class PODType():
    pass


class Int64Array(PortableArray):
    _fields_ = [("count", c_uint), ("data", POINTER(c_longlong)),
            ("index", c_uint)]


class Int32Array(PortableArray):
    _fields_ = [("count", c_uint), ("data", POINTER(c_int)),
            ("index", c_uint)]


class Int16Array(PortableArray):
    _fields_ = [("count", c_uint), ("data", POINTER(c_short)),
            ("index", c_uint)]


class Int8Array(PortableArray):
    _fields_ = [("count", c_uint), ("data", POINTER(c_byte)),
            ("index", c_uint)]


class UInt64Array(PortableArray):
    _fields_ = [("count", c_uint), ("data", POINTER(c_ulonglong)),
            ("index", c_uint)]


class UInt32Array(PortableArray):
    _fields_ = [("count", c_uint), ("data", POINTER(c_uint)),
            ("index", c_uint)]


class UInt16Array(PortableArray):
    _fields_ = [("count", c_uint), ("data", POINTER(c_ushort)),
            ("index", c_uint)]


class UInt8Array(PortableArray):
    _fields_ = [("count", c_uint), ("data", POINTER(c_ubyte)),
            ("index", c_uint)]


class DoubleArray(PortableArray):
    _fields_ = [("count", c_uint), ("data", POINTER(c_double)),
            ("index", c_uint)]


class BoolArray(PortableArray):
    _fields_ = [("count", c_uint), ("data", POINTER(c_bool)),
            ("index", c_uint)]


class BlobData(Structure, PODType):
    _fields_ = [("count", c_uint), ("data", c_char_p)]


class BlobDataArray(PortableArray, PODType):
    _fields_ = [("count", c_uint), ("data", POINTER(BlobData)),
            ("index", c_uint)]


class Hash(Structure, PODType):
    _fields_ = [("data", c_ubyte * 32)]
    def __repr__(self):
        return binascii.hexlify(self.data).decode()


class HashArray(PortableArray, PODType):
    _fields_ = [("count", c_uint), ("data", POINTER(Hash)),
            ("index", c_uint)]


class Key(Hash):
    pass


class KeyMask(Hash):
    pass


class RPCError(Exception):
    pass


class GetOutputsOut(Structure):
    _fields_ = [("amount", c_ulonglong), ("index", c_ulonglong)]


class GetOutputsOutArray(PortableArray):
    _fields_ = [("count", c_uint), ("data", POINTER(GetOutputsOut)),
            ("index", c_uint)]


class OutKey(Structure):
    _fields_ = [("key", Key), ("mask", KeyMask), ("unlocked", c_bool), 
            ("height", c_ulonglong), ("txid", Hash)]


class OutKeyArray(PortableArray):
    _fields_ = [("count", c_uint), ("data", POINTER(OutKey)),
            ("index", c_uint)]


class TxOutputIndices(Structure):
    _fields_ = [("indices", UInt64Array)]


class TxOutputIndicesArray(PortableArray):
    _fields_ = [("count", c_uint), ("data", POINTER(UInt64Array)),
            ("index", c_uint)]


class BlockTxOutputIndices(Structure):
    _fields_ = [("indices", TxOutputIndicesArray)]


class BlockOutputIndicesArray(PortableArray):
    _fields_ = [("count", c_uint), ("data", POINTER(BlockTxOutputIndices)),
            ("index", c_uint)]


class OutputIndices(Structure):
    _fields_ = [("indices", BlockOutputIndicesArray)]


class BlockCompleteEntry(Structure):
    _fields_ = [("block", BlobData), ("txs", BlobDataArray)]


class BlockCompleteEntryArray(PortableArray):
    _fields_ = [("count", c_uint), ("data", POINTER(BlockCompleteEntry)),
            ("index", c_uint)]


class GetOutputIndexesRequest(Structure):
    _fields_ = [
            ("txid", c_ubyte * 32)]


class GetOutputIndexesResponse(Structure):
    _fields_ = [
            ("o_indexes", UInt64Array),
            ("status", c_char_p),
            ("untrusted", c_bool)]


class GetHashesRequest(Structure):
    _fields_ = [
            ("block_ids", HashArray),
            ("start_height", c_ulonglong)]


class GetHashesResponse(Structure):
    _fields_ = [
            ("m_block_ids", HashArray),
            ("start_height", c_ulonglong),
            ("current_height", c_ulonglong),
            ("status", c_char_p),
            ("untrusted", c_bool)]


class GetOutsRequest(Structure):
    _fields_ = [
            ("outputs", GetOutputsOutArray),
            ("get_txid", c_bool)]


class GetOutsResponse(Structure):
    _fields_ = [
            ("outs", OutKeyArray),
            ("status", c_char_p),
            ("untrusted", c_bool)]


class GetTransactionPoolHashesRequest(Structure):
    _fields_ = []


class GetTransactionPoolHashesResponse(Structure):
    _fields_ = [
            ("tx_hashes", HashArray),
            ("status", c_char_p),
            ("untrusted", c_bool)]


class GetBlocksRequest(Structure):
    _fields_ = [
            ("block_ids", HashArray),
            ("start_height", c_ulonglong),
            ("prune", c_bool),
            ("no_miner_tx", c_bool)]


class GetBlocksResponse(Structure):
    _fields_ = [
            ("blocks", BlockCompleteEntryArray),
            ("start_height", c_ulonglong),
            ("current_height", c_ulonglong),
            ("status", c_char_p),
            ("output_indices", OutputIndices),
            ("untrusted", c_bool)]


class GetBlocksByHeightRequest(Structure):
    _fields_ = [("heights", UInt64Array)]


class GetBlocksByHeightResponse(Structure):
    _fields_ = [
            ("blocks", BlockCompleteEntryArray),
            ("status", c_char_p),
            ("untrusted", c_bool)]


def pack_vint(n):
    """
    Pack an integer to a varint.

    Returns the varint.
    """
    # The mask (which occupies the lowest 2 bits) is used to identify how many
    # more bytes are needing when reading back. E.g. a reader reads the first
    # byte, inspects the mask bits, and if needed then reads more bytes.
    mask = 0
    if n < 64:
        mask = 0
    elif n < 16384:
        mask = 1
    elif n < 1073741824:
        mask = 2
    else:
        mask = 3
    n <<= 2
    n |= mask
    return struct.pack(VINT_FORMATS[mask], n)


def unpack_vint(buf, offset):
    """
    Unpack a varint from the supplied buffer.
    
    Returns a tuple of the unpacked number and width consumed.
    """
    # The 2 least significant bits specify the extra byte width of the varint.
    mask, = struct.unpack_from("B", buf, offset)
    mask &= VINT_MASK
    w = VINT_WIDTHS[mask]
    v, = struct.unpack_from(VINT_FORMATS[mask], buf, offset)
    v >>= 2
    return v, w


def pack_array_entry(data, arr):
    """
    Pack an array to the supplied bytearray.

    Writes:
    - count (varint)
    - write each elements entry data
    """
    assert isinstance(arr, PortableArray), "Must be a PortableArray!"
    c = arr.count
    data.extend(pack_vint(c))
    for e in arr:
        pack_entry_data(data, e)
        

def pack_entry_type(data, field):
    """
    Pack an entry type ID to the supplied bytearray.

    Type is deduced from the supplied field.
    """
    entry_type = None
    if hasattr(field, "_length_") and field._type_ is c_ubyte:
        entry_type, ff = SERIALIZE_TYPES[c_char_p]
    elif hasattr(field, "count") and hasattr(field, "data"):
        if isinstance(field, PODType):
            entry_type, ff = SERIALIZE_TYPES[c_char_p]
        else:
            entry_type, ff = SERIALIZE_TYPES.get(field.data._type_, (None, None))
            if entry_type is None:
                if (issubclass(field.data._type_, PortableArray)
                        and issubclass(field.data._type_, PODType)):
                    entry_type, ff = SERIALIZE_TYPES[c_char_p]
                    entry_type |= SERIALIZE_FLAG_ARRAY
                elif issubclass(field.data._type_, PortableArray):
                    entry_type = SERIALIZE_FLAG_ARRAY | SERIALIZE_TYPE_ARRAY
                else:
                    entry_type = SERIALIZE_FLAG_ARRAY | SERIALIZE_TYPE_OBJECT
            else:
                entry_type |= SERIALIZE_FLAG_ARRAY
    elif isinstance(field, Structure) and not isinstance(field, PortableArray):
        entry_type = SERIALIZE_TYPE_OBJECT
    elif type(field) is long:
        entry_type, ff = SERIALIZE_TYPES[c_ulong]
    elif type(field) is bool:
        entry_type, ff = SERIALIZE_TYPES[c_bool]
    else:
        entry_type, ff = SERIALIZE_TYPES[type(field)]

    assert entry_type is not None, "Cannot determine type for {}!".format(field)
    _log.debug("packing: type {} for instance {}".format(hex(entry_type), field))
    data.extend(struct.pack("B", entry_type))
    

def pack_entry_data(data, field):
    """
    Pack an entries data to the supplied bytearray.
    """
    if hasattr(field, "_length_") and field._type_ is c_ubyte:
        entry_type, ff = SERIALIZE_TYPES[c_char_p]
        sl = len(field)
        _log.debug("packing: {} {}B bytes".format(field._type_, sl))
        data.extend(pack_vint(sl))
        data.extend(struct.pack("{}B".format(sl), *field))
    elif isinstance(field, PortableArray) and not isinstance(field, PODType):
        entry_type, ff = SERIALIZE_TYPES.get(field.data._type_, (None, None))
        if entry_type is None:
            entry_type = SERIALIZE_TYPE_OBJECT
        entry_type |= SERIALIZE_FLAG_ARRAY
        pack_array_entry(data, field)
    elif isinstance(field, PortableArray) and isinstance(field, PODType):
        entry_type, ff = SERIALIZE_TYPES[c_char_p]
        es = sizeof(field.data._type_)
        data.extend(pack_vint(field.count * es))
        _log.debug("packing: Array as POD {} {} count {}"
                .format(type(field), field.data._type_, field.count))
        for i in range(field.count):
            if hasattr(field.data[i],"data"):
                data.extend(struct.pack("{}B".format(es), *field.data[i].data))
            else:
                pack_entries(data, field.data[i])
    elif isinstance(field, Structure) and not isinstance(field, PortableArray):
        pack_entries(data, field)
    elif isinstance(field, c_char_p):
        entry_type, ff = SERIALIZE_TYPES[type(field)]
        _log.debug("packing: {} {}".format(n, sl,ff))
        sl = len(field.value)
        data.extend(pack_vint(sl))
        data.extend(struct.pack("{}{}".format(sl,ff), field.value))
    elif type(field) is long:
        entry_type, ff = SERIALIZE_TYPES[c_ulong]
        data.extend(struct.pack(ff, field))
    elif type(field) is bool:
        entry_type, ff = SERIALIZE_TYPES[c_bool]
        data.extend(struct.pack(ff, field))
    else:
        entry_type, ff = SERIALIZE_TYPES[type(field)]
        data.extend(struct.pack(ff, field))


def pack_entry(data, f):
    """
    Pack an entry type and data to the supplied bytearray.

    Writes:
    - entry type (byte)
    - entry data (dependent on type)
    """
    pack_entry_type(data, f)
    pack_entry_data(data, f)


def pack_entries(data, obj):
    """
    Pack a section's entries to the supplied bytearray.

    Writes:
    - entry count (varint)
    """
    assert isinstance(obj, Structure), "Must be a ctypes Structure!"
    c = len(obj._fields_)
    data.extend(pack_vint(c))
    for n,t in obj._fields_:
        n = str(n)
        data.extend(struct.pack("B {}s".format(len(n)), len(n), n.encode()))
        f = getattr(obj, n)
        pack_entry(data, f)


def pack_request(obj):
    """
    Pack a request object to binary format.

    Returns a bytearray of the packed request object.

    Introspection is used on the supplied object to infer entry types.
    Structure of the binary data is as follows:

    HEADER
    ------
    - signature (uint64)
    - version (byte)
    - entry count (varint)

    FIELD []
    --------
    - entry name length (byte)
    - entry name (char[])
    - entry type (byte)
    - entry value (dependent on type)
    """
    data = bytearray()
    data.extend(struct.pack("> Q B", STORAGE_SIGNATURE, STORAGE_VERSION))
    pack_entries(data, obj)
    _log.debug("Final request bytes: {}".format(binascii.hexlify(data)))
    return data


def unpack_label(buf, offset):
    """
    Unpack an entry label.

    Returns a tuple of the label and new offset after reading.
    """
    length, = struct.unpack_from("B", buf, offset)
    offset += 1
    entry_name, = struct.unpack_from("{}s".format(length), buf, offset)
    offset += length
    return entry_name.decode(), offset


def unpack_array_object(buf, offset, arr, element_type):
    """
    Unpack an array of objects from supplied buffer.

    Returns the new offset after reading.
    """
    _log.debug("unpacking: filling array {}".format(type(arr)))
    element_type = element_type or arr.data._type_
    arrlen = arr.count

    # This bit is a kinda cludge as this method is supposed to be for
    # unpacking just objects in the array, not arrays in arrays.
    # It is used when unpacking an array member in a serialized object array.
    # e.g. SERIALIZE_FLAG_ARRAY | SERIALIZE_TYPE_OBJECT
    if issubclass(element_type, PortableArray):
        for i in range(arrlen):
            field_count, w = unpack_vint(buf, offset)
            offset += w
            assert field_count == 1, "There is more than 1 field for this object holding an array!"
            field_name, offset = unpack_label(buf, offset)
            offset = unpack_entry(buf, offset, arr[i])
        return offset

    es = sizeof(element_type)
    ec = arrlen / es
    for e in arr:
        offset = unpack_section(buf, offset, e)
    return offset

def unpack_entry(buf, offset, parent, entry_name=None):
    """
    Unpack an entry from the supplied buffer.

    Returns the new offset after reading.
    """
    typeid, = struct.unpack_from("B", buf, offset)
    offset += 1

    try:
        ct = next((t for t,v in SERIALIZE_TYPES.iteritems()
            if v[0] == typeid & ~SERIALIZE_FLAG_ARRAY), None)
        ff = next((v for t,v in SERIALIZE_TYPES.iteritems()
            if v[0] == typeid & ~SERIALIZE_FLAG_ARRAY), (None, None))[1]
    except AttributeError:
        ct = next((t for t,v in SERIALIZE_TYPES.items()
            if v[0] == typeid & ~SERIALIZE_FLAG_ARRAY), None)
        ff = next((v for t,v in SERIALIZE_TYPES.items()
            if v[0] == typeid & ~SERIALIZE_FLAG_ARRAY), (None, None))[1]

    _log.debug("unpacking: found ct {} and typeid {} for entry_name {}"
            .format(ct, typeid, entry_name))

    # First handle this special case of member array in object
    # e.g. SERIALIZE_FLAG_ARRAY | SERIALIZE_TYPE_OBJECT
    if entry_name is None and isinstance(parent, PortableArray):
        arrlen, w = unpack_vint(buf, offset)
        offset += w
        parent.data = (ct * arrlen)()
        parent.count = arrlen
        for i in range(arrlen):
            val, = struct.unpack_from(ff, buf, offset)
            offset += sizeof(ct)
            parent.data[i] = val
        return offset

    field = getattr(parent, entry_name)
    entry_type = type(field)

    if typeid & SERIALIZE_FLAG_ARRAY and ff:
        # Simple arrays such as array of u64's
        # note we stil need to match this to our parent.entry_name as could be an
        # array of strings for example, which may be Hash or Blob types

        if hasattr(field, "data") and hasattr(field, "count") and ct is c_char_p:
            arrlen, w = unpack_vint(buf, offset)
            offset += w
            item_type = field.data._type_
            arr = (arrlen * item_type)(item_type())
            for e in arr:
                arrlen, w = unpack_vint(buf, offset)
                offset += w
                _log.debug("unpacking: a {}s string".format(arrlen))
                v, = struct.unpack_from("{}s".format(arrlen), buf, offset)
                offset += arrlen
                e.data = v
                e.count = arrlen
            return offset

        # Following works for simple types but not prefixed strings
        arrlen, w = unpack_vint(buf, offset)
        offset += w
        _log.debug("unpacking: {} {} array with {} values".format(entry_name, ff, arrlen))
        arr = (ct * arrlen)(*struct.unpack_from("{}{}".format(arrlen, ff), buf, offset))
        offset += arrlen * sizeof(ct)
        arr_type = type(getattr(parent, entry_name))
        arr_obj = arr_type()
        arr_obj.count = arrlen
        arr_obj.data = arr
        setattr(parent, entry_name, arr_obj)

    elif (typeid & SERIALIZE_FLAG_ARRAY 
            and typeid & ~SERIALIZE_FLAG_ARRAY == SERIALIZE_TYPE_OBJECT):
        ob_count, w = unpack_vint(buf, offset)
        offset += w

        # Sometimes we get an actual array rather than an object
        # that holds an array in a member.
        if isinstance(field, PortableArray):
            ct = entry_type
            temp = ct()
            arr = (temp.data._type_ * ob_count)()
            arr.count = ob_count
            _log.debug("unpacking: setting {} {} on {}".format(entry_name, ct, parent))
            offset = unpack_array_object(buf, offset, arr, temp.data._type_)
            p = getattr(parent, entry_name)
            p.data = arr
            p.count = ob_count
            return offset

        # OK we're an object with a member that holds the array...
        arr_entry_name = field._fields_[0][0]
        arr_field = getattr(field, arr_entry_name)
        arr_mtype = arr_field.data._type_
        arr_field.data = (ob_count * arr_mtype)()
        arr_field.count = ob_count

        for i in range(ob_count):
            field_count, w = unpack_vint(buf, offset)
            offset += w
            assert field_count == 1, "There is more than 1 field for this object holding an array!"
            field_name, offset = unpack_label(buf, offset)
            assert field_name == arr_entry_name, "Was expecting an field name of {}!".format(arr_entry_name)
            _log.debug("unpacking: {} {}".format(arr_field.data[i], field_name))
            offset = unpack_entry(buf, offset, arr_field.data[i], field_name)

    elif (typeid & SERIALIZE_FLAG_ARRAY 
            and typeid & ~SERIALIZE_FLAG_ARRAY == SERIALIZE_TYPE_ARRAY):
        _log.warn("Not yet implemented SERIALIZE_FLAG_ARRAY|SERIALIZE_TYPE_ARRAY")
    elif typeid == SERIALIZE_TYPE_OBJECT:
        _log.warn("Not yet implemented SERIALIZE_TYPE_OBJECT")
    elif typeid == SERIALIZE_TYPE_ARRAY:
        _log.warn("Not yet implemented SERIALIZE_TYPE_ARRAY")
    else:
        # Must have a match on ct and ff above
        if (ct is c_char_p and not isinstance(field, HashArray) 
                and not isinstance(field, BlobData) and not isinstance(field, Hash)):
            size, w = unpack_vint(buf, offset)
            offset += w
            _log.debug("unpacking: {} {}s string".format(entry_name, size))
            val, = struct.unpack_from("{}s".format(size), buf, offset)
            offset += size
            setattr(parent, entry_name, val)
        elif isinstance(field, Hash):
            size, w = unpack_vint(buf, offset)
            offset += w
            _log.debug("unpacking: {} {}s string".format(entry_name, size))
            field.data = struct.unpack_from("{}B".format(size), buf, offset)
            offset += size
        elif isinstance(field, BlobData):
            size, w = unpack_vint(buf, offset)
            offset += w
            _log.debug("unpacking: {} {}s string".format(entry_name, size))
            val, = struct.unpack_from("{}s".format(size), buf, offset)
            offset += size
            field.data = val
            field.count = size
        elif hasattr(field, "data") and hasattr(field, "count"):
            # handles HashArray aswell
            item_type = field.data._type_
            arrlen, w = unpack_vint(buf, offset)
            offset += w
            item_size = sizeof(item_type)
            item_count = arrlen // item_size
            arr = (item_type * item_count)()
            _log.debug("unpacking: {} {} {} count {}"
                    .format(entry_name, entry_type, item_type, item_count))
            for item in arr:
                item.data = struct.unpack_from("{}B".format(item_size), buf, offset)
                offset += item_size
            # TODO: revisit to find out why I did this!
            # Its probably just type juggling which can be improved!
            ob = entry_type(item_count, arr)
            ob.count = item_count
            setattr(parent, entry_name, ob)
        else:
            _log.debug("unpacking: {} {}".format(entry_name, ff))
            val, = struct.unpack_from(ff, buf, offset)
            offset += sizeof(ct)
            setattr(parent, entry_name, ct(val))
    return offset


def unpack_section(buf, offset, parent):
    """
    Unpack a section's entries.

    Returns the new offset after reading.
    """
    fcount, w = unpack_vint(buf, offset)
    offset += w
    _log.debug("unpacking: {} entries".format(fcount))
    while fcount:
        fcount -= 1
        entry_name, offset = unpack_label(buf, offset)
        offset = unpack_entry(buf, offset, parent, entry_name)
    return offset


def unpack_response(buf, obj):
    """
    Unpack a binary response to a supplied object instance.

    Structure of the binary data is as follows:

    HEADER
    ------
    - signature (uint64)
    - version (byte)
    - entry count (varint)

    FIELD []
    --------
    - entry name length (byte)
    - entry name (char[])
    - entry type (byte)
    - entry value (dependent on type)

    """
    offset = 0
    sig, ver = struct.unpack_from("> Q B", buf, offset)
    if sig != STORAGE_SIGNATURE or ver != STORAGE_VERSION:
        _log.warning("Response data signature / version mismatched. Aborting.")
        return
    offset += 9
    unpack_section(buf, offset, obj)


# The meat of the pudding...
class BinaryRPC(object):
    """
    A wrapper for the Monero RPC binary interface.

    Create an instance of this class for each daemon / wallet.
    """
    def __init__(self, proto="http", host="localhost", port=18081):
        self.proto = proto
        self.host = host
        self.port = port

    def _raw_request(self, path, command, response):
        packed = pack_request(command)
        url = "{}://{}:{}{}".format(self.proto, self.host, self.port, path)
        res = requests.post(url, data=packed)
        if res.status_code != 200:
            raise RPCError("HTTP status: {}".format(res.status_code))
        buf = buffer(res.content)
        unpack_response(buf, response)
        return response

    def get_o_indexes(self, txid):
        path = "/get_o_indexes.bin"
        if len(txid) != 64:
            raise TypeError("txid must be a hex string of length 64")
        txid_bin = (c_ubyte * 32)(
            *bytearray.fromhex(txid))
        command = GetOutputIndexesRequest(txid_bin)
        response = GetOutputIndexesResponse()
        self._raw_request(path, command, response)
        return response

    def get_hashes(self, block_ids, start_height):
        path = "/get_hashes.bin"
        hc = len(block_ids)
        block_ids_bin = HashArray(hc, (Hash * hc)(
            *map(lambda h: Hash((c_ubyte*32)(*bytearray.fromhex(h))), block_ids)))
        command = GetHashesRequest(block_ids_bin, start_height)
        response = GetHashesResponse()
        self._raw_request(path, command, response)
        return response

    def get_outs(self, outputs, get_txid=True):
        path = "/get_outs.bin"
        oc = len(outputs)
        outputs_bin = GetOutputsOutArray(oc, (GetOutputsOut * oc)(*outputs))
        command = GetOutsRequest(outputs_bin, get_txid)
        response = GetOutsResponse()
        self._raw_request(path, command, response)
        return response

    def get_blocks(self, block_ids, start_height, prune=False, no_miner_tx=False):
        path = "/get_blocks.bin"
        hc = len(block_ids)
        block_ids_bin = HashArray(hc, (Hash * hc)(
            *map(lambda h: Hash((c_ubyte*32)(*bytearray.fromhex(h))), block_ids)))
        command = GetBlocksRequest(block_ids_bin, start_height, prune, no_miner_tx)
        response = GetBlocksResponse()
        self._raw_request(path, command, response)
        return response

    def get_blocks_by_height(self, heights):
        path = "/get_blocks_by_height.bin"
        hc = len(heights)
        heights_bin = UInt64Array(hc, (c_ulonglong * hc)(*heights))
        command = GetBlocksByHeightRequest(heights_bin)
        response = GetBlocksByHeightResponse()
        self._raw_request(path, command, response)
        return response

