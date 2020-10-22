# FILE: udp.py
#
# VSCP UDP functionality
#
# This file is part of the VSCP (http://www.vscp.org)
#
# The MIT License (MIT)
#
# Copyright (c) 2000-2020 Ake Hedman, Grodans Paradis AB <info@grodansparadis.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import time
import struct
import socket
import sys
import datetime
from ctypes import *
from PyCRC.CRCCCITT import CRCCCITT     # pythoncrc
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto import Random

#from vscp import *
import vscp.py

################################################################################
# Create a VSCP frame
#

def makeVscpFrame( ptype, e ):
    
    # Must be ex version
    if not isinstance(e,vscpEventEx):
        raise ValueError('VSCP event must be vscpEventEx not vscpEvent.')

    if e.sizedata > vscp.VSCP_LEVEL2_MAXDATA:
        raise ValueError('VSCP event has data size that is greater than allowed.')

    # Create room for possible max frame
    frame = bytearray( 1 + \
                        vscp.VSCP_MULTICAST_PACKET0_HEADER_LENGTH + \
                        vscp.VSCP_LEVEL2_MAXDATA + \
                        2 )

    # Frame type, Type 0, unencrypted
    frame[ vscp.VSCP_MULTICAST_PACKET0_POS_PKTTYPE ] = ptype

    # Head
    frame[ vscp.VSCP_MULTICAST_PACKET0_POS_HEAD_MSB ] = ((e.head) >> 8 & 0xff)
    frame[ vscp.VSCP_MULTICAST_PACKET0_POS_HEAD_LSB ] = e.head & 0xff

    # Timestamp       
    frame[ vscp.VSCP_MULTICAST_PACKET0_POS_TIMESTAMP ] = ((e.timestamp) >> 24 & 0xff)
    frame[ vscp.VSCP_MULTICAST_PACKET0_POS_TIMESTAMP + 1 ] = ((e.timestamp) >> 8 & 0xff)
    frame[ vscp.VSCP_MULTICAST_PACKET0_POS_TIMESTAMP + 2 ] = ((e.timestamp) >> 8 & 0xff)
    frame[ vscp.VSCP_MULTICAST_PACKET0_POS_TIMESTAMP + 3 ] = e.timestamp & 0xff    

    # UTC time
    dt = datetime.datetime.utcnow()

    # Date / time block GMT
    if ((0 == e.year) and (0 == e.month) and (0 == e.day) and 
            (0 == e.hour) and (0 == e.minute) and (0 == e.second)) :
        frame[ vscp.VSCP_MULTICAST_PACKET0_POS_YEAR_MSB ] = ((1900 + dt.year) >> 8) & 0xff
        frame[ vscp.VSCP_MULTICAST_PACKET0_POS_YEAR_LSB ] = (1900 + dt.year) & 0xff
        frame[ vscp.VSCP_MULTICAST_PACKET0_POS_MONTH ] = dt.month
        frame[ vscp.VSCP_MULTICAST_PACKET0_POS_DAY ] = dt.day
        frame[ vscp.VSCP_MULTICAST_PACKET0_POS_HOUR ] = dt.hour
        frame[ vscp.VSCP_MULTICAST_PACKET0_POS_MINUTE ] = dt.minute
        frame[ vscp.VSCP_MULTICAST_PACKET0_POS_SECOND ] = dt.second
    else:
        frame[ vscp.VSCP_MULTICAST_PACKET0_POS_YEAR_MSB ] = (e.year >> 8) & 0xff
        frame[ vscp.VSCP_MULTICAST_PACKET0_POS_YEAR_LSB ] = e.year & 0xff
        frame[ vscp.VSCP_MULTICAST_PACKET0_POS_MONTH ] = e.month
        frame[ vscp.VSCP_MULTICAST_PACKET0_POS_DAY ] = e.day
        frame[ vscp.VSCP_MULTICAST_PACKET0_POS_HOUR ] = e.hour
        frame[ vscp.VSCP_MULTICAST_PACKET0_POS_MINUTE ] = e.minute
        frame[ vscp.VSCP_MULTICAST_PACKET0_POS_SECOND ] = e.second    

    # VSCP Class 
    frame[ vscp.VSCP_MULTICAST_PACKET0_POS_VSCP_CLASS_MSB ] = (e.vscpclass >> 8) & 0xff
    frame[ vscp.VSCP_MULTICAST_PACKET0_POS_VSCP_CLASS_LSB ] = e.vscpclass & 0xff

    # VSCP Type 
    frame[ vscp.VSCP_MULTICAST_PACKET0_POS_VSCP_TYPE_MSB ] = (e.vscptype >> 8) & 0xff
    frame[ vscp.VSCP_MULTICAST_PACKET0_POS_VSCP_TYPE_LSB ] = e.vscptype & 0xff

    # GUID 
    for i in (0,15) :
        frame[ vscp.VSCP_MULTICAST_PACKET0_POS_VSCP_GUID + i ] = e.guid[i]

    # Size
    frame[ vscp.VSCP_MULTICAST_PACKET0_POS_VSCP_SIZE_MSB ] = (e.sizedata >> 8) & 0xff
    frame[ vscp.VSCP_MULTICAST_PACKET0_POS_VSCP_SIZE_LSB ] = e.sizedata & 0xff

    # Data  
    for i in (0,e.sizedata) :
        frame[ vscp.VSCP_MULTICAST_PACKET0_POS_VSCP_DATA + i ] = e.data[i]      

    # Calculate CRC
    binstr = ''.join('\\x{:02X}'.format(x) for x in frame[ 1:vscp.VSCP_MULTICAST_PACKET0_POS_VSCP_DATA + 13 ] )
    framecrc = CRCCCITT(version='FFFF').calculate( binstr )

    # CRC
    frame[ 1 + vscp.VSCP_MULTICAST_PACKET0_HEADER_LENGTH + 13 ] = (framecrc >> 8) & 0xff
    frame[ 1 + vscp.VSCP_MULTICAST_PACKET0_HEADER_LENGTH + 13 + 1 ] = framecrc & 0xff

    # Shrink to frame size
    frame = frame[0: (1 + vscp.VSCP_MULTICAST_PACKET0_HEADER_LENGTH + 13 + 2 ) ]

    return frame

################################################################################
# Encrypt a VSCP frame with AES128/AES192/AES256
#
# Return decrypted frame
#

def encryptVscpFrame( frame, encryption ):

    key = binascii.unhexlify( VSCP_DEFAULT_KEY16 )
    prebyte = b"\x01"

    if  vscp.VSCP_ENCRYPTION_NONE == encryption :
        print("No encryption is used.")
        return frame
    elif vscp.VSCP_ENCRYPTION_AES128 == encryption :
        print("AES128 encryption is used.")
        key = binascii.unhexlify( VSCP_DEFAULT_KEY16 )
        prebyte = b"\x01"
    elif vscp.VSCP_ENCRYPTION_AES192 == encryption :
        print("AES192 encryption is used.")
        key = binascii.unhexlify( VSCP_DEFAULT_KEY24 )
        prebyte = b"\x02"
    elif vscp.VSCP_ENCRYPTION_AES256 == encryption :
        print("AES256 encryption is used.")
        key = binascii.unhexlify( VSCP_DEFAULT_KEY32 )
        prebyte = b"\x03"
    else :
        print("Bad encryption argument - AES128 encryption used.")

    # Frame must be 16 byte aligned for encryption
    while ( len( frame ) - 1 ) % 16:
        frame.append(0)

    # Get initialization vector
    iv = Random.new().read(16)
    cipher = AES.new( key, AES.MODE_CBC, iv )
    result = prebyte  + \
        cipher.encrypt( str( frame[1:] ) ) + iv

    return result
