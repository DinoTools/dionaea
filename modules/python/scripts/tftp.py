#********************************************************************************
#*                               Dionaea
#*                           - catches bugs -
#*
#*
#*
#* Copyright (C) 2009  Paul Baecher & Markus Koetter
#* Copyright (c) 2006-2009 Michael P. Soulier
#* 
#* This program is free software; you can redistribute it and/or
#* modify it under the terms of the GNU General Public License
#* as published by the Free Software Foundation; either version 2
#* of the License, or (at your option) any later version.
#* 
#* This program is distributed in the hope that it will be useful,
#* but WITHOUT ANY WARRANTY; without even the implied warranty of
#* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#* GNU General Public License for more details.
#* 
#* You should have received a copy of the GNU General Public License
#* along with this program; if not, write to the Free Software
#* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#* 
#* 
#*             contact nepenthesdev@gmail.com  
#*
#*******************************************************************************/

#
# The whole logic is taken from tftpy
# http://tftpy.sourceforge.net/
# tftpy is licensed using CNRI Python License
# which is claimed to be incompatible with the gpl
# http://www.gnu.org/philosophy/license-list.html
# 
# Nevertheless, the tftpy author Michael P. Soulier
# gave us a non exclusive permission to use his code in 
# our gpl project

from dionaea import connection, ihandler, g_dionaea, incident

import tempfile
import struct
import logging
import os


DEF_BLKSIZE = 512
MIN_BLKSIZE = 8
DEF_BLKSIZE = 512
MAX_BLKSIZE = 65536

logger = logging.getLogger('tftp')
logger.setLevel(logging.DEBUG)


def tftpassert(condition, msg):
    """This function is a simple utility that will check the condition
    passed for a false state. If it finds one, it throws a TftpException
    with the message passed. This just makes the code throughout cleaner
    by refactoring."""
    if not condition:
        raise TftpException(msg)

class TftpException(Exception):
    """This class is the parent class of all exceptions regarding the handling
    of the TFTP protocol."""
    pass


class TftpErrors(object):
    """This class is a convenience for defining the common tftp error codes,
    and making them more readable in the code."""
    NotDefined = 0
    FileNotFound = 1
    AccessViolation = 2
    DiskFull = 3
    IllegalTftpOp = 4
    UnknownTID = 5
    FileAlreadyExists = 6
    NoSuchUser = 7
    FailedNegotiation = 8


class TftpState(object):
    """This class represents a particular state for a TFTP Session. It encapsulates a
    state, kind of like an enum. The states mean the following:
    nil - Client/Server - Session not yet established
    rrq - Client - Just sent RRQ in a download, waiting for response
          Server - Just received an RRQ
    wrq - Client - Just sent WRQ in an upload, waiting for response
          Server - Just received a WRQ
    dat - Client/Server - Transferring data
    oack - Client - Just received oack
           Server - Just sent OACK
    ack - Client - Acknowledged oack, awaiting response
          Server - Just received ACK to OACK
    err - Client/Server - Fatal problems, giving up
    fin - Client/Server - Transfer completed
    """
    states = ['nil',
              'rrq',
              'wrq',
              'dat',
              'oack',
              'ack',
              'err',
              'fin']
    
    def __init__(self, state='nil'):
        self.state = state
        
    def getState(self):
        return self.__state
    
    def setState(self, state):
        if state in TftpState.states:
            self.__state = state
            
    state = property(getState, setState)

class TftpSession(connection):
    """This class is the base class for the tftp client and server. Any shared
    code should be in this class."""

    def __init__(self):
        """Class constructor. Note that the state property must be a TftpState
        object."""
        self.options = None
        self.state = TftpState()
        self.dups = 0
        self.errors = 0
        connection.__init__(self, 'udp')
        
        def __del__(self):
            print('__del__' + str(self))
        
                
    def senderror(self, errorcode):
        """This method uses the socket passed, and uses the errorcode, address
        and port to compose and send an error packet."""
        logger.debug("In senderror, being asked to send error %d to %s:%i"
                % (errorcode, self.remote.host, self.remote.port))
        errpkt = TftpPacketERR()
        errpkt.errorcode = errorcode
        self.send(errpkt.encode().buffer)

class TftpPacketWithOptions(object):
    """This class exists to permit some TftpPacket subclasses to share code
    regarding options handling. It does not inherit from TftpPacket, as the
    goal is just to share code here, and not cause diamond inheritance."""

    def __init__(self):
        self.options = []

    def setoptions(self, options):
        logger.debug("in TftpPacketWithOptions.setoptions")
        logger.debug("options: " + str(options))
        myoptions = {}
        for key in options:
            newkey = str(key)
            myoptions[newkey] = str(options[key])
            logger.debug("populated myoptions with %s = %s"
                         % (newkey, myoptions[newkey]))

        logger.debug("setting options hash to: " + str(myoptions))
        self._options = myoptions

    def getoptions(self):
        logger.debug("in TftpPacketWithOptions.getoptions")
        return self._options

    # Set up getter and setter on options to ensure that they are the proper
    # type. They should always be strings, but we don't need to force the
    # client to necessarily enter strings if we can avoid it.
    options = property(getoptions, setoptions)

    def decode_options(self, buffer):
        """This method decodes the section of the buffer that contains an
        unknown number of options. It returns a dictionary of option names and
        values."""
        nulls = 0
        format = "!"
        options = {}

        logger.debug("decode_options: buffer is: " + repr(buffer))
        logger.debug("size of buffer is %d bytes" % len(buffer))
        if len(buffer) == 0:
            logger.debug("size of buffer is zero, returning empty hash")
            return {}

        # Count the nulls in the buffer. Each one terminates a string.
        logger.debug("about to iterate options buffer counting nulls")
        length = 0
        for c in buffer:
            #logger.debug("iterating this byte: " + repr(c))
            if c == 0 or c == '\x00':
                logger.debug("found a null at length %d" % length)
                if length > 0:
                    format += "%dsx" % length
                    length = -1
                else:
                    raise TftpException("Invalid options in buffer")
            length += 1
                
        logger.debug("about to unpack, format is: %s" % format)
        mystruct = struct.unpack(format, buffer)
        
        tftpassert(len(mystruct) % 2 == 0, 
                   "packet with odd number of option/value pairs")
        
        for i in range(0, len(mystruct), 2):
            logger.debug("setting option %s to %s" % (mystruct[i], mystruct[i+1]))
            options[mystruct[i].decode()] = mystruct[i+1].decode()

        return options

class TftpPacket(object):
    """This class is the parent class of all tftp packet classes. It is an
    abstract class, providing an interface, and should not be instantiated
    directly."""
    def __init__(self):
        self.opcode = 0
        self.buffer = None

    def encode(self):
        """The encode method of a TftpPacket takes keyword arguments specific
        to the type of packet, and packs an appropriate buffer in network-byte
        order suitable for sending over the wire.
        
        This is an abstract method."""
        raise NotImplementedError("Abstract method")

    def decode(self):
        """The decode method of a TftpPacket takes a buffer off of the wire in
        network-byte order, and decodes it, populating internal properties as
        appropriate. This can only be done once the first 2-byte opcode has
        already been decoded, but the data section does include the entire
        datagram.
        
        This is an abstract method."""
        raise NotImplementedError("Abstract method")

class TftpPacketInitial(TftpPacket, TftpPacketWithOptions):
    """This class is a common parent class for the RRQ and WRQ packets, as 
    they share quite a bit of code."""
    def __init__(self):
        TftpPacket.__init__(self)
        TftpPacketWithOptions.__init__(self)
        self.filename = None
        self.mode = None
        
    def encode(self):
        """Encode the packet's buffer from the instance variables."""
        tftpassert(self.filename, "filename required in initial packet")
        tftpassert(self.mode, "mode required in initial packet")

        ptype = None
        if self.opcode == 1: ptype = "RRQ"
        else:                ptype = "WRQ"
        logger.debug("Encoding %s packet, filename = %s, mode = %s"
                     % (ptype, self.filename, self.mode))
        for key in self.options:
            logger.debug("    Option %s = %s" % (key, self.options[key]))
        
        format = "!H"
        format += "%dsx" % len(self.filename)
        if self.mode == "octet":
            format += "5sx"
        else:
            raise AssertionError("Unsupported mode: %s" % mode)
        # Add options.
        options_list = []
        if len(self.options.keys()) > 0:
            logger.debug("there are options to encode")
            for key in self.options:
                # Populate the option name
                format += "%dsx" % len(key)
                options_list.append(key)
                # Populate the option value
                format += "%dsx" % len(str(self.options[key]))
                options_list.append(str(self.options[key]))

        logger.debug("format is %s" % format)
        logger.debug("options_list is %s" % options_list)
        logger.debug("size of struct is %d" % struct.calcsize(format))

        self.buffer = struct.pack(format,
                                  self.opcode,
                                  self.filename,
                                  self.mode,
                                  *options_list)

        logger.debug("buffer is " + repr(self.buffer))
        return self
    
    def decode(self):
        tftpassert(self.buffer, "Can't decode, buffer is empty")

        # FIXME - this shares a lot of code with decode_options
        nulls = 0
        format = ""
        nulls = length = tlength = 0
        logger.debug("in decode: about to iterate buffer counting nulls")
        subbuf = self.buffer[2:]
        for c in subbuf:
            logger.debug("iterating this byte: " + repr(c))
            if c == 0 or c == '\x00':
                nulls += 1
                logger.debug("found a null at length %d, now have %d" 
                             % (length, nulls))
                format += "%dsx" % length
                length = -1
                # At 2 nulls, we want to mark that position for decoding.
                if nulls == 2:
                    break
            length += 1
            tlength += 1

        logger.debug("hopefully found end of mode at length %d" % tlength)
        # length should now be the end of the mode.
        tftpassert(nulls == 2, "malformed packet")
        shortbuf = subbuf[:tlength+1]
        logger.debug("about to unpack buffer with format: %s" % format)
        logger.debug("unpacking buffer: " + repr(shortbuf))
        mystruct = struct.unpack(format, shortbuf)

        tftpassert(len(mystruct) == 2, "malformed packet")
        
        try:        
            logger.debug("setting filename to %s" % mystruct[0])
            self.filename = mystruct[0].decode()
            logger.debug("setting mode to %s" % mystruct[1])
            self.mode = mystruct[1].decode()
        except:
            tftpassert(0, "malformed packet")

        self.options = self.decode_options(subbuf[tlength+1:])
        return self

class TftpPacketRRQ(TftpPacketInitial):
    """
        2 bytes    string   1 byte     string   1 byte
        -----------------------------------------------
RRQ/  | 01/02 |  Filename  |   0  |    Mode    |   0  |
WRQ     -----------------------------------------------
    """
    def __init__(self):
        TftpPacketInitial.__init__(self)
        self.opcode = 1

    def __str__(self):
        s = 'RRQ packet: filename = %s' % self.filename
        s += ' mode = %s' % self.mode
        if self.options:
            s += '\n    options = %s' % self.options
        return s

class TftpPacketWRQ(TftpPacketInitial):
    """
        2 bytes    string   1 byte     string   1 byte
        -----------------------------------------------
RRQ/  | 01/02 |  Filename  |   0  |    Mode    |   0  |
WRQ     -----------------------------------------------
    """
    def __init__(self):
        TftpPacketInitial.__init__(self)
        self.opcode = 2

    def __str__(self):
        s = 'WRQ packet: filename = %s' % self.filename
        s += ' mode = %s' % self.mode
        if self.options:
            s += '\n    options = %s' % self.options
        return s

class TftpPacketDAT(TftpPacket):
    """
        2 bytes    2 bytes       n bytes
        ---------------------------------
DATA  | 03    |   Block #  |    Data    |
        ---------------------------------
    """
    def __init__(self):
        TftpPacket.__init__(self)
        self.opcode = 3
        self.blocknumber = 0
        self.data = None

    def __str__(self):
        s = 'DAT packet: block %s' % self.blocknumber
        if self.data:
            s += '\n    data: %d bytes' % len(self.data)
        return s

    def encode(self):
        """Encode the DAT packet. This method populates self.buffer, and
        returns self for easy method chaining."""
        if len(self.data) == 0:
            logger.debug("Encoding an empty DAT packet")
        format = "!HH%ds" % len(self.data)
        self.buffer = struct.pack(format, 
                                  self.opcode, 
                                  self.blocknumber, 
                                  self.data)
        return self

    def decode(self):
        """Decode self.buffer into instance variables. It returns self for
        easy method chaining."""
        # We know the first 2 bytes are the opcode. The second two are the
        # block number.
        (self.blocknumber,) = struct.unpack("!H", self.buffer[2:4])
        logger.debug("decoding DAT packet, block number %d" % self.blocknumber)
        logger.debug("should be %d bytes in the packet total" 
                     % len(self.buffer))
        # Everything else is data.
        self.data = self.buffer[4:]
        logger.debug("found %d bytes of data"
                     % len(self.data))
        return self

class TftpPacketACK(TftpPacket):
    """
        2 bytes    2 bytes
        -------------------
ACK   | 04    |   Block #  |
        --------------------
    """
    def __init__(self):
        TftpPacket.__init__(self)
        self.opcode = 4
        self.blocknumber = 0

    def __str__(self):
        return 'ACK packet: block %d' % self.blocknumber

    def encode(self):
        logger.debug("encoding ACK: opcode = %d, block = %d" 
                     % (self.opcode, self.blocknumber))
        self.buffer = struct.pack("!HH", self.opcode, self.blocknumber)
        return self

    def decode(self):
        self.opcode, self.blocknumber = struct.unpack("!HH", self.buffer)
        logger.debug("decoded ACK packet: opcode = %d, block = %d"
                     % (self.opcode, self.blocknumber))
        return self

class TftpPacketERR(TftpPacket):
    """
        2 bytes  2 bytes        string    1 byte
        ----------------------------------------
ERROR | 05    |  ErrorCode |   ErrMsg   |   0  |
        ----------------------------------------
    Error Codes

    Value     Meaning

    0         Not defined, see error message (if any).
    1         File not found.
    2         Access violation.
    3         Disk full or allocation exceeded.
    4         Illegal TFTP operation.
    5         Unknown transfer ID.
    6         File already exists.
    7         No such user.
    8         Failed to negotiate options
    """
    def __init__(self):
        TftpPacket.__init__(self)
        self.opcode = 5
        self.errorcode = 0
        self.errmsg = None
        # FIXME - integrate in TftpErrors references?
        self.errmsgs = {
            1: "File not found",
            2: "Access violation",
            3: "Disk full or allocation exceeded",
            4: "Illegal TFTP operation",
            5: "Unknown transfer ID",
            6: "File already exists",
            7: "No such user",
            8: "Failed to negotiate options"
            }

    def __str__(self):
        s = 'ERR packet: errorcode = %d' % self.errorcode
        s += '\n    msg = %s' % self.errmsgs.get(self.errorcode, '')
        return s

    def encode(self):
        """Encode the DAT packet based on instance variables, populating
        self.buffer, returning self."""
        format = "!HH%dsx" % len(self.errmsgs[self.errorcode])
        logger.debug("encoding ERR packet with format %s" % format)
        self.buffer = struct.pack(format,
                                  self.opcode,
                                  self.errorcode,
                                  self.errmsgs[self.errorcode])
        return self

    def decode(self):
        "Decode self.buffer, populating instance variables and return self."
        tftpassert(len(self.buffer) > 4, "malformed ERR packet, too short")
        logger.debug("Decoding ERR packet, length %s bytes" %
                len(self.buffer))
        format = "!HH%dsx" % (len(self.buffer) - 5)
        logger.debug("Decoding ERR packet with format: %s" % format)
        self.opcode, self.errorcode, self.errmsg = struct.unpack(format, 
                                                                 self.buffer)
        logger.error("ERR packet - errorcode: %d, message: %s"
                     % (self.errorcode, self.errmsg))
        return self
    
class TftpPacketOACK(TftpPacket, TftpPacketWithOptions):
    """
    #  +-------+---~~---+---+---~~---+---+---~~---+---+---~~---+---+
    #  |  opc  |  opt1  | 0 | value1 | 0 |  optN  | 0 | valueN | 0 |
    #  +-------+---~~---+---+---~~---+---+---~~---+---+---~~---+---+
    """
    def __init__(self):
        TftpPacket.__init__(self)
        TftpPacketWithOptions.__init__(self)
        self.opcode = 6

    def __str__(self):
        return 'OACK packet:\n    options = %s' % self.options
        
    def encode(self):
        format = "!H" # opcode
        options_list = []
        logger.debug("in TftpPacketOACK.encode")
        for key in self.options:
            logger.debug("looping on option key %s" % key)
            logger.debug("value is %s" % self.options[key])
            format += "%dsx" % len(key)
            format += "%dsx" % len(self.options[key])
            options_list.append(key)
            options_list.append(self.options[key])
        self.buffer = struct.pack(format, self.opcode, *options_list)
        return self
    
    def decode(self):
        self.options = self.decode_options(self.buffer[2:])
        return self
    
    def match_options(self, options):
        """This method takes a set of options, and tries to match them with
        its own. It can accept some changes in those options from the server as
        part of a negotiation. Changed or unchanged, it will return a dict of
        the options so that the session can update itself to the negotiated
        options."""
        for name in self.options:
            if name in options:
                if name == 'blksize':
                    # We can accept anything between the min and max values.
                    size = int(self.options[name])
                    if size >= MIN_BLKSIZE and size <= MAX_BLKSIZE:
                        logger.debug("negotiated blksize of %d bytes" % size)
                        options[name] = size
                else:
                    raise TftpException("Unsupported option: %s" % name)
        return True


class TftpPacketFactory(object):
    """This class generates TftpPacket objects. It is responsible for parsing
    raw buffers off of the wire and returning objects representing them, via
    the parse() method."""
    def __init__(self):
        self.classes = {
            1: TftpPacketRRQ,
            2: TftpPacketWRQ,
            3: TftpPacketDAT,
            4: TftpPacketACK,
            5: TftpPacketERR,
            6: TftpPacketOACK
            }

    def parse(self, buffer):
        """This method is used to parse an existing datagram into its
        corresponding TftpPacket object. The buffer is the raw bytes off of
        the network."""
        logger.debug("parsing a %d byte packet" % len(buffer))
        (opcode,) = struct.unpack("!H", buffer[:2])
        logger.debug("opcode is %d" % opcode)
        packet = self.__create(opcode)
        packet.buffer = buffer
        return packet.decode()

    def __create(self, opcode):
        """This method returns the appropriate class object corresponding to
        the passed opcode."""
        tftpassert( opcode in self.classes, 
                   "Unsupported opcode: %d" % opcode)

        packet = self.classes[opcode]()

        logger.debug("packet is %s" % packet)
        return packet


class TftpServerHandler(TftpSession):
    def __init__ (self, state, root, localhost, remotehost, remoteport, packet):
        TftpSession.__init__(self)
        self.bind(localhost,0)
        self.connect(remotehost, remoteport)
        self.packet = packet
        self.state = state
        self.root = root
        self.mode = None
        self.filename = None
        self.options = { 'blksize': DEF_BLKSIZE }
        self.blocknumber = 0
        self.buffer = None
        self.fileobj = None
        self.timeouts.idle = 3
        self.timeouts.sustain = 120

    def handle_io_in(self, data):
        """This method informs a handler instance that it has data waiting on
        its socket that it must read and process."""
        recvpkt = self.packet.parse(data)

        # FIXME - refactor into another method, this is too big
        if isinstance(recvpkt, TftpPacketRRQ):
            logger.debug("Handler %s received RRQ packet" % self)
            logger.debug("Requested file is %s, mode is %s" % (recvpkt.filename, recvpkt.mode))

            if recvpkt.mode != 'octet':
                self.senderror(TftpErrors.IllegalTftpOp)
                raise TftpException("Unsupported mode: %s" % recvpkt.mode)

            if self.state.state == 'rrq':
                logger.debug("Received RRQ. Composing response.")
                self.filename = self.root + os.sep + recvpkt.filename
                logger.debug("The path to the desired file is %s" %
                        self.filename)
                self.filename = os.path.abspath(self.filename)
                logger.debug("The absolute path is %s" % self.filename)
                # Security check. Make sure it's prefixed by the tftproot.
                if self.filename.find(self.root) == 0:
                    logger.debug("The path appears to be safe: %s" %
                            self.filename)
                else:
                    logger.error("Insecure path: %s" % self.filename)
                    self.errors += 1
                    self.senderror(TftpErrors.AccessViolation)
                    raise TftpException("Insecure path: %s" % self.filename)

                # Does the file exist?
                if os.path.exists(self.filename):
                    logger.debug("File %s exists." % self.filename)

                    # Check options. Currently we only support the blksize
                    # option.
                    if 'blksize' in recvpkt.options:
                        logger.debug("RRQ includes a blksize option")
                        blksize = int(recvpkt.options['blksize'])
                        # Delete the option now that it's handled.
                        del recvpkt.options['blksize']
                        if blksize >= MIN_BLKSIZE and blksize <= MAX_BLKSIZE:
                            logger.info("Client requested blksize = %d"
                                    % blksize)
                            self.options['blksize'] = blksize
                        else:
                            logger.warning("Client %s requested invalid "
                                           "blocksize %d, responding with default"
                                           % (self.remote.host, blksize))
                            self.options['blksize'] = DEF_BLKSIZE

                    if 'tsize' in recvpkt.options:
                        logger.info('RRQ includes tsize option')
                        self.options['tsize'] = os.stat(self.filename).st_size
                        # Delete the option now that it's handled.
                        del recvpkt.options['tsize']

                    if len(list(recvpkt.options.keys())) > 0:
                        logger.warning("Client %s requested unsupported options: %s"
                                       % (self.remote.host, recvpkt.options))

                    if self.options['blksize'] != DEF_BLKSIZE or 'tsize' in self.options:
                        logger.info("Options requested, sending OACK")
                        self.send_oack()
                    else:
                        logger.debug("Client %s requested no options."
                                     % self.remote.host)
                        self.start_download()

                else:
                    logger.error("Requested file %s does not exist." %
                            self.filename)
                    self.senderror(TftpErrors.FileNotFound)
                    raise TftpException("Requested file not found: %s" % self.filename)

            else:
                # We're receiving an RRQ when we're not expecting one.
                logger.error("Received an RRQ in handler %s "
                             "but we're in state %s" % (self.remote.host, self.state))
                self.errors += 1

        # Next packet type
        elif isinstance(recvpkt, TftpPacketACK):
            logger.debug("Received an ACK from the client.")
            if recvpkt.blocknumber == 0 and self.state.state == 'oack':
                logger.debug("Received ACK with 0 blocknumber, starting download")
                self.start_download()
            else:
                if self.state.state == 'dat' or self.state.state == 'fin':
                    if self.blocknumber == recvpkt.blocknumber:
                        logger.debug("Received ACK for block %d"
                                % recvpkt.blocknumber)
                        if self.state.state == 'fin':
#                            raise TftpException, "Successful transfer."
                            self.close()
                        else:
                            self.send_dat()
                    elif recvpkt.blocknumber < self.blocknumber:
                        # Don't resend a DAT due to an old ACK. Fixes the
                        # sorceror's apprentice problem.
                        logger.warn("Received old ACK for block number %d"
                                % recvpkt.blocknumber)
                    else:
                        logger.warn("Received ACK for block number "
                                    "%d, apparently from the future"
                                    % recvpkt.blocknumber)
                else:
                    logger.error("Received ACK with block number %d "
                                 "while in state %s"
                                 % (recvpkt.blocknumber,
                                    self.state.state))

        elif isinstance(recvpkt, TftpPacketERR):
            logger.error("Received error packet from client: %s" % recvpkt)
            self.state.state = 'err'
            raise TftpException("Received error from client")

        # Handle other packet types.
        else:
            logger.error("Received packet %s while handling a download"
                    % recvpkt)
            self.senderror(TftpErrors.IllegalTftpOp)
            raise TftpException("Invalid packet received during download")
        return len(data)

    def start_download(self):
        """This method opens self.filename, stores the resulting file object
        in self.fileobj, and calls send_dat()."""
        self.state.state = 'dat'
        self.fileobj = open(self.filename, "rb")
        self.send_dat()

    def send_dat(self, resend=False):
        """This method reads sends a DAT packet based on what is in self.buffer."""
        if not resend:
            blksize = int(self.options['blksize'])
            self.buffer = self.fileobj.read(blksize)
            logger.debug("Read %d bytes into buffer" % len(self.buffer))
            if len(self.buffer) < blksize:
                logger.info("Reached EOF on file %s" % self.filename)
                self.state.state = 'fin'
            self.blocknumber += 1
            if self.blocknumber > 65535:
                logger.debug("Blocknumber rolled over to zero")
                self.blocknumber = 0
        else:
            logger.warn("Resending block number %d" % self.blocknumber)
        dat = TftpPacketDAT()
        dat.data = self.buffer
        dat.blocknumber = self.blocknumber
        logger.debug("Sending DAT packet %d" % self.blocknumber)
        self.send(dat.encode().buffer)


    # FIXME - should these be factored-out into the session class?
    def send_oack(self):
        """This method sends an OACK packet based on current params."""
        logger.debug("Composing and sending OACK packet")
        oack = TftpPacketOACK()
        oack.options = self.options
        self.send(oack.encode().buffer)
        self.state.state = 'oack'
        logger.debug("state %s" % self.state.state)


class TftpServer(TftpSession):
    def __init__(self):
        TftpSession.__init__(self)
        self.packet = TftpPacketFactory()
        self.root = ''
	
    def handle_io_in(self,data):
        logger.debug("Data ready on our main socket")
        buffer = data
        logger.debug("Read %d bytes" % len(buffer))
        recvpkt = None
        try:
            recvpkt = self.packet.parse(buffer)
        except:
            return len(data)

        if isinstance(recvpkt, TftpPacketRRQ):
            logger.debug("RRQ packet from %s:%i" % (self.remote.host, self.remote.port))
            t = TftpServerHandler(TftpState('rrq'), self.root, self.local.host, self.remote.host, self.remote.port, self.packet)
            t.handle_io_in(data)
        elif isinstance(recvpkt, TftpPacketWRQ):
            logger.error("Write requests not implemented at this time.")
            self.senderror(TftpErrors.IllegalTftpOp)
        return len(data)

    def chroot(self,r):
        self.root = r;

class TftpClient(TftpSession):
    """This class is an implementation of a tftp client. Once instantiated, a
    download can be initiated via the download() method."""
    def __init__(self):
        TftpSession.__init__(self)
        self.timeouts.idle=5
        self.timeouts.sustain = 120
        self.options = {}
        self.packet = TftpPacketFactory()
        self.expected_block = 0
        self.curblock = 0
        self.bytes = 0
        self.filename = None
        self.port = 0
        self.connected = False
        self.idlecount = 0

    def __del__(self):
        print('__del__' + str(self))

    def download(self, lhost, host, port, filename):
        logger.info("Connecting to %s to download" % host)
        logger.info("    filename -> %s" % filename)

        if 'blksize' in self.options:
            size = self.options['blksize']
            if size < MIN_BLKSIZE or size > MAX_BLKSIZE:
                raise TftpException("Invalid blksize: %d" % size)
        else:
            self.options['blksize'] = DEF_BLKSIZE

        self.filename = filename
        self.port = port
        if lhost != None:
            self.bind(lhost, 0)
        self.connect(host,0)

    def handle_established(self):
        logger.info("connection to %s established" % self.remote.host)
        logger.info("port %i established" % self.port)
        self.remote.port = self.port
        pkt = TftpPacketRRQ()
        pkt.filename = self.filename
        pkt.mode = "octet" # FIXME - shouldn't hardcode this
        pkt.options = self.options
        self.last_packet = pkt.encode().buffer
        self.send(self.last_packet)
        self.state.state = 'rrq'
        self.fileobj = tempfile.NamedTemporaryFile(delete=False, prefix='tftp-', suffix=g_dionaea.config()['downloads']['tmp-suffix'], dir=g_dionaea.config()['downloads']['dir'])

    def handle_io_in(self, data):
        print('packet from %s:%i' % (self.remote.host, self.remote.port))
        
        if self.connected == False:
            self.connect(self.remote.host, self.remote.port)
            self.connected = True


        recvpkt = self.packet.parse(data)
        if isinstance(recvpkt, TftpPacketDAT):
            logger.debug("recvpkt.blocknumber = %d" % recvpkt.blocknumber)
            logger.debug("curblock = %d" % self.curblock)

            if self.state.state == 'rrq' and self.options:
                logger.info("no OACK, our options were ignored")
                self.options = { 'blksize': DEF_BLKSIZE }
                self.state.state = 'ack'

            self.expected_block = self.curblock + 1
            if self.expected_block > 65535:
                logger.debug("block number rollover to 0 again")
                self.expected_block = 0
            if recvpkt.blocknumber == self.expected_block:
                logger.debug("good, received block %d in sequence"
                            % recvpkt.blocknumber)
                self.curblock = self.expected_block


                # ACK the packet, and save the data.
                logger.info("sending ACK to block %d" % self.curblock)
                logger.debug("ip = %s, port = %i" % (self.remote.host, self.remote.port))
                ackpkt = TftpPacketACK()
                ackpkt.blocknumber = self.curblock
                self.last_packet = ackpkt.encode().buffer
                self.send(self.last_packet)

                logger.debug("writing %d bytes to output file"
                            % len(recvpkt.data))
                self.fileobj.write(recvpkt.data)
                self.bytes += len(recvpkt.data)
                # Check for end-of-file, any less than full data packet.
                if len(recvpkt.data) < int(self.options['blksize']):
                    logger.info("end of file detected")
                    self.fileobj.close()
                    icd = incident("dionaea.download.complete")
                    icd.set('path', self.fileobj.name)
                    icd.report()
                    self.close()
                    self.fileobj.unlink(self.fileobj.name)
                    

            elif recvpkt.blocknumber == self.curblock:
                logger.warn("dropping duplicate block %d" % self.curblock)
                logger.debug("ACKing block %d again, just in case" % self.curblock)
                ackpkt = TftpPacketACK()
                ackpkt.blocknumber = self.curblock
                self.send(ackpkt.encode().buffer)

            else:
                msg = "Whoa! Received block %d but expected %d" % (recvpkt.blocknumber,
                                                                self.curblock+1)
                logger.error(msg)

        # Check other packet types.
        elif isinstance(recvpkt, TftpPacketOACK):
            if not self.state.state == 'rrq':
                self.errors += 1
                logger.error("Received OACK in state %s" % self.state.state)
#                continue
            self.state.state = 'oack'
            logger.info("Received OACK from server.")
            if len(recvpkt.options.keys()) > 0:
                if recvpkt.match_options(self.options):
                    logger.info("Successful negotiation of options")
                    # Set options to OACK options
                    self.options = recvpkt.options
                    for key in self.options:
                        logger.info("    %s = %s" % (key, self.options[key]))
                    logger.debug("sending ACK to OACK")
                    ackpkt = TftpPacketACK()
                    ackpkt.blocknumber = 0
                    self.last_packet = ackpkt.encode().buffer
                    self.send(self.last_packet)
                    self.state.state = 'ack'
                else:
                    logger.error("failed to negotiate options")
                    self.senderror(TftpErrors.FailedNegotiation)
                    self.state.state = 'err'
                    raise TftpException("Failed to negotiate options")

        elif isinstance(recvpkt, TftpPacketACK):
            # Umm, we ACK, the server doesn't.
            self.state.state = 'err'
            self.senderror(TftpErrors.IllegalTftpOp)
            tftpassert(False, "Received ACK from server while in download")

        elif isinstance(recvpkt, TftpPacketERR):
            self.state.state = 'err'
            self.senderror(TftpErrors.IllegalTftpOp)
            tftpassert(False, "Received ERR from server: " + str(recvpkt))

        elif isinstance(recvpkt, TftpPacketWRQ):
            self.state.state = 'err'
            self.senderror(TftpErrors.IllegalTftpOp)
            tftpassert(False, "Received WRQ from server: " + str(recvpkt))
        else:
            self.state.state = 'err'
            self.senderror(TftpErrors.IllegalTftpOp)
            tftpassert(False, "Received unknown packet type from server: " + str(recvpkt))
        return len(data)

    def handle_error(self, err):
        pass

    def handle_timeout_idle(self):
        logger.warn("tftp timeout!")
        if self.idlecount > 10:
            self.fileobj.close()
            self.fileobj.unlink(self.fileobj.name)
            return False
        self.idlecount+=1
        self.send(self.last_packet)
        return True

from urllib import parse

class tftpdownloadhandler(ihandler):
    def __init__(self):
        logger.debug("%s ready!" % (self.__class__.__name__))
        ihandler.__init__(self, 'dionaea.download.offer')
    def handle(self, icd):
        logger.warn("do download")
        url = icd.get("url")
        if url.startswith('tftp://'):
            # python fails parsing tftp://, ftp:// works, so ...
            url = url[1:]
            x = parse.urlsplit(url)
            try:
                con = icd.get('con')
                lhost = con.local.host
            except AttributeError:
                lhost = None
            t=TftpClient()
            t.download(lhost, x.netloc, 69, x.path[1:])
            print(x)

