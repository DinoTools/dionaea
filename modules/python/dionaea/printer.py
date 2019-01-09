#*************************************************************************
#*                               Dionaea
#*                           - catches bugs -
#*
#*
#*
#* Copyright (C) 2019  Michael Neu
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
#*             contact inquiries@michaeln.eu
#*
#*******************************************************************************/

# The following code is based on github.com/michaelneu/pjl-honeypot
# MIT licensed code, GPL compatible
# Copyright (c) 2019 Michael Neu

# pjl/pcl server (printer)
from dionaea import ServiceLoader
from dionaea.core import connection, g_dionaea, incident
from dionaea.exception import ServiceConfigError
import logging
import os
import re
import time

logger = logging.getLogger("printer")
logger.setLevel(logging.DEBUG)

class PrinterService(ServiceLoader):
    name = "printer"

    @classmethod
    def start(cls, addr,  iface=None, config=None):
        if config is None:
            config = {}

        daemon = Printerd()
        try:
            daemon.apply_config(config)
        except ServiceConfigError as e:
            logger.error(e.msg, *e.args)
            return
        daemon.bind(addr, 9100, iface=iface)
        daemon.listen()
        return daemon

def convert_pjl_command_to_regex(command):
    """Converts an underscore separated PJL command to a regex pattern.

    The generated regex pattern captures the command's arguments in the first group.
    """
    command_bytes = bytes(command, "utf-8")
    return re.compile(rb"^\@pjl\s+%s\s*(.*)" % command_bytes.replace(b"_", rb"\s+"), re.IGNORECASE)

def convert_pjl_responses_to_regex(responses_dict):
    """Converts all dictionary items to a (regex, command, response) triple.

    The regex is generated using `convert_pjl_command_to_regex`, thus it can be used to capture arguements.
    """
    return [
        (
            convert_pjl_command_to_regex(command),
            command,
            response,
        )
        for command, response in responses_dict.items()
    ]

def cut_bytes_before_last_crlf(text):
    """Cuts the given text before the last line break.

    Example:
        cut_bytes_before_last_crlf(b"foo\r\nbar") => b"foo\r\n"
        cut_bytes_before_last_crlf(b"foo\r\nbar\r\n") => b"foo\r\nbar\r\n"
    """
    try:
        last_crlf_index = text.rindex(b"\r\n")
        return text[0:last_crlf_index + 2]
    except ValueError:
        return text

pjl_default_responses = {
    "comment": "",
    "enter_language_pcl": "E . . . . PCL Job . . . . E",
    "enter_language_postscript": "%!PS-ADOBE ... PostScript print job ...",
    "job": "",
    "eoj": "",
    "default": "",
    "set": "",
    "initialize": "",
    "reset": "",
    "inquire_ret": "MEDIUM",
    "inquire_pageprotect": "OFF",
    "inquire_resolution": "600",
    "inquire_personality": "AUTO",
    "inquire_timeout": "15",
    "inquire_lparm:pcl_pitch": "10.00",
    "inquire_lparm:pcl_ptsize": "12.00",
    "inquire_lparm:pcl_symset": "ROMAN8",
    "dinquire_ret": "MEDIUM",
    "dinquire_pageprotect": "OFF",
    "dinquire_resolution": "600",
    "dinquire_personality": "AUTO",
    "dinquire_timeout": "15",
    "dinquire_lparm:pcl_pitch": "10.00",
    "dinquire_lparm:pcl_ptsize": "12.00",
    "dinquire_lparm:pcl_symset": "ROMAN8",
    "info_id": "HP LASERJET 4ML",
    "info_config": "IN TRAYS [3 ENUMERATED]\n\tINTRAY1 MP\n\tINTRAY2 PC\n\tINTRAY3 LC\nENVELOPE TRAY\nOUT TRAYS [1 ENUMERATED]\n\tNORMAL FACEDOWN\nPAPERS [9 ENUMERATED]\n\tLETTER\n\tLEGAL\n\tA4\n\tEXECUTIVE\n\tMONARCH\n\tCOM10\n\tDL\n\tC5\n\tB5\nLANGUAGES [2 ENUMERATED]\n\tPCL\n\tPOSTSCRIPT\nUSTATUS [4 ENUMERATED]\n\tDEVICE\n\tJOB\n\tPAGE\n\tTIMED\nFONT CARTRIDGE SLOTS [1 ENUMERATED]\n\tCARTRIDGE\nMEMORY=2097152\nDISPLAY LINES=1\nDISPLAY CHARACTER SIZE=16",
    "info_filesys": "VOLUME TOTAL SIZE FREE SPACE LOCATION LABEL STATUS\n0:     1755136    1718272    <HT>     <HT>  READ-WRITE",
    "info_memory": "TOTAL=1494416\nLARGEST=1494176",
    "info_pagecount": "PAGECOUNT=183933",
    "info_status": "CODE=10001\nDISPLAY=\"Non HP supply in use\"\nONLINE=TRUE",
    "info_variables": "COPIES=1 [2 RANGE]\n\t1\n\t999\nPAPER=LETTER [3 ENUMERATED]\n\tLETTER\n\tLEGAL\n\tA4\nORIENTATION=PORTRAIT [2 ENUMERATED]\n\tPORTRAIT\n\tLANDSCAPE\nFORMLINES=60 [2 RANGE]\n\t5\n\t128\nMANUALFEED=OFF [2 ENUMERATED]\n\tOFF\n\tON\nRET=MEDIUM [4 ENUMERATED]\n\tOFF\n\tLIGHT\n\tMEDIUM\n\tDARK\nPAGEPROTECT=OFF [4 ENUMERATED]\n\tOFF\n\tLETTER\n\tLEGAL\n\tA4\nRESOLUTION=600 [2 ENUMERATED]\n\t300\n\t600\nPERSONALITY=AUTO [3 ENUMERATED]\n\tAUTO\n\tPCL\n\tPOSTSCRIPT\nTIMEOUT=15 [2 RANGE]\n\t5\n\t300\nMPTRAY=CASSETTE [3 ENUMERATED]\n\tMANUAL\n\tCASSETTE\n\tFIRST\nINTRAY1=UNLOCKED [2 ENUMERATED]\n\tUNLOCKED\n\tLOCKED\nINTRAY2=UNLOCKED [2 ENUMERATED]\n\tUNLOCKED\n\tLOCKED\nINTRAY3=UNLOCKED [2 ENUMERATED]\n\tUNLOCKED\n\tLOCKED\nCLEARABLEWARNINGS=ON [2 ENUMERATED READONLY]\n\tJOB\n\tON\nAUTOCONT=OFF [2 ENUMERATED READONLY]\n\tOFF\n\tON\n\nDENSITY=3 [2 RANGE READONLY]\n\t1\n\t5\nLOWTONER=ON [2 ENUMERATED READONLY]\n\tOFF\n\tON\nINTRAY1SIZE=LETTER [9 ENUMERATED READONLY]\n\tLETTER\n\tLEGAL\n\tA4\n\tEXECUTIVE\n\tCOM10\n\tMONARCH\n\tC5\n\tDL\n\tB5\nINTRAY2SIZE=LETTER [4 ENUMERATED READONLY]\n\tLETTER\n\tLEGAL\n\tA4\n\tEXECUTIVE\nINTRAY3SIZE=LETTER [4 ENUMERATED READONLY]\n\tLETTER\n\tLEGAL\n\tA4\n\tEXECUTIVE\nINTRAY4SIZE=COM10 [5 ENUMERATED READONLY]\n\tCOM10\n\tMONARCH\n\tC5\n\tDL\n\tB5\nLPARM:PCL FONTSOURCE=I [1 ENUMERATED]\n\tI\nLPARM:PCL FONTNUMBER=0 [2 RANGE]\n\t0\n\t50\nLPARM:PCL PITCH=10.00 [2 RANGE]\n\t0.44\n\t99.99\nLPARM:PCL PTSIZE=12.00 [2 RANGE]\n\t4.00\n\t999.75\nLPARM:PCL SYMSET=ROMAN8 [4 ENUMERATED]\n\tROMAN8\n\tISOL1\n\tISOL2\n\tWIN30\nLPARM:POSTSCRIPT PRTPSERRS=OFF [2 ENUMERATED]\n\tOFF\n\tON",
    "info_ustatus": "DEVICE=OFF [3 ENUMERATED]\n\tOFF\n\tON\n\tVERBOSE\nJOB=OFF [2 ENUMERATED]\n\tOFF\n\tON\nPAGE=OFF [2 ENUMERATED]\n\tOFF\n\tON\nTIMED=0 [2 RANGE]\n\t5\n\t300",
    "ustatusoff": "",
    "ustatus_device": "CODE=10001\nDISPLAY=\"Non HP supply in use\"\nONLINE=TRUE",
    "ustatus_job": "",
    "ustatus_page": "",
    "ustatus_timed": "CODE=10001\nDISPLAY=\"Non HP supply in use\"\nONLINE=TRUE",
    "rdymsg": "",
    "opmsg": "",
    "stmsg": "",
    "fsappend": "",
    "fsdelete": "",
    "fsdownload": "",
    "fsinit": "",
    "fsmkdir": "",
    "fsupload": "",
}

echo_command_regex = convert_pjl_command_to_regex("echo")
fsdirlist_command_regex = convert_pjl_command_to_regex("fsdirlist")
fsquery_command_regex = convert_pjl_command_to_regex("fsquery")
path_regex = re.compile(r"\"([^\"]+)\"")

class Printerd(connection):
    """A PJL/PCL based printer daemon
    """
    STATE_INIT, STATE_PJL, STATE_PCL = range(3)

    protocol_name = "printerd"
    shared_config_values = [
        "download_dir",
        "pjl_response_regexes",
        "root",
    ]

    def __init__(self, proto="tcp"):
        connection.__init__(self, proto)
        self.download_dir = None
        self.root = None

        self.pjl_response_regexes = []
        self.pjl_responses = dict(pjl_default_responses.items())

        self.state = self.STATE_INIT
        self.pjl_program_delimiter = None
        self.pcl_file_handle = None

    def reply(self, msg):
        """Sends the given message back to the client.
        """
        msg_lf = "%s\n" % msg
        msg_crlf = msg_lf.replace("\n", "\r\n")

        logger.debug("sending %s", bytes(msg_crlf, "utf-8"))
        self.send(msg_crlf)

    def apply_config(self, config):
        """Applies the given configuration to this daemon
        """
        dionaea_config = g_dionaea.config().get("dionaea")
        self.download_dir = dionaea_config.get("download.dir")

        if self.download_dir is None:
            raise ServiceConfigError("download_dir not defined")
        if not os.path.isdir(self.download_dir):
            raise ServiceConfigError("The PCL output directory '%s' is not a directory" % self.download_dir)
        if not os.access(self.download_dir, os.W_OK):
            raise ServiceConfigError("Unable to write files in '%s'" % self.download_dir)

        self.root = config.get("root")

        if self.root is None:
            raise ServiceConfigError("root not defined")
        if not os.path.isdir(self.root):
            raise ServiceConfigError("The PJL filesystem '%s' is not a directory" % self.root)
        if not os.access(self.root, os.R_OK):
            raise ServiceConfigError("Unable to read files in '%s'" % self.root)

        self.pjl_responses.update(config.get("pjl_msgs", {}))
        self.pjl_response_regexes = convert_pjl_responses_to_regex(self.pjl_responses)
    
    def chroot(self, p):
        self.root = p
    
    def handle_origin(self, parent):
        logger.debug("setting download_dir to '%s' from parent" % parent.download_dir)
        self.download_dir = parent.download_dir

        logger.debug("setting pjl_response_regexes from parent")
        self.pjl_response_regexes = parent.pjl_response_regexes

        logger.debug("setting root from parent")
        self.root = parent.root
    
    def handle_established(self):
        self.processors()

    def handle_disconnect(self):
        if self.pcl_file_handle is not None:
            self.pcl_file_handle.close()

    def handle_io_in(self, data):
        logger.debug("received %s", str(data))

        if self.state == self.STATE_INIT:
            if data.startswith(b"\x1bE\x1b&l"):
                logger.debug("entering PCL mode")
                self.state = self.STATE_PCL
            else:
                logger.debug("entering PJL mode")
                self.state = self.STATE_PJL

        if self.state == self.STATE_PJL:
            return self.process_pjl_program(data)
        elif self.state == self.STATE_PCL:
            return self.process_pcl(data)

    def process_pjl_program(self, program):
        """Parses a PJL program, taking delimiters and chunk-split programs into account.

        If the program starts with a delimiter, it will be removed and be expected in each
        follow up chunk, until it appears. If a previous chunk started with a delimiter,
        but the current chunk doesn't end with one, the last line will be preserved, to
        wait for more data.
        """
        processed_bytes = 0
        reset_delimiter = False

        if self.pjl_program_delimiter is None:
            try:
                program_start = program.index(b"@")
            except ValueError:
                program_start = 0
            
            if program_start != 0:
                self.pjl_program_delimiter = program[0:program_start]
                program = program[len(self.pjl_program_delimiter):]
                processed_bytes += len(self.pjl_program_delimiter)

        if self.pjl_program_delimiter:
            if program.endswith(self.pjl_program_delimiter):
                program = program[0:-len(self.pjl_program_delimiter)]
                processed_bytes += len(self.pjl_program_delimiter)
                reset_delimiter = True
            else:
                program = cut_bytes_before_last_crlf(program)

        if not program.endswith(b"\r\n"):
            program = cut_bytes_before_last_crlf(program)

        lines = program.strip().split(b"\r\n")
        processed_bytes += len(program)

        for line in lines:
            while self.pjl_program_delimiter and line.startswith(self.pjl_program_delimiter):
                line = line[len(self.pjl_program_delimiter):]

            self.process_pjl_line(line)

        if reset_delimiter:
            self.pjl_program_delimiter = None

        return processed_bytes
    
    def process_pjl_line(self, line):
        """Executes a line of PJL code.

        Static PJL commands, as defined in `pjl_default_responses`, will be sent as is, whereas
        "dynamic" commands like ECHO or FSQUERY will take their arguments into account.

        If no matching command could be found, "?" will be sent.
        """
        for regex, command, response in self.pjl_response_regexes:
            match = regex.match(line)

            if match:
                logger.debug("input matches command '%s'", command)
                self.reply(response)
                return

        echo_match = echo_command_regex.match(line)
        if echo_match:
            command = echo_match.group(0).decode("utf-8")
            self.pjl_ECHO(command)
            return
        
        fsdirlist_match = fsdirlist_command_regex.match(line)
        if fsdirlist_match:
            arguments = fsdirlist_match.group(1).decode("utf-8")
            self.pjl_FSDIRLIST(arguments)
            return 
        
        fsquery_match = fsquery_command_regex.match(line)
        if fsquery_match:
            arguments = fsquery_match.group(1).decode("utf-8")
            self.pjl_FSQUERY(arguments)
            return

        logger.warning("unable to find command for '%s'", str(line))
        self.reply("?")

    def pjl_ECHO(self, command):
        """@PJL ECHO COMMAND
        """
        logger.debug("echo %s", command)
        stripped_command = command.strip()
        self.reply(stripped_command)

    def extract_path_from_arguments(self, arguments):
        """Extracts a path string from a command's arguments.
        """
        paths = path_regex.findall(arguments)

        if len(paths) > 0:
            path = paths[0]
            return self.normalize_path(path)

    def normalize_path(self, path):
        """Normalizes the given PJL path to a regular path.

        Example:
            normalize_path(r"0:\\foo\\bar") => "0/foo/bar"
        """
        volume, rest = path.split(":", 2)
        path_parts = [volume] + [part for part in re.split(r"(\\|/)", rest) if part.strip() not in ["", "/", "\\"]]
        full_path = os.path.join(*path_parts)

        while "../" in full_path:
            full_path = full_path.replace("../", "")

        return full_path

    def listdir(self, path):
        """Sends the result similar to an `ls` call.

        If the file doesn't exist, "FILEERROR=1" will be sent. If the path is a
        directory, a directory listing will be sent, whereas a file will only yield
        its name and size according to the PJL specification.
        """
        actual_path = os.path.join(self.root, path)

        if not os.path.exists(actual_path):
            self.reply("FILEERROR=1")
            return

        template_file = "%s TYPE=FILE SIZE=%d"
        template_directory = "%s TYPE=DIR"

        if os.path.isfile(actual_path):
            stat = os.stat(actual_path)
            basename = os.path.basename(actual_path)

            self.reply(template_file % (basename, stat.st_size))
        elif os.path.isdir(actual_path):
            directory_entries = sorted(os.listdir(actual_path))

            files = []
            directories = [template_directory % "."]

            if "/" in path:
                directories.append(template_directory % "..")
            
            for entry in directory_entries:
                entry_path = os.path.join(actual_path, entry)

                if os.path.isfile(entry_path):
                    stat = os.stat(entry_path)
                    files.append(template_file % (entry, stat.st_size))
                elif os.path.isdir(entry_path):
                    directories.append(template_directory % entry)
            
            listing = directories + files
            self.reply("\n".join(listing))

    def pjl_FSDIRLIST(self, arguments):
        """@PJL FSDIRLIST NAME="PATH"
        """
        path = self.extract_path_from_arguments(arguments)
        logger.debug("listdir '%s'", path)
        self.listdir(path)

    def pjl_FSQUERY(self, arguments):
        """@PJL FSQUERY NAME="PATH"
        """
        path = self.extract_path_from_arguments(arguments)
        logger.debug("fsquery '%s'", path)
        self.listdir(path)

    def process_pcl(self, data):
        """Starts "printing" the given PCL to a new file.

        The file name will be created using the current time, e.g. "print-1547056738.pcl".
        Additionally, an incident "dionaea.modules.python.printer.print" will be created.
        """
        if self.pcl_file_handle is None:
            filename = "print-%d.pcl" % time.time()
            path = os.path.join(self.download_dir, filename)
            logger.info("printing to '%s'", path)
            self.pcl_file_handle = open(path, "wb")

            icd = incident("dionaea.modules.python.printer.print")
            icd.con = self
            icd.path = path
            icd.report()

        self.pcl_file_handle.write(data)
        return len(data)
