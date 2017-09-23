# coding=utf-8

import argparse
import ctypes
import ctypes.wintypes as wintypes
import yara
import os
import pefile
import sys
import progressbar

__version__ = '1.0'
__author__ = 'Mor Kalfon (zefferno@gmail.com)'
__program_desc__ = 'UNRUY Malware Removal Tool'

SIGNATURE_FILE = os.path.join(os.path.dirname(__file__), 'unruy.yar')
# System processes are not affected by the malware
PROCESSES_TO_SKIP_SCAN = [0, 4]
# File extensions to scan
FILE_EXTENSIONS = [".exe"]

class UNRUYScanner:
    # PROCESSENTRY32 Windows structure
    class PROCESSENTRY32(ctypes.Structure):
        _fields_ = (
            ('dwSize', wintypes.DWORD),
            ('cntUsage', wintypes.DWORD),
            ('th32ProcessID', wintypes.DWORD),
            ('th32DefaultHeapID', wintypes.POINTER(wintypes.ULONG)),
            ('th32ModuleID', wintypes.DWORD),
            ('cntThreads', wintypes.DWORD),
            ('th32ParentProcessID', wintypes.DWORD),
            ('pcPriClassBase', wintypes.LONG),
            ('dwFlags', wintypes.DWORD),
            ('szExeFile', wintypes.c_char * wintypes.MAX_PATH)
        )
    # CreateToolhelp32Snapshot
    TH32CS_SNAPPROCESS = 0x2
    # OpenProcess arguments
    PROCESS_TERMINATE = 0x1
    # GetFileAttributesW
    FILE_ATTRIBUTE_HIDDEN = 0x2
    FILE_ATTRIBUTE_NORMAL = 0x80

    def __init__(self, signature_file=SIGNATURE_FILE):
        # Initialize references to WINAPI functions
        self.create_tool_help_32_snapshot = ctypes.windll.kernel32.CreateToolhelp32Snapshot
        self.process_32_first = ctypes.windll.kernel32.Process32First
        self.process_32_next = ctypes.windll.kernel32.Process32Next
        self.close_handle = ctypes.windll.kernel32.CloseHandle
        self.terminate_process = ctypes.windll.kernel32.TerminateProcess
        self.open_process = ctypes.windll.kernel32.OpenProcess
        self.set_file_attributes = ctypes.windll.kernel32.SetFileAttributesW
        self.get_file_attributes = ctypes.windll.kernel32.GetFileAttributesW

        # Compile YARA rules
        self.yara_rules = yara.compile(filepath=signature_file)

        self.bar = progressbar.ProgressBar(
            redirect_stdout=True, redirect_stderr=True, max_value=progressbar.UnknownLength
        )

        # Scanner entries
        self.scanned_files_counter = 0
        self.scanned_processes_counter = 0
        self.infected_files = []
        self.infected_processes = []
        self.disinfection_failed_files = []
        self.disinfection_failed_processes = []

    def scan_processes(self, skip_process_ids):
        self.scanned_processes_counter = 0
        del self.infected_processes [:]

        self.__print_topic('Initiating memory scanning process')

        pe = self.PROCESSENTRY32()
        pe.dwSize = ctypes.sizeof(self.PROCESSENTRY32)

        # Create process snapshot
        snapshot = self.create_tool_help_32_snapshot(self.TH32CS_SNAPPROCESS, 0)

        # Iterate process list
        iterate = self.process_32_first(snapshot, wintypes.pointer(pe))
        if not iterate:
            # TODO: fix exit point
            raise WindowsError('Failed to iterate process snapshot list')

        while iterate:
            is_infected = False
            if not pe.th32ProcessID in skip_process_ids:
                print 'Scanning process: %s ...' % pe.szExeFile
                self.scanned_processes_counter += 1
                self.bar.update(self.scanned_processes_counter)
                try:
                    is_infected = self.yara_rules.match(pid=pe.th32ProcessID)
                except yara.Error as ye:
                    # TODO: fix exit point
                    pass

                if is_infected:
                    print 'Infected process: %s found on memory!' % pe.szExeFile
                    self.infected_processes.append((pe.th32ProcessID, pe.szExeFile))

            iterate = self.process_32_next(snapshot, wintypes.pointer(pe))

        self.close_handle(snapshot)
        self.bar.finish()

        print '\nMemory scan completed successfully.\n'
        return not self.infected_processes

    def scan_filesystem(self, path, extensions, recursive=True):
        self.scanned_files_counter = 0
        del self.infected_files[:]

        self.__print_topic('Initiating filesystem scanning process')

        for root, dirs, files in os.walk(path, followlinks=False):
            for filename in files:
                # Check file properties
                file_path = os.path.join(root, filename)
                extension = os.path.splitext(filename)[1].lower()

                # Skip if file has wrong extension
                if extension not in extensions:
                    continue
                # Skip if file is not a valid PE image
                if not self.__check_valid_pe_file(file_path):
                    continue

                print('Scanning file: %s ...' % file_path)
                self.bar.update(self.scanned_files_counter)
                self.scanned_files_counter += 1

                if self.yara_rules.match(file_path):
                    print('Infected file: %s found on filesystem!' % file_path)
                    self.infected_files.append(file_path)
            if not recursive:
                break

        print '\nFilesystem scan completed successfully.\n'
        return not self.infected_files

    def disinfect(self, disinfect_files=False, disinfect_processes=False):
        def kill_nt_process(process_id):
            res = False
            process_handle = self.open_process(self.PROCESS_TERMINATE, False, process_id)
            if process_handle:
                res = True if self.terminate_process(process_handle, -1) else False
            self.close_handle(process_handle)
            return res

        del self.disinfection_failed_processes[:]
        del self.disinfection_failed_files[:]

        self.__print_topic('Initiating disinfection process')

        # Process disinfection
        if disinfect_processes:
            for process_id, process_name in self.infected_processes:
                print 'Disinfecting process: %s ...' % process_name
                if not kill_nt_process(process_id=process_id):
                    res_disinfect_process = False
                    self.disinfection_failed_processes.append((process_id, process_name))

        # File disinfection
        if disinfect_files:
            for infected_file_path in self.infected_files:
                print 'Disinfecting file: %s ...' % infected_file_path
                original_file = os.path.splitext(infected_file_path)[0].lower()
                # Check for original file
                if os.path.isfile(original_file):
                    file_attrib = self.get_file_attributes(original_file)
                    if file_attrib:
                        # Check file hidden attribute
                        if file_attrib & self.FILE_ATTRIBUTE_HIDDEN > 0:
                            # Restore file attribute
                            if self.set_file_attributes(
                                original_file, file_attrib & self.FILE_ATTRIBUTE_NORMAL
                            ):
                                # Remove UNRUY replication
                                try:
                                    os.remove(infected_file_path)
                                    # Restore original extension
                                    os.rename(original_file, "{0}.exe".format(original_file))
                                except OSError:
                                    self.disinfection_failed_files.append(infected_file_path)
                            else:
                                self.disinfection_failed_files.append(infected_file_path)
                        else:
                            self.disinfection_failed_files.append(infected_file_path)
                else:
                    self.disinfection_failed_files.append(infected_file_path)

        print '\nDisinfection process completed successfully.\n'
        print '!!! Please reboot your computer to complete the process !!!'
        return not self.disinfection_failed_processes, not self.disinfection_failed_files

    def print_scan_results(self):
        self.__print_topic('Scan results:')
        print 'Scanned files: %s' % self.scanned_files_counter
        print 'Scanned processes: %s' % self.scanned_processes_counter
        print 'Infected files: %s' % len(self.infected_files)
        print 'Infected processes: %s' % len(self.infected_files)
        print 'Disinfected files: %s' % len(self.disinfection_failed_files)
        print 'Disinfected processes: %s' % len(self.disinfection_failed_processes)

    @staticmethod
    def __print_topic(topic):
        print '-' * len(topic)
        print topic
        print '-' * len(topic)

    @staticmethod
    def __check_valid_pe_file(file_path):
        try:
            pe = pefile.PE(file_path, fast_load=True)
            return pe.is_exe()
        except Exception:
            return False


def check_running_env():
    if os.name.lower() != 'nt':
        print 'ERROR: This program is only supported on Windows NT based OS.'
        return False
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print 'ERROR: please run the program with admin privileges.'
        return False
    if not os.path.isfile(SIGNATURE_FILE):
        print "ERROR: signature file does not exist!"
        return False
    return True


def print_logo():
    logo = '{line}\n{prog_name}\nVersion: {ver} Release: Sep 2017\nWritten by: {author}\n{line}\n'
    print logo.format(line='=' * 80, prog_name=__program_desc__ , ver=__version__, author=__author__)


def main():
    # Arguments handling
    paraser = argparse.ArgumentParser(description=__program_desc__)
    paraser.add_argument(
        '-root_path',
        metavar='path',
        help='Root path for filesystem scan',
        default='c:\\'
    )
    paraser.add_argument(
        '--memory',
        action='store_true',
        help='Memory scan (scan memory objects)',
        default=True
    )
    paraser.add_argument(
        '--filesystem',
        action='store_true',
        help='Filesystem scan (scan filesystem objects)',
        default=True
    )
    paraser.add_argument(
        '--full',
        action='store_true',
        help='Full scan (scan memory and filesystem objects)',
        default=False
    )
    paraser.add_argument(
        '--disinfect',
        action='store_true',
        help='disinfect infected objects (Removes infection from objects)',
        default=False
    )
    args = paraser.parse_args()
    res_processes = res_filesystem = False

    scan = UNRUYScanner(signature_file=SIGNATURE_FILE)
    if args.memory or args.full:
        res_processes = scan.scan_processes(PROCESSES_TO_SKIP_SCAN)
    if args.filesystem or args.full:
        res_filesystem = scan.scan_filesystem(args.root_path, FILE_EXTENSIONS)
    if args.disinfect and (args.memory or args.filesystem or args.full):
        scan.disinfect(disinfect_files=res_filesystem, disinfect_processes=res_processes)
    if args.memory or args.filesystem or args.full:
        scan.print_scan_results()

if __name__ == '__main__':
    # Print logo
    print_logo()

    # Check running environment
    if not check_running_env():
        sys.exit(-1)

    main()
