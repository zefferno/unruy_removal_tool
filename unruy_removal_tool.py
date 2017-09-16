# coding=utf-8

import argparse
import ctypes
import ctypes.wintypes as wintypes
import yara
import os
import pefile
import sys

__version__ = '1.0'


class UNRUYScannerLogger:
    def __init__(self):
        pass

    def log(self, msg, type='INFO'):
        print msg

    @staticmethod
    def print_banner(self):
        print '-' * 80
        print 'UNRUY Malware Removal Tool v%s' % __version__
        print 'Written by Mor Kalfon (zefferno@gmail.com)'
        print '-' * 80


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

    # CreateToolhelp32Snapshot arguments
    TH32CS_SNAPPROCESS = 0x2

    # OpenProcess arguments
    PROCESS_TERMINATE = 0x1

    # GetFileAttributesW arguments
    FILE_ATTRIBUTE_HIDDEN = 0x2
    FILE_ATTRIBUTE_NORMAL = 0x80

    # Windows API functions
    create_tool_help_32_snapshot = None
    process_32_first = None
    process_32_next = None
    close_handle = None
    terminate_process = None
    open_process = None

    # YARA rules
    rules = None

    # logging
    logger = UNRUYScannerLogger()

    def __init__(self, signature_file):
        # Initialize references to API functions
        self.create_tool_help_32_snapshot = ctypes.windll.kernel32.CreateToolhelp32Snapshot
        self.process_32_first = ctypes.windll.kernel32.Process32First
        self.process_32_next = ctypes.windll.kernel32.Process32Next
        self.close_handle = ctypes.windll.kernel32.CloseHandle
        self.terminate_process = ctypes.windll.kernel32.TerminateProcess
        self.open_process = ctypes.windll.kernel32.OpenProcess
        self.set_file_attributes = ctypes.windll.kernel32.SetFileAttributesW
        self.get_file_attributes = ctypes.windll.kernel32.GetFileAttributesW

        # Compile YARA rules
        self.rules = yara.compile(filepath=signature_file)

    def scan_processes(self, skip_process_ids, kill_infected_process=True):
        disinfect_failures = []
        snapshot = self.create_tool_help_32_snapshot(self.TH32CS_SNAPPROCESS, 0)
        pe = self.PROCESSENTRY32()
        pe.dwSize = ctypes.sizeof(self.PROCESSENTRY32)

        try:
            iterate = self.process_32_first(snapshot, wintypes.pointer(pe))
            if not iterate:
                raise WindowsError('Failed to iterate process snapshot list')

            while iterate:
                if not pe.th32ProcessID in skip_process_ids:
                    self.logger.log(msg='[+] Scanning process: %s ...' % pe.szExeFile)
                    if self.rules.match(pid=pe.th32ProcessID):
                        self.logger.log('[!] Infected process: %s found !' % pe.szExeFile)
                        if kill_infected_process:
                            self.logger.log('[+] Killing infected process: %s' % pe.szExeFile)
                            disinfect_failures.append(pe.th32ProcessID)

                iterate = self.process_32_next(snapshot, wintypes.pointer(pe))
        finally:
            self.close_handle(snapshot)

        self.logger.log('[+] Memory scan completed.')
        return disinfect_failures

    def scan_filesystem(self, path, file_extensions, recursive=True, disinfect=True):
        disinfect_failures = []

        for root, dirs, files in os.walk(path, followlinks=False):
            for filename in files:
                # Check file properties
                file_path = os.path.join(root, filename)
                file_extension = os.path.splitext(filename)[1].lower()

                # Skip if file has the right extension
                if file_extension not in file_extensions:
                    continue

                # Skip if file is not a valid PE
                if not self.__check_valid_file(file_path):
                    continue

                self.logger.log('[+] Scanning file: %s ...' % file_path)

                if self.rules.match(file_path):
                    self.logger.log('[!] file: %s is infected with UNRUY!' % file_path)
                    if disinfect:
                        self.logger.log('[+] Disinfecting file: %s' % file_path)
                        if not self.disinfect(infected_file_path=file_path):
                            disinfect_failures.append(file_path)

        self.logger.log('[+] Filesystem scan completed.')
        return disinfect_failures

    def disinfect(self, infected_file_path=None, process_id=None):
        res_kill_process = True
        res_remove_file = True

        if process_id and not self.__kill_process(process_id=process_id):
                res_kill_process = False

        if infected_file_path:
            original_file_path = os.path.splitext(infected_file_path)[0].lower()
            if os.path.isfile(original_file_path):
                file_attrib = self.get_file_attributes(original_file_path)
                if not file_attrib:
                    res_remove_file = False
                else:
                    if file_attrib & self.FILE_ATTRIBUTE_HIDDEN > 0:
                        if not self.set_file_attributes(original_file_path, file_attrib & self.FILE_ATTRIBUTE_NORMAL):
                            res_remove_file = False
                        else:
                            try:
                                os.remove(infected_file_path)
                            except Exception:
                                res_remove_file = False
            else:
                res_remove_file = False

        return res_remove_file and res_kill_process

    def __check_valid_file(self, file_path):
        try:
            pe = pefile.PE(file_path, fast_load=True)
            return pe.is_exe()
        except Exception:
            return False

    def __kill_process(self, process_id):
        res = False
        process_handle = self.open_process(self.PROCESS_TERMINATE, False, process_id)
        if process_handle:
            res = True if self.terminate_process(process_handle, -1) else False
        self.close_handle(process_handle)
        return res


if __name__ == '__main__':
    if os.name.lower() != 'Windows':
        print("This program is only supported on Windows NT based OS.")
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("Please run the program with admin privileges.")
        sys.exit(-1)
    # Arguments handling
    paraser = argparse.ArgumentParser(description='UNRUY malware removal tool')
    paraser.add_argument(
        '--memory',
        action='store_true',
        help='Memory scan (scan memory objects)',
        default=False
    )
    paraser.add_argument(
        '--filesystem',
        action='store_true',
        help='Filesystem scan (scan filesystem objects)',
        default=False
    )
    paraser.add_argument(
        '--full',
        action='store_true',
        help='Full scan (scan memory and filesystem objects)',
        default=False
    )
    paraser.add_argument(
        '--remove',
        action='store_true',
        help='Remove infected objects (Removes infection from objects)',
        default=True
    )
    args = paraser.parse_args()

    signature_file = os.path.join(os.path.dirname(__file__), 'signatures/unruy.yar')
    unruy_scanner = UNRUYScanner(signature_file=signature_file)

    unruy_scanner.scan_processes(skip_process_ids=[0, 4])
    unruy_scanner.scan_filesystem("C:\\", [".exe", ""])
