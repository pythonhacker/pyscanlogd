# -- coding: utf-8
#!/usr/bin/env python
"""
pyscanlogger: Port scan detector/logger tool, inspired
by scanlogd {http://www.openwall.com/scanlogd} but with
added ability to log slow port-scans.

Features

1. Detects all stealth (half-open) and full-connect scans.
2. Detects Idle scan and logs it correctly using correlation!
3. Detects SCTP scan.
4. Detects slow port-scans also.

Modification History

Mar 17 2010  - Cleaned up code to publish to google.
Apr 8 2010   - Better detection of TCP full-connect scan without
               spurious and incorrect logging. Better logging
               functions.

Licensed under GNU GPL v3.0.

"""

import sys, os
import dpkt, pcap
import struct
import socket
import time
import threading
import optparse

import entry
import timerlist

__author__ = "pythonhacker"
__maintainer__ = "pythonhacker"
__version__ = '0.5.1'
__modified__ = 'Thu Apr  8 19:21:11 IST 2010'

# UDP - in progress...

SCAN_TIMEOUT = 5
WEIGHT_THRESHOLD = 25
PIDFILE="/var/run/pyscanlogger.pid"

# TCP flag constants
TH_URG=dpkt.tcp.TH_URG
TH_ACK=dpkt.tcp.TH_ACK
TH_PSH=dpkt.tcp.TH_PUSH
TH_RST=dpkt.tcp.TH_RST
TH_SYN=dpkt.tcp.TH_SYN
TH_FIN=dpkt.tcp.TH_FIN

# Protocols
TCP=dpkt.tcp.TCP
UDP=dpkt.udp.UDP
SCTP=dpkt.sctp.SCTP

get_timestamp = lambda : time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
ip2quad = lambda x: socket.inet_ntoa(struct.pack('I', x))
scan_ip2quad = lambda scan: map(ip2quad, [scan.src, scan.dst])

    
class ScanLogger(object):
    """ Port scan detector/logger """
    
    # TCP flags to scan type mapping
    scan_types = {0: 'TCP null',
                  TH_FIN: 'TCP fin',
                  TH_SYN: 'TCP syn', TH_SYN|TH_RST: 'TCP syn',
                  TH_ACK: 'TCP ack',
                  TH_URG|TH_PSH|TH_FIN: 'TCP x-mas',
                  TH_URG|TH_PSH|TH_FIN|TH_ACK: 'TCP x-mas',
                  TH_SYN|TH_FIN: 'TCP syn/fin',
                  TH_FIN|TH_ACK: 'TCP fin/ack',
                  TH_SYN|TH_ACK: 'TCP full-connect',
                  TH_URG|TH_PSH|TH_ACK|TH_RST|TH_SYN|TH_FIN: 'TCP all-flags',
                  TH_SYN|TH_ACK|TH_RST: 'TCP full-connect',                                    
                  # Not a scan
                  TH_RST|TH_ACK: 'reply'} 
                  
    def __init__(self, timeout, threshold, maxsize, daemon=True, logfile='/var/log/scanlog'):
        self.scans = entry.EntryLog(maxsize)
        self.long_scans = entry.EntryLog(maxsize)
        # Port scan weight threshold
        self.threshold = threshold
        # Timeout for scan entries
        self.timeout = timeout
        # Long-period scan timeouts
        self.timeout_l = 3600
        # Long-period scan threshold
        self.threshold_l = self.threshold/2
        # Daemonize ?
        self.daemon = daemon
        # Log file
        try:
            self.scanlog = open(logfile,'a')
            print >> sys.stderr, 'Scan logs will be saved to %s' % logfile
        except (IOError, OSError), (errno, strerror):
            print >> sys.stderr, "Error opening scan log file %s => %s" % (logfile, strerror)
            self.scanlog = None
            
        # Recent scans - this list allows to keep scan information
        # upto last 'n' seconds, so as to not call duplicate scans
        # in the same time-period. 'n' is 60 sec by default.

        # Since entries time out in 60 seconds, max size is equal
        # to maximum such entries possible in 60 sec - assuming
        # a scan occurs at most every 5 seconds, this would be 12.
        self.recent_scans = timerlist.TimerList(12, 60.0)
        
    def hash_func(self, addr):
        """ Hash a host address """
        
        value = addr
        h = 0
    
        while value:
            # print value
            h ^= value
            value = value >> 9
        
        return h & (8192-1)

    def mix(self, a, b, c):

          a -= b; a -= c; a ^= (c>>13)
          b -= c; b -= a; b ^= (a<<8) 
          c -= a; c -= b; c ^= (b>>13)
          a -= b; a -= c; a ^= (c>>12)
          b -= c; b -= a; b ^= (a<<16)
          c -= a; c -= b; c ^= (b>>5) 
          a -= b; a -= c; a ^= (c>>3)
          b -= c; b -= a; b ^= (a<<10)
          c -= a; c -= b; c ^= (b>>15)

          return abs(c)
  
    def host_hash(self, src, dst):
        """ Hash mix two host addresses """

        return self.hash_func(self.mix(src, dst, 0xffffff))

    def log(self, msg):
        """ Log a message to console and/or log file """

        line = '[%s]: %s' % (get_timestamp(), msg)
        if self.scanlog:
            self.scanlog.write(line + '\n')
            self.scanlog.flush()
            
        if not self.daemon:
            print >> sys.stderr, line
        
    def log_scan(self, scan, continuation=False, slow_scan=False, unsure=False):
        """ Log the scan to file and/or console """

        srcip, dstip = scan_ip2quad(scan)
        ports = ','.join([str(port) for port in scan.ports])
        
        if not continuation:
            tup = [scan.type,scan.flags_or,srcip,dstip, ports]
            
            if not slow_scan:
                if scan.type != 'Idle':
                    line = '%s scan (flags:%d) from %s to %s (ports:%s)'
                else:
                    tup.append(ip2quad(scan.zombie))
                    line = '%s scan (flags: %d) from %s to %s (ports: %s) using zombie host %s'                    
            else:
                tup.append(scan.time_avg)                    
                if unsure:
                    line = 'Possible slow %s scan (flags:%d) from %s to %s (ports:%s), average timediff %.2fs'
                else:
                    line = 'Slow %s scan (flags:%d) from %s to %s (ports:%s), average timediff %.2fs'                    
        else:
            tup = [scan.type, srcip,dstip, ports]
            if not slow_scan:
                if scan.type != 'Idle':
                    line = 'Continuation of %s scan from %s to %s (ports:%s)'
                else:
                    tup.append(ip2quad(scan.zombie))
                    line = 'Continuation of %s scan from %s to %s (ports: %s) using zombie host %s' 
            else:
                tup.append(scan.time_avg)
                line = 'Continuation of slow %s scan from %s to %s (ports:%s), average timediff %.2fs'                
            

        msg = line % tuple(tup)
        self.log(msg)

    def update_ports(self, scan, dport, flags):

        scan.flags_or |= flags

        if dport in scan.ports:
            return
        
        # Add weight for port
        if dport < 1024:
            scan.weight += 3
        else:
            scan.weight += 1

        scan.ports.append(dport)

    def inspect_scan(self, scan, slow_scan=False):

        # Sure scan
        is_scan = ((slow_scan and scan.weight >= self.threshold_l) or (not slow_scan and scan.weight >= self.threshold))
        # Possible scan
        maybe_scan = (slow_scan and len(scan.ports)>=3 and len(scan.timediffs)>=4 and (scan.weight < self.threshold_l))
        not_scan = False
        
        if is_scan or maybe_scan:
            scan.logged = True

            if scan.proto==TCP:
                idle_scan = False
                if scan.flags_or==TH_RST:
                    # None does scan using RST, however this could be
                    # return packets from a zombie host to the scanning
                    # host when a scanning host is doing an idle scan.
                    # Basically
                    # A -scanning host
                    # B - zombie host
                    # C - target host

                    # If A does an idle scan on C with B as zombie,
                    # it will appear to C as if B is syn scanning it
                    # and later we could get an apparent RST "scan"
                    # from B to A 
                    # Correlation: If 'RST scan' detected from X to Y
                    # See if there was a SYN scan recently from host
                    # X to host Z. Then actually Y is idle scanning
                    # Z
                    dummy_scans, idle_ports = [], []

                    for item in reversed(self.recent_scans):
                        rscan = item[1]
                        if rscan.src==scan.src and rscan.flags_or==TH_SYN and ((rscan.timestamp - scan.timestamp)<30):
                            idle_scan = True
                            idle_ports.append(rscan.ports)
                            dummy_scans.append(item)
                            
                    if idle_scan:
                        scan.src = scan.dst
                        scan.dst = rscan.dst
                        scan.zombie = rscan.src
                        scan.type = 'Idle'
                        scan.ports = idle_ports
                        # for d in dummy_scans:
                        #    self.recent_scans.remove(d)
                    else:
                        # Remove entry
                        if slow_scan:
                            del self.long_scans[scan.hash]
                        else:
                            del self.scans[scan.hash]
                        
                        return False
                else:
                    scan.type = self.scan_types.get(scan.flags_or,'unknown')
                    if scan.type in ('', 'reply'):
                        not_scan = True

                    # If we see scan flags 22 from A->B, make sure that
                    # there was no recent full-connect scan from B->A, if
                    # so this is spurious and should be ignored.
                    if scan.flags_or == (TH_SYN|TH_ACK|TH_RST) and len(self.recent_scans):
                        recent1 = self.recent_scans[-1:-2:-1]
                        for recent in recent1:
                            # Was not a scan, skip
                            if not recent.is_scan: continue
                            if recent.type == 'TCP full-connect' and ((scan.src == recent.dst) and (scan.dst == recent.src)):
                                # Spurious
                                self.log("Ignoring spurious TCP full-connect scan from %s" % ' to '.join(scan_ip2quad(scan)))
                                not_scan = True
                                break

                    # If this is a syn scan, see if there was a recent idle scan
                    # with this as zombie, then ignore it...
                    elif scan.flags_or == TH_SYN and len(self.recent_scans):
                        # Try last 1 scans
                        recent1 = self.recent_scans[-1:-2:-1]
                        for recent in recent1:
                            if recent.type=='Idle' and scan.src==recent.zombie:
                                self.log('Ignoring mis-interpreted syn scan from zombie host %s' % ' to '.join(scan_ip2quad(scan)))
                                break
                            # Reply from B->A for full-connect scan from A->B
                            elif (recent.type == 'reply' and ((scan.src == recent.dst) and (scan.dst == recent.src))):
                                scan.type = 'TCP full-connect'
                                break
                            
            elif scan.proto==UDP:
                scan.type = 'UDP'
                # Reset flags for UDP scan
                scan.flags_or = 0
            elif scan.proto==SCTP:
                if scan.chunk_type==1:
                    scan.type = 'SCTP Init'
                elif scan.chunk_type==10:
                    scan.type = 'SCTP COOKIE_ECHO'                    
                
            # See if this was logged recently
            scanentry = entry.RecentScanEntry(scan, not not_scan)

            if scanentry not in self.recent_scans:
                continuation=False
                self.recent_scans.append(scanentry)
            else:
                continuation=True

            if not not_scan:
                self.log_scan(scan, continuation=continuation, slow_scan=slow_scan, unsure=maybe_scan)
                
            # Remove entry
            if slow_scan:
                del self.long_scans[scan.hash]
            else:
                del self.scans[scan.hash]

            return True
        else:
            return False
        
    def process(self, pkt):

        if not hasattr(pkt, 'ip'):
            return

        ip = pkt.ip
        # Ignore non-tcp, non-udp packets
        if type(ip.data) not in (TCP, UDP, SCTP):
            return

        pload = ip.data
        src,dst,dport,flags = int(struct.unpack('I',ip.src)[0]),int(struct.unpack('I', ip.dst)[0]),int(pload.dport),0
        proto = type(pload)
        
        if proto == TCP: flags = pload.flags
            
        key = self.host_hash(src,dst)

        curr=time.time()

        # Keep dropping old entries
        self.recent_scans.collect()
        
        if key in self.scans:
            scan = self.scans[key]

            if scan.src != src:
               # Skip packets in reverse direction or invalid protocol
               return

            timediff = curr - scan.timestamp
            # Update only if not too old, else skip and remove entry
            if (timediff > self.timeout):
                # Add entry in long_scans if timediff not larger
                # than longscan timeout
                prev = self.scans[key].timestamp

                if timediff<=self.timeout_l:
                    if key not in self.long_scans:
                        lscan = entry.ScanEntry(key)
                        lscan.src = src
                        lscan.dst = dst
                        lscan.timestamp = curr
                        lscan.timediffs.append(curr - prev)
                        lscan.flags_or |= flags
                        lscan.ports.append(dport)
                        lscan.proto = proto
                        self.long_scans[key] = lscan
                    else:
                        lscan = self.long_scans[key]
                        lscan.timestamp = curr
                        lscan.flags_or |= flags
                        lscan.timediffs.append(curr - prev)
                        lscan.update_time_sd()
                        self.update_ports(lscan, dport, flags)
                        
                        if lscan.time_sd<2:
                            # SD is less than 2, possible slow scan
                            # update port weights...
                            # print 'Weight=>',lscan.weight
                            if not self.inspect_scan(lscan, True):
                                # Not a scan, check # of entries - if too many
                                # then this is a regular network activity
                                # but not a scan, so remove entry
                                if len(lscan.timediffs)>=10:
                                    # print lscan.src, lscan.timediffs, lscan.time_sd 
                                    print 'Removing',key,lscan.src,'since not a scan'
                                    del self.long_scans[key]
                                    
                        elif len(lscan.timediffs)>2:
                            # More than 2 entries, but SD is too large,
                            # delete the entry
                            # print 'Removing',key,lscan.src,'since SD is',lscan.time_sd
                            del self.long_scans[key]
                else:
                    # Too large timeout, remove key
                    del self.long_scans[key]
                    
                del self.scans[key]
                return 

            if scan.logged: return
                
            scan.timestamp = curr
            self.update_ports(scan, dport, flags)
            self.inspect_scan(scan)
            
        else:
            # Add new entry
            scan = entry.ScanEntry(key)
            scan.src = src
            scan.dst = dst
            scan.timestamp = curr
            scan.flags_or |= flags
            if proto==SCTP:
                scan.chunk_type = pload.chunks[0].type
            scan.ports.append(dport)
            scan.proto = proto
            self.scans[key] = scan
            
    def loop(self):
        
        pc = pcap.pcap()
        decode = { pcap.DLT_LOOP:dpkt.loopback.Loopback,
                   pcap.DLT_NULL:dpkt.loopback.Loopback,
                   pcap.DLT_EN10MB:dpkt.ethernet.Ethernet } [pc.datalink()]

        try:
            print 'listening on %s: %s' % (pc.name, pc.filter)
            for ts, pkt in pc:
                self.process(decode(pkt))
        except KeyboardInterrupt:
            if not self.daemon:
                nrecv, ndrop, nifdrop = pc.stats()
                print '\n%d packets received by filter' % nrecv
                print '%d packets dropped by kernel' % ndrop

    def run_daemon(self):
        # Disconnect from tty
        try:
            pid = os.fork()
            if pid>0:
                sys.exit(0)
        except OSError, e:
            print >>sys.stderr, "fork #1 failed", e
            sys.exit(1)

        os.setsid()
        os.umask(0)

        # Second fork
        try:
            pid = os.fork()
            if pid>0:
                open(PIDFILE,'w').write(str(pid))
                sys.exit(0)
        except OSError, e:
            print >>sys.stderr, "fork #2 failed", e
            sys.exit(1)
            
        self.loop()
        
    def run(self):
        # If dameon, then create a new thread and wait for it
        if self.daemon:
            print 'Daemonizing...'
            self.run_daemon()
        else:
            # Run in foreground
            self.loop()

def main():
    
    if os.geteuid() != 0:
        sys.exit("You must be super-user to run this program")
        
    o=optparse.OptionParser()
    o.add_option("-d", "--daemonize", dest="daemon", help="Daemonize",
                 action="store_true", default=False)
    o.add_option("-f", "--logfile", dest="logfile", help="File to save logs to",
                 default="/var/log/scanlog")
    
    options, args = o.parse_args()
    s=ScanLogger(SCAN_TIMEOUT, WEIGHT_THRESHOLD, 8192, options.daemon, options.logfile)
    s.run()
    
if __name__ == '__main__':
    main()
