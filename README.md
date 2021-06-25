# http-xst.nse

SUMMARY
-------
This script was modification by referring https://seclists.org/nmap-dev/2010/q3/60 to test the Cross Site Tracing vulnerability. Nmap have two scripts that test the TRACE method "http-methods and http-trace", but not test the XST vulnerability. The http-methods only test with OPTIONS request, but if OPTION request is disabled and TRACE request enable, this script don't detect  the TRACE method. The second script "http-trace" "Sends an HTTP TRACE request and shows header fields that were modified in the response" but not test the XST vulnerability.


INSTALLATION
------------

$ git clone https://github.com/ahzhen988/http-xst.nse.git
$ cd http-xst.nse/
$ sudo cp http-xst.nse /usr/share/nmap/scripts/
$ nmap --script-updatedb

USAGE
-----

nmap -p80 --script http-xst 192.168.1.2
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-28 17:53 +08
Nmap scan report for 192.168.1.2 (192.168.1.2)
Host is up (0.59s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-xst: This Server it's vulnerable to Cross Site Tracing.
| Request:
| TRACE / HTTP/1.0\x0D
| Via: <script>alert('XSS')</script>\x0D
| \x0D
| 
| Response:
| HTTP/1.1 200 OK\x0D
| Date: Fri, 28 May 2021 09:54:02 GMT\x0D
| Server: Apache/2.2.15 (Oracle)\x0D
| Connection: close\x0D
| Content-Type: message/http\x0D
| \x0D
| TRACE / HTTP/1.0\x0D
| Via: <script>alert('XSS')</script>\x0D
| \x0D
|_

Nmap done: 1 IP addresses (1 hosts up) scanned in 6.98 seconds
