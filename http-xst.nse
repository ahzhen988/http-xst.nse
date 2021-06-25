description = [[Sends an HTTP TRACE request for test Cross Site Tracing vulnerability.]]

---
-- @usage
-- nmap -p80 --script http-xst 192.168.1.2
--
-- @output
-- 80/tcp   open  http
-- | http-xst: This Server it's vulnerable to Cross Site-Tracing.
-- | Request:
-- | TRACE / HTTP/1.0
-- | Via: <script>alert('XSS')</script>
-- |
-- | Response:
-- | HTTP/1.1 200 OK
-- | Date: Fri, 28 May 2021 09:54:02 GMT\
-- | Server: Apache/2.2.15 (Oracle)
-- | Connection: close
-- | Content-Type: message/http
-- |
-- | TRACE / HTTP/1.0
-- | Via: <script>alert('XSS')</script>
-- |_

-- The reference of original source: https://seclists.org/nmap-dev/2010/q3/60

-- 25/06/2021

author = "zn9988"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html";

categories = {"default", "intrusive"}

local comm = require('comm')	
local shortport = require('shortport')
local stdnse = require('stdnse')

portrule = shortport.port_or_service({80, 8080, 443, 8443}, {"http", "https", "http-alt", "https-alt"})

action = function(host, port)
        local start, stop, body
        local request = "TRACE / HTTP/1.0\r\nVia: <script>alert('XSS')</script>\r\n\r\n"

        local sd, response = comm.tryssl(host, port, request, false)
        if not sd then 
                stdnse.print_debug("Unable to open connection") 
                return
        end

        if not response:match("HTTP/1.[01] 200") or
           not response:match("TRACE / HTTP/1.0") then
                return
        end

        start, stop = response:find("\r\n\r\n")
        body = response:sub(stop + 1)

        if request == body then
                local output =  "This Server it's vulnerable to Cross Site Tracing.\n"
                output = output .. "Request:\n"
                output = output .. request .. "\n"
                output = output .. "Response:\n"
                return output .. response .. "\n"

        end
end
