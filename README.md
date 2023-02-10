# Artifact Evaluation Submission

### Artifact Abstract
Our paper includes one artifact for review which will all be available for open-access on our Github page (https://github.com/breakerspace/turkmenistan-censorship). This artifact consists of instructions and scripts to emulate how we triggerred DNS, HTTP, and HTTPS censorship for our measurement system, and how we evaded censorship across the same three protocols using both transport and application layer strategies discovered by Geneva.

In order to correctly trigger and evade censorship as done within our study, you must have a machine outside of Turkmenistan and drop all outbound RSTs from your machine. To do so, you can run the `drop_outbound_rsts.sh` shell script we have provided. Please make all shell scripts executable before evaluating this artifact.

### Disclaimer
The artifact that we have provided are designed to trick and confuse the firewall and censoring system of Turkmenistan. Even though this artifact may be evaluated from a machine outside of Turkmenistan, Turkmenistan is known to be adversarial and may block IP addresses from probing machines. Please understand the risks of evaluating this artifact before doing so.

## Triggering DNS, HTTP, and HTTPS Censorship
The following sections encompass the techniques we used to trigger DNS, HTTP and HTTPS censorship from outside of Turkmenistan for measurement purposes. 

### DNS
To trigger DNS censorship within Turkmenistan, we can simply use the following command:
```
$ dig @95.85.117.12 twitter.com
```
We receive the following response from the censor:
```
; <<>> DiG 9.11.3-1ubuntu1.17-Ubuntu <<>> @95.85.117.12 twitter.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 53440
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;twitter.com.			IN	A

;; ANSWER SECTION:
twitter.com.		300	IN	A	127.0.0.1

;; Query time: 272 msec
;; SERVER: 95.85.117.12#53(95.85.117.12)
;; WHEN: Thu Feb 09 06:41:14 UTC 2023
;; MSG SIZE  rcvd: 45
```
We can further confirm that the response is from the censor by running a `tcpdump` while simultaneously running the `dig` command:
```
$ sudo tcpdump -i any -nv host 95.85.117.12
tcpdump: listening on any, link-type LINUX_SLL (Linux cooked), capture size 262144 bytes
06:48:23.949310 IP (tos 0x0, ttl 64, id 27767, offset 0, flags [none], proto UDP (17), length 80)
    172.31.40.121.38202 > 95.85.117.12.53: 13698+ [1au] A? twitter.com. (52)
06:48:24.201835 IP (tos 0x0, ttl 102, id 30000, offset 0, flags [none], proto UDP (17), length 73)
    95.85.117.12.53 > 172.31.40.121.38202: 13698 1/0/0 twitter.com. A 127.0.0.1 (45)
```
The censor is known to have a fingerprint with an IPID of 30000 and an initial IP TTL of 128. At the time of writing this submission, the censor is 26 hops away from the machine, which aligns with an initial TTL value of 128. As such, we can confirm that any DNS request to `twitter.com` is censored as the censor responds with a dummy IP address of `127.0.0.1`.

### HTTP
To trigger HTTP censorship via an incomplete handshake, as we did in our measurement study, we can use the `http_censorship.py` script. This script takes in an IP address that experiences HTTP censorship in Turkmenistan, a censored domain, a source port for the outgoing packets, and a destination port for the IP address. The destination port need not be a port designated for HTTP traffic as Turkmenistan censors HTTP traffic on all ports. The script takes these arguments and crafts a PSH+ACK packet containing an HTTP GET request to twitter.com. The script then sends the PSH+ACK packet to the specified IP address, waits 5 seconds, and then sends the same PSH+ACK packet again. The script can be run as follows:
```
$ sudo python3 http_censorship.py --ip 95.85.117.12 --censored-domain twitter.com --sport 8763 --dport 5656
```
If we run tcpdump in parallel while running this command, we can see the following output:
```
$ sudo tcpdump -i any -nv host 95.85.117.12 
tcpdump: listening on any, link-type LINUX_SLL (Linux cooked), capture size 262144 bytes
07:30:16.618994 IP (tos 0x0, ttl 64, id 1, offset 0, flags [none], proto TCP (6), length 77)
    172.31.40.121.8763 > 95.85.117.12.5656: Flags [P.], cksum 0x3d51 (correct), seq 101:138, ack 0, win 8192, length 37
E..M....@.....(y_Uu.";.....e....P. .=Q..GET / HTTP/1.1
Host: twitter.com

07:30:21.667925 IP (tos 0x0, ttl 64, id 1, offset 0, flags [none], proto TCP (6), length 77)
    172.31.40.121.8763 > 95.85.117.12.5656: Flags [P.], cksum 0x3d51 (correct), seq 0:37, ack 1, win 8192, length 37
E..M....@.....(y_Uu.";.....e....P. .=Q..GET / HTTP/1.1
Host: twitter.com

07:30:21.940259 IP (tos 0x0, ttl 102, id 30000, offset 0, flags [none], proto TCP (6), length 40)
    95.85.117.12.5656 > 172.31.40.121.8763: Flags [R], cksum 0xce93 (correct), seq 0, win 0, length 0
E..(u0..f.6._Uu...(y..";........P.......
```
We can observe that by sending the PSH+ACK packet, waiting for 5 seconds, and then sending the same PSH+ACK packet again, the censor responds with a RST packet. Again, we can confirm that this is the censor's response because the initial IP TTL is 128 (since the machine is 26 hops away from the censor) and the IPID is 30000.

Please note that we mustn't wait for exactly 5 seconds. We can wait anywhere between 5 to 29 seconds between packets to trigger the censor's response.

### HTTPS
To trigger HTTPS censorship via an incomplete handshake, as we did in our measurement study, we can use the `https_censorship.py` script. This script takes in an IP address that experiences HTTPS censorship in Turkmenistan, a censored domain, a source port to be used for outgoing packets, and a destionation port for the IP address. Just like for HTTP, the destination port need not be a port designated for HTTPS traffic, as Turkmenistan censors HTTPS traffic on all ports. The script uses these arguments to construct a PSH+ACK packet with a Client Hello payload. The Client Hello payload has its SNI field set to the censored domain. The script sends the PSH+ACK packet, waits 5 seconds, and then sends the same PSH+ACK packet again. The script can be run as follows:
```
$ sudo python3 https_censorship.py --ip 95.85.117.12 --censored-domain twitter.com --sport 9377 --dport 8383
```
Again, if we run tcpdump in parallel while running this command, we can see the following output:
```
$ sudo tcpdump -i any -nvA host 95.85.117.12 
tcpdump: listening on any, link-type LINUX_SLL (Linux cooked), capture size 262144 bytes
09:52:03.278686 IP (tos 0x0, ttl 64, id 1, offset 0, flags [none], proto TCP (6), length 353)
    172.31.40.121.9377 > 95.85.117.12.8383: Flags [P.], cksum 0xe51c (correct), seq 101:414, ack 0, win 8192, length 313
E..a....@.....(y_Uu.$. ....e....P. .........4...0..
.....	.h.ep.CX.......a&.k.=..1. ....6q..!f..;........E.	..'...S|.>.......,.0.........+./...$.(.k.#.'.g.
...9.	...3.....=.<.5./...............twitter.com.........
...
...........#.............0.............	.
.................................+.	..........-.....3.&.$... ...J....eA.9....f.....#r...J4|9e
09:52:08.331729 IP (tos 0x0, ttl 64, id 1, offset 0, flags [none], proto TCP (6), length 353)
    172.31.40.121.9377 > 95.85.117.12.8383: Flags [P.], cksum 0xe51c (correct), seq 0:313, ack 1, win 8192, length 313
E..a....@.....(y_Uu.$. ....e....P. .........4...0..
.....	.h.ep.CX.......a&.k.=..1. ....6q..!f..;........E.	..'...S|.>.......,.0.........+./...$.(.k.#.'.g.
...9.	...3.....=.<.5./...............twitter.com.........
...
...........#.............0.............	.
.................................+.	..........-.....3.&.$... ...J....eA.9....f.....#r...J4|9e
09:52:08.597145 IP (tos 0x0, ttl 102, id 30000, offset 0, flags [none], proto TCP (6), length 40)
    95.85.117.12.8383 > 172.31.40.121.9377: Flags [R], cksum 0xc186 (correct), seq 0, win 0, length 0
E..(u0..f.6._Uu...(y .$.........P.......
```
Just as before, we observe that the RST has the same fingerprint as the censor, and can confirm that we have triggerred censorship. In addition, just like with HTTP, we don't have to wait for exactly 5 seconds between packets. We can wait anywhere between 5 to 29 seconds.

## Evading DNS, HTTP, and HTTPS Censorship
The following section details how to evade censorship in Turkmenistan across DNS, HTTP, and HTTPS protocols both at the transport layer and application layer.

### Transport Layer
The transport layer evasion strategies used in our paper consist of the following three strategies: `[TCP:flags:PA]-fragment{tcp:8:True}-| \/`, `[TCP:flags:S]-duplicate(,duplicate(tamper{TCP:flags:replace:R}(tamper{TCP:chksum:corrupt},),))-| \/`, and `[TCP:flags:S]-duplicate(tamper{TCP:flags:replace:R},)-| \/`. These strategies are implemented in bash scripts that we describe how to use below. 

Please note that for HTTPS, our bash script fragments the PSH+ACK packet at a byte index of 4 instead of 8, as described in our paper. In addition, since the submission of our paper, we have discovered that the TCB Teardown via RST strategy, `[TCP:flags:S]-duplicate(,duplicate(tamper{TCP:flags:replace:R}(tamper{TCP:chksum:corrupt},),))-| \/` is no longer successful for HTTPS requests.
#### **HTTP**
To use the transport layer strategies outlined in our paper to evade HTTP censorship, we can run the bash script, `transport_http_evasion_strategies.sh`, with the IP address of the HTTP server we would like to talk to, the censored domain, the source port, and the destination port/port of the HTTP server. This destination port must be a port designated for HTTP traffic. This script clones the geneva repository from Github and runs Geneva's engine in the background. The bash script then iterates through the strategies and executes a curl command for each strategy. The engine picks up the packets from the curl command, manipulates them based on the current strategy, and then sends them off to the HTTP server. We can run the script as follows:
```
$ sudo ./transport_http_evasion_strategies.sh 95.85.96.78 twitter.com 6722 80
```
In addition, we need to run `tcpdump` simultaneously as well:
```
$ sudo tcpdump -i any -nvA host 95.85.96.78
```
We can confirm censorship on this IP addrss with a simple curl command, such as `curl -H "Host: twitter.com:95.85.96.78:80`, and observe that the censor sends a RST after the PSH+ACK packet. However, when Geneva runs the evasion strategies for HTTP, we will not see any RSTs with the censor's signature in our `tcpdump` and the request will go through to the server.
#### **HTTPS**
To use the transport layer strategies to evade HTTPS censorship, we can run the bash script, `transport_https_evasion_strategies.sh`, with the IP address of the HTTPS server we would like to talk to, the censored domain, the source port, and the destination port/port of the HTTPS server. This destination port must be a port designated for HTTPS traffic so this value should almost always be 443. This script clones the geneva repository from Github and runs Geneva's engine in the background. The bash script then iterates through the strategies and executes a curl command for each strategy. The engine picks up these packets, manipulates them based on the current strategy, and then sends them off to the HTTPS server.
```
$ sudo ./transport_https_evasion_strategies.sh 95.85.96.78 twitter.com 7878 443
```
In addition, we need to run `tcpdump` simultaneously as well:
```
$ sudo tcpdump -i any -nvA host 95.85.96.78
```
We observe that we do not receive the RST from the censor when we send a PSH+ACK with the Client Hello containing `twitter.com` in the SNI field. We can compare this to sending a simple curl command, `curl --local-port 7878 --connect-to ::95.85.96.78:443 https://twitter.com/` and confirm that we do see censorship when we do not deploy the evasion strategy.

### Application Layer
Geneva discovered the application-layer evasion strategies using an application-layer specific plugin. This plugin has not been released to the public as of the writing of this submission, and therefore we are not able to write bash scripts to automate the process of running Geneva to evade censorship. However, we implemented these application-layer evasion strategies manually by manipulating the packets containing the censored request. These scripts are detailed below.

#### **DNS**
In order to evade DNS censorship, we can run the `application_dns_evasion_strategy.py` script. This script takes in an IP address to a DNS server (i.e. it must have port 53 open) and a censored domain. The script simply crafts a DNS packet using the provided arguments, sets the `ancount` field to 32, and then sends the packet to the DNS server. This strategy is noted in our paper as `[DNS:*:*]-tamper{DNS:ancount:replace:32}-| \/`. The script can be used as follows:
```
$ sudo python3 application_dns_evasion_strategy.py --ip 95.85.97.78 --censored-domain twitter.com
```
We need to run `tcpdump` simultaneously as well:
```
$ sudo tcpdump -i any -nvA host 95.85.97.78
tcpdump: listening on any, link-type LINUX_SLL (Linux cooked), capture size 262144 bytes
18:12:54.738689 IP (tos 0x0, ttl 64, id 1, offset 0, flags [none], proto UDP (17), length 57)
    172.31.40.121.53 > 95.85.97.78.53: 0+ [32a] A? twitter.com. (29)
18:12:55.012336 IP (tos 0x0, ttl 36, id 23390, offset 0, flags [none], proto UDP (17), length 40)
    95.85.97.78.53 > 172.31.40.121.53: 0 Refused- [0q] 0/0/0 (12)
18:12:55.012412 IP (tos 0xc0, ttl 64, id 25466, offset 0, flags [none], proto ICMP (1), length 68)
    172.31.40.121 > 95.85.97.78: ICMP 172.31.40.121 udp port 53 unreachable, length 48
	IP (tos 0x0, ttl 36, id 23390, offset 0, flags [none], proto UDP (17), length 40)
    95.85.97.78.53 > 172.31.40.121.53: 0 Refused- [0q] 0/0/0 (12)
```
We can confirm that we do not receive a dummy IP address fo `127.0.0.1` from the censor.
#### **HTTP**
In order to evade HTTP censorship at the application level, we can run the `application_http_evasion_strategies.py` script. This script takes in an IP address of the HTTP server we would like to talk to, the censored domain, the destination port/port of the HTTP server, and a number that corresponds to which application-layer HTTP strategy to run. Please note that the destination port must be a port designated for HTTP traffic. The script completes a three way handshake with the server and then sends a PSH+ACK packet with an HTTP GET request to the censored domain. We can run the script as follows:
```
$ sudo python3 application_http_evasion_strategies.py --ip 95.85.96.78 --censored-domain twitter.com --sport 7878 --dport 80 --strategy 1
```
Please note that we need to provide a number to the `--strategy` argument. The following table maps this number to the corresponding strategies:
| Number    | Strategy      |
| --------- | ------------- |
|1     | `[HTTP:host:*]-insert{%09%0A:start:value:1}-\| \/`|
|2     | `[HTTP:version:*]-insert{%20%0A%09:end:value:1}-\| \/`        |
|3     | `[HTTP:method:*]-insert{%0A:start:value:1}-\| \/`|
|4     | `[HTTP:host:*]-insert{%20:end:value:3391}(duplicate(duplicate(,replace{a:name:1}),insert{%09:start:name:1}),)-\| \/` or <br />`[HTTP:host:*]-insert{%20:end:value:3391}(duplicate(duplicate(insert{%09:start:name:1},),replace{a:name:1}),)-\|\/`|

We need to run `tcpdump` simultaneously as well:
```
$ sudo tcpdump -i any -nvA host 95.85.97.78
```
We can confirm that we do not receive any RSTs from the censor via our `tcpdump`.

**Note**: Throughout this submission, we use many different IP addresses in our examples. These IP address have consistently been censored. However, please note that IP addresses may churn and, since Turkmenistan is known to censor only specific IP addresses even in the same `/24`, these IP addresses may not be censored in the future.