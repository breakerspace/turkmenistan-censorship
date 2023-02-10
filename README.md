# Artifact Evaluation Submission

### Artifact Abstract
Our paper includes two artifacts for review which will all be available for open-access on our Github page (https://github.com/breakerspace/turkmenistan-censorship). These two artifacts consists of instructions and scripts to emulate how we triggerred DNS, HTTP, and HTTPS censorship for our measurement system, and how we evaded censorship across the same three protocols using strategies discovered by Geneva.

In order to correctly trigger and evade censorship as done within our study, you must have a machine outside of Turkmenistan and drop all outbound RSTs from your machine. To do so you can run the `drop_outbound_rsts.sh` script we have provided. 

### Disclaimer
Both of the artifacts that we have provided are designed to trick and confuse the firewall and censoring system in Turkmenistan. Even though these artifacts may be evaluated from a machine outside of Turkmenistan, Turkmenistan is known to be adversarial and may block IP addresses from probing machines. Please understand the risks of evaluating these artifacts before doing so.

## Artifact 1: Triggering DNS, HTTP, and HTTPS Censorship
The following sections encompass the techniques we used to trigger DNS, HTTP and HTTPS censorship from outside of Turkmenistan for measurement purposes. 

### DNS
To trigger DNS censorship within Turkmenistan, we can simply use the following command:
```
$ dig @95.85.117.102 twitter.com
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
We can further confirm that the response is from the server by running a `tcpdump` while simultaneously running the `dig` command:
```
$ sudo tcpdump -i any -nv host 95.85.117.12
tcpdump: listening on any, link-type LINUX_SLL (Linux cooked), capture size 262144 bytes
06:48:23.949310 IP (tos 0x0, ttl 64, id 27767, offset 0, flags [none], proto UDP (17), length 80)
    172.31.40.121.38202 > 95.85.117.12.53: 13698+ [1au] A? twitter.com. (52)
06:48:24.201835 IP (tos 0x0, ttl 102, id 30000, offset 0, flags [none], proto UDP (17), length 73)
    95.85.117.12.53 > 172.31.40.121.38202: 13698 1/0/0 twitter.com. A 127.0.0.1 (45)
```
The censor is known to have a fingerprint with an IPID of 30000 and an initial IP TTL of 128. At the time of the writing of this artifact evaluation, the censor is 26 hops away from the machine, which aligns with an initial TTL value of 128. As such, we can confirm that any DNS request to `twitter.com` is censored as the censor responds with a dummy IP address of `127.0.0.1`.

### HTTP
To trigger HTTP censorship via an incomplete handshake, as we did in our measurement study, we can run `http_censorship.py` using the following command:
```
$ sudo python3 tm_http_censorship.py --ip 95.85.117.12 --censored-domain twitter.com --sport 8763 --dport 5656
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
We can observe that by sending the PSH+ACK, waiting for 5 seconds, and then sending the same PSH+ACK packet again, the censor responds with a RST packet. Again, we can confirm that this is the censor's response because the initial IP TTL is 128 (since the machine is 26 hops away from the censor) and the IPID is 30000.

We mustn't wait for exactly 5 seconds. We can wait anywhere between 5 to 29 seconds between packets to trigger the censor's response.

### HTTPS
To trigger HTTPS censorship via an incomplete handshake, as we did in our measurement study, we can run `https_censorship.py` using the following command:
```
$ sudo python3 tm_https_censorship.py --ip 95.85.117.12 --censored-domain twitter.com --sport 9377 --dport 8383
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
Just as before, we observe that the RST has the same fingerprint as the censor, and can confirm that we have triggerred censorship.

**Note**: For all three protocols, we use `95.85.117.12` as an example. This IP address has consistently been censored during the course of our study. Please note that IP addresses may churn and, since Turkmenistan is known to censor only specific IP addresses even in the same `/24`, this IP address may not be censored in the future.

## Artifact 2: Evading DNS, HTTP, and HTTPS Censorship

### Transport Layer

### Application Layer

Use geneva as the building block, 

