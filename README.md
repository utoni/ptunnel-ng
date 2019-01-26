[![Build Status](https://travis-ci.org/lnslbrty/ptunnel-ng.svg?branch=master)](https://travis-ci.org/lnslbrty/ptunnel-ng)
[![Coverity Status](https://scan.coverity.com/projects/14737/badge.svg?flat=1)](https://scan.coverity.com/projects/14737)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/021aa1d88dd7486db83df3ff96f9eff8)](https://www.codacy.com/app/lnslbrty/ptunnel-ng?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=lnslbrty/ptunnel-ng&amp;utm_campaign=Badge_Grade)
[![GitHub issues](https://img.shields.io/github/issues/lnslbrty/ptunnel-ng.svg)](https://github.com/lnslbrty/ptunnel-ng/issues)
[![GitHub license](https://img.shields.io/github/license/lnslbrty/ptunnel-ng.svg)](https://github.com/lnslbrty/ptunnel-ng/blob/master/COPYING)
[![Gitter chat](https://badges.gitter.im/ptunnel-ng/Lobby.png)](https://gitter.im/ptunnel-ng/Lobby)

# PingTunnel-[N]ew[G]eneration Read Me

## What is ptunnel-ng?
```
Ptunnel-NG is a bugfixed and refactored version of Ptunnel with some additional
features e.g. change the magic value without recompiling (bypass Cisco IPS).
```

## What is ptunnel?
```
Ptunnel is an application that allows you to reliably tunnel TCP connections
to a remote host using ICMP echo request and reply packets, commonly known as
ping requests and replies.
```

## How does it work?
```
ICMP Packet structure
```
![Ptunnel Packet Structure](https://github.com/lnslbrty/ptunnel-ng/raw/master/web/packet-format.png)
```
Ptunnel program setup
```
![Ptunnel Setup](https://github.com/lnslbrty/ptunnel-ng/raw/master/web/setup.png)

## Contact details
```
The ptunnel-ng fork was done by Toni Uhlig:
   <matzeton@googlemail.com>
You can contact the author of ptunnel, Daniel Stoedle, here:
   <daniels@cs.uit.no>
The official ptunnel website is located here:
   <http://www.cs.uit.no/~daniels/PingTunnel/>
```

## Dependencies
```
Required: pthread
Optional: pcap, selinux
```

## Compiling
```
Either run "./autogen.sh" for a fully automatic build or run it manually with:
    "./configure && make"

You should end up with a binary called ptunnel-ng.
This serves as both the client and proxy. You can
optionally install it using "make install".
To compile the Windows binary. You will need mingw installed.
If you want pcap support you will need the WinPcap library as well.
WinPcap is available here:
  <http://www.winpcap.org/install/bin/WpdPack_4_0_2.zip>

REMEMBER: ptunnel-ng might not work on Windows without WinPcap!
```

## Running
```
Ptunnel works best when starting as root, and usually requires starting as root.
Common ptunnel-ng options:

Proxy(Server):
	./ptunnel-ng -r<destination address> -R<destination port> -v <loglevel>
	             -P<password> -u<user> -g<group>

Forwarder(Client):
	./ptunnel-ng -p <address> -l <listen port> -r<destination address>
	             -R<destination port> -v <loglevel>
	             -P<password> -u<user> -g<group>

The -p switch sets the address of the host on which the proxy is running. A
quick test to see if the proxy will work is simply to try pinging this host -
if you get replies, you should be able to make the tunnel work.
If pinging works but you are not able to establish a tunnel, you should play
around with the -m switch and change the magic value. A IDS/IPS or Firwall
might try to fool you.

The -l, -r and -R switches set the local listening port, destination address
and destination port. For instance, to tunnel ssh connections from the client
machine via a proxy running on proxy.pingtunnel.com to the computer
login.domain.com, the following command line would be used:

sudo ./ptunnel-ng -p proxy.pingtunnel.com -l 8000 -r login.domain.com -R 22

An ssh connection to login.domain.com can now be established as follows:

ssh -p 8000 localhost

If ssh complains about potential man-in-the-middle attacks, simply remove the
offending key from the known_hosts file. The warning/error is expected if you
have previously ssh'd to your local computer (i.e., ssh localhost), or you have
used ptunnel-ng to forward ssh connections to different hosts.

Of course, for all of this to work, you need to start the proxy on your
proxy-computer (we'll call it proxy.pingtunnel.com here). Doing this is very
simple:

sudo ./ptunnel-ng

If you find that the proxy isn't working, you will need to enable packet
capturing on the main network device. Currently this device is assumed to be
an ethernet-device (i.e., ethernet or wireless). Packet capturing is enabled by
giving the -L switch, and supplying the device name to capture packets on (for
instance eth0 or en1). The same goes for the client. On versions of Mac OS X
prior to 10.4 (Tiger), packet capturing must always be enabled (both for proxy
and client), as resent packets won't be received otherwise.

To protect yourself from others using your proxy, you can protect access to it
with a password using the -P switch. The password is never sent in
the clear, but keep in mind that it may be visible from tools like top or ps,
which can display the command line used to start an application.

Finally, the -u switch will attempt to run the proxy in unprivileged mode (i.e.,
no need for root access), and the -v switch controls the amount of output from
ptunnel-ng. -1 indicates no output, 0 shows errors only, 1 shows info messages, 2
gives more output, 3 provides even more output, level 4 displays debug info and
level 5 displays absolutely everything, including the nasty details of sends and
receives. The -o switch allows output to be saved to a logfile.

Security features: Please see the ptunnel-ng man-page for instructions.
```

## Supported operating systems
```
Ptunnel supports most operating systems with libpcap, the usual POSIX functions
and a BSD sockets compatible API. In particular, it has been tested on Linux
Fedora Core 2 and Mac OS X 10.3.6 and above. As of version 0.7, ptunnel-ng can also
be compiled on Windows, courtesy of Mike Miller, assuming mingw and WinPcap is
installed.
```

## Credits and contributors
```
Daniel Stoedle et al.
```

## License
```
Ping Tunnel NG is Copyright (c) 2017-2019, Toni Uhlig <matzeton@googlemail.com>,
All rights reserved. Ping Tunnel NG is licensed under the
BSD License. Please see the COPYING file for details.
```
