# VF Cash
VF Cash has no proof of work (PoW) and blockchain file that grows at a rate 76% less than Bitcoin. [Whitepaper.pdf](https://github.com/vfcash/RELEASES/blob/master/vfcash.pdf)

The project started on the 23rd of April 2019. It has no Proof-of-Work (POW) rather it has a finders-keeps distribution system similar to mining and a transaction rate limit per address / public key of three seconds for the confirmation period. This prevents the sender of a transaction from making any further transactions during this period. The chain is unordered, and the networking uses UDP. The Digital Signature algorithm uses secp256r1.

Divisible to three decimal places, mineable, written in C, compiled with GCC, 256-bit key length.

Transactions are free, there is no charge for making a transaction on the network.
However transactions can optionally create inflation of the currency which is partly paid back to the node operators as rewards.

VFC is a private decentralised network, as-in you will need control of some currency before the rest of the network considers your dedicated node viable for indexing. The usual method is to mine some. Also you can transfer VFC to your node's reward address `vfc reward` will identify your reward public key / address and as such your node will automatically verify itself within the hour.

Join us on Telegram [@vfcash](https://t.me/vfcash)

# Installation & Running a Node

**Linux Compile & Install Instructions (Full Node & Client Wallet):**
```
git clone https://github.com/vfcash/VFC-Core && cd VFC-Core
chmod 0777 compile.sh
./compile.sh

vfc master_resync
```
Then use the `vfc help` command in the console for a full command list or `vfui` if you are running a desktop environment and prefer a graphical user interface.

```> vfui```
[![Watch the video](https://raw.githubusercontent.com/vfcash/RELEASES/master/vfui.png)](https://raw.githubusercontent.com/vfcash/RELEASES/master/vfui.mp4)

By default your data-dir is ~/.vfc if you would like to set a custom path please set the envionment variable VFCDIR, for example if running as root choose a directory such as /srv

**Windows Install Instructions (Full Node & Client Wallet):**

For a Windows installation you can follow the steps above via the Ubuntu Console, install the Ubuntu Terminal software for Windows: https://www.microsoft.com/en-us/p/ubuntu/9nblggh4msv6

**To become an active part of the network make sure UDP Port 8787 is forwarded.** You will need to make atleast one valid transaction on the network before the mainnet indexes you as a peer and will commuicate with your node. We recommend that you send 1 VFC to yourself, to and from the same address. If you are sent VFC your balance will still show 0 until you perform this operation from your network node. Alternatively you can mine VFC with `vfc mine` and your first successful mined VFC will register you on the network. 

Each address is limited to one transaction every three seconds, once a transaction is made the sender cannot make another transaction to a different address for three seconds.

# Running a serious node?
All nodes by default will run in single threaded mode, and will use mmap if the target platform is x86_64.

If you intend to run a serious node on the network which uses a dedicated server it is recommend to create a `vfc.cnf` configuration file in `~/.vfc/` with the following settings
```
multi-threaded 1
mmap 1
replay-delay 1000
```
This will set your node to use all CPU cores available for transaction processing, it will also allow the blockchain file to be mapped to memory via the use of [mmap()](http://man7.org/linux/man-pages/man2/mmap.2.html) which will significantly increase transaction processing speed.

`replay-delay 1000` means that the delay between sending transactions when other peers request a replay will be 1,000 microseconds. Each transaction is 144 bytes on file or 147 bytes over the network and 143 bytes if it's a replay. With 1,000,000 microseconds in a second this means your node will send 1,000 replay transactions a second to each peer that requests a replay. That's a total of 1000 * 143 bytes a second or 143kb a second per requesting peer if you consider 1kb to be 1000 bytes rather than 1024 bytes.

Generally your node should stay in sync, if it falls behind it is recommended that you run `vfc sync` in the background. This command can take an argument of how many peers to replay from e.g. `vfc sync 256` will attempt to replay from 256 peers. You should set the number of peers relative to the power of your server, if your flood your server with too many replay packets it will be too encumbered to process the regular network transactions.

# Expose a gateway
VF Cash is a private decentralised network, this means that the only people who get access to the network are node operators. The only way a regular client can access the network is by using one of the running nodes as a gateway to access the network.

This is why it is important that you expose some kind of gatway for end-users, at minimum this would mean installing NGINX, PHP-FPM and exposing the [php rest api](https://github.com/vfcash/VFC-PHP-API/blob/master/rest.php) for public use by copying the rest.php file to `/var/www/html` the default configured nginx www/html path.

# No IPv4 address?
It is reccomend that users who do not have access to an IPv4 address to use a VPN service that offers port forwarding on IPv4 addresses, such as [AirVPN](https://airvpn.org/).

# Denial-of-service Protection
```diff
- Do not set this up by default unless you have bandwidth limits on your server that are being exceeded
```
We recommend configuring iptables to throttle incoming UDP packets on port 8787 to 7,133 every minute [~119 packets a second]. 

This should be adequate for the maximum throughput of the entire network allowing 'leeway'.

- **Block Replay:** 10 tps [max]
- **Valid Transactions:** 85 tps [max]
- **Remainder / Utility Requests:** 24 tps

Utility requests such as balance checks, pings, reward payments and user-agent requests have no defined limit like how the Block Replay is always limited to 10 tps and the valid processable transactions of each client is limited to 85 tps. Thus, when both of these services are at their max throughput remainder services will only get 24 tps when using the following iptables configuration;

```
iptables -I INPUT -p udp -i eth0 --dport 8787 -m state --state NEW -m recent --update --seconds 2 --hitcount 255 -j DROP
```

# Additional Software

- [Supervisord](http://supervisord.org/) - Supervisor is a client/server system that allows its users to monitor and control a number of processes on UNIX-like operating systems. A good tool that can relaunch important processes if they happen to crash.


# Third-Party Dependencies

**CRYPTO:**
- https://github.com/brainhub/SHA3IUF   [SHA3]
- https://github.com/esxgx/easy-ecc     [ECDSA]

**Additional Dependencies:**
- CRC64.c - Salvatore Sanfilippo
- Base58.c - Luke Dashjr
