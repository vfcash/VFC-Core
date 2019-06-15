# VF Cash

VF Cash is a Cryptocurrency project that started on the 23rd of April 2019. It has no Proof-of-Work (POW) rather it has a transaction rate limit per address / public key of one second. This prevents the sender or the receiver of a transaction from making any further transactions during this period. The chain is unordered, and the networking uses UDP. The Digital Signature algorithm uses secp256r1.

This is a non-divisible coin, pre-mined, written in C, compiled with GCC, 256-bit key length, Transactions are 72.3% smaller than an average Bitcoin-Core transaction, relating to total blockchain size.

The only incentive to run a Full Node is if you wish to implement a payment gateway in your website or service, if you are running an exchange, or maybe you are just a die-hard supporter of VF Cash. There can be re-occuring reward payouts to node operators, delegated from the pre-mine.

Transactions are truly free, there is no charge for making a transaction on the network.

This is a private decentralised network, as-in you will need control of some currency before the rest of the network considers your dedicated node viable for indexing.

Join us on Telegram [@vfcash](https://t.me/vfcash)

# Installation & Running a Full Node

**Linux Compile & Install Instructions (Full Node & Client Wallet):**
```
git clone https://github.com/vfcash/VFC-Core && cd VFC-Core
sudo chmod 0777 compile.sh
./compile.sh
```
Then use the `coin help` command in the console for a full command list.

If you are running a full node then consider also installing NGINX + PHP-FPM and extracting the `server-www.zip` files into the `/var/www/html` directory; https://github.com/vfcash/RELEASES/raw/master/server-www.zip

Doing so will allow other users in the network a method of finding and donating rewards to you. It comes with a basic web-wallet that can be expanded upon and will allow users to make transactions via your node.

If you wish the full node to launch on startup of the server, `edit /etc/rc.local` and add the command `coin` at the end of the file. Alternatively you can SSH in and launch an instance of coin in a screen or tmux, or if running a crontab add `@restart coin`.


**Windows Install Instructions (Full Node & Client Wallet):**

For a Windows installation you can follow the steps above but first install the Ubuntu Terminal software on Windows first: https://www.microsoft.com/en-us/p/ubuntu/9nblggh4msv6

**To become an active part of the network leave the coin program running in a screen and make sure any necessary ports are forwarded, VFC uses UDP Port 8173.** You will need to make atleast one valid transaction on the network before the mainnet indexes you as a peer and will commuicate with your node. We recommend that you send 1 VFC to yourself, to and from the same address. If you are sent VFC your balance will still show 0 until you perform this operation from your network node.

Each address is limited to one transaction every one second, once a transaction is made both the sender and receievers addresses are limited for a total of one second. 

# Third-Party Dependencies

**CRYPTO:**
- https://github.com/brainhub/SHA3IUF   [SHA3]
- https://github.com/esxgx/easy-ecc     [ECDSA]

**Additional Dependencies:**
- CRC64.c - Salvatore Sanfilippo
- Base58.c - Luke Dashjr
