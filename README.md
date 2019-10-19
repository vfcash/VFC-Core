# VF Cash
VF Cash has no proof of work (PoW) and blockchain file that grows at a rate 76% less than Bitcoin. [Whitepaper.pdf](https://github.com/vfcash/RELEASES/blob/master/vfcash.pdf)

The project started on the 23rd of April 2019. It has no Proof-of-Work (POW) rather it has a finders-keeps distribution system similar to mining and a transaction rate limit per address / public key of three seconds for the confirmation period. This prevents the sender of a transaction from making any further transactions during this period. The chain is unordered, and the networking uses UDP. The Digital Signature algorithm uses secp256r1.

Divisible to three decimal places, mineable, written in C, compiled with GCC, 256-bit key length.

Transactions are free, there is no charge for making a transaction on the network.

VFC is a private decentralised network, consequently you will need control of some currency before the rest of the network considers your node viable for indexing. The usual method is to mine some VFC using the `vfc mine` command. Also you can transfer VFC to your node's reward address `vfc reward` will identify your reward public key / address once your reward address has some VFC your node will automatically verify itself within the hour.

Join us on Telegram [@vfcash](https://t.me/vfcash)

# Installation & Running a Node

**Linux Compile & Install Instructions (Full Node & Client Wallet):**
```
git clone https://github.com/vfcash/VFC-Core && cd VFC-Core
chmod 0777 compile.sh
./compile.sh

vfc cdn_resync
```
Then use the `vfc help` command in the console for a full command list or `vfui` if you are running a desktop environment and prefer a graphical user interface.

```> vfui```

[![Watch the video](https://raw.githubusercontent.com/vfcash/RELEASES/master/vfui.png)](https://raw.githubusercontent.com/vfcash/RELEASES/master/vfui.mp4)

```> vfwallet```

![VF Wallet](https://github.com/vfcash/RELEASES/blob/master/vfwallet.jpg)

```
> vfc help

-----------------------------
vfc update                    - Updates node
vfc <address public key>      - Get address balance
vfc out <address public key>  - Gets sent transactions
vfc in <address public key>   - Gets received transactions
vfc all <address public key>  - Recv & Sent transactions
-----------------------------

Send a transaction:
vfc <sender public key> <reciever public key> <amount> <sender private key>

--------------------------------------
vfc new <optional seed>                 - Create a new Address / Key-Pair
vfc new <seed1> <seed2> <seed3> <seed4> - Four random seed(uint64), Key-Pair
--------------------------------------
vfc qsend <amount> <receiver address>   - Send transaction from rewards address
vfc claim <optional file path>          - Claims private keys to rewards addr
vfc reward                              - Your awarded or mined VFC
-------------------------------
vfc mine <optional num threads>  - CPU miner for VFC
vfc peers                        - List locally indexed peers
vfc getpub <private key>         - Get Public Key from Private Key
vfc issub <public key>           - Is supplied public address a subG address
-------------------------------
vfc votes                        - Map of difficulty votes
vfc difficulty                   - Network mining difficulty
-------------------------------
vfc sync <optional num peers>    - Trigger blockchain sync from your peers
vfc cdn_resync                   - Trigger blockchain resync from the master
vfc reset_chain                  - Reset blockchain back to genesis state
vfc scan                         - Scan for peers in the IPv4 range.
-------------------------------
vfc replaypeer <peer ip address> - Manually replay from specific peer
vfc addpeer <peer ip address>    - Manually add a peer
vfc printtrans 1000 1010         - Print transactions[start,end] on chain
vfc findtrans <transaction uid>  - Find a transaction by it's UID
-------------------------------
vfc dump                         - List all transactions on chain
vfc dumptop <num trans>          - List top x transactions on chain
vfc dumpbad                      - List all detected double spend attempts
vfc clearbad                     - Clear all detected double spend attempts
-------------------------------

Scan blocks.dat for invalid transactions and truncate at first detected:
vfc trunc <offset from eof>

[Fast] Scan blocks.dat for duplicate transactions and generates a cleaned output; cblocks.dat:
vfc clean

[Slow] Scan blocks.dat for invalid transactions and generates a cleaned output; cfblocks.dat:
vfc cleanfull

----------------
vfc version      - Node version
vfc agent        - Node user-agent
vfc config       - Node configuration
vfc heigh        - Returns node [ blocks.dat size / num transactions ]
vfc circulating  - Circulating supply
vfc minted       - Minted supply
vfc unclaimed    - Lists all unclaimed addresses from your minted.priv
vfc claim        - Claims the contents of minted.priv to your rewards address
----------------
vfc single       - Launches the VFC node as single threaded
vfc multi        - Launches the VFC node as multi threaded
----------------

To get started running a dedicated node, execute ./vfc on a seperate screen.
```

By default your data-dir is ~/.vfc if you would like to set a custom path please set the envionment variable VFCDIR, for example if running as root choose a directory such as /srv

**Windows Install Instructions (Full Node & Client Wallet):**

For a Windows installation you can follow the steps above via the Ubuntu Console, install the Ubuntu Terminal software for Windows: https://www.microsoft.com/en-us/p/ubuntu/9nblggh4msv6

**To become an active part of the network make sure UDP Port 8787 is forwarded.** You will need to make atleast one valid transaction on the network before the mainnet indexes you as a peer and will commuicate with your node. We recommend that you send 1 VFC to yourself, to and from the same address. If you are sent VFC your balance will still show 0 until you perform this operation from your network node. Alternatively you can mine VFC with `vfc mine` and your first successful mined VFC will register you on the network. 

Each address is limited to one transaction every three seconds, once a transaction is made the sender cannot make another transaction to a different address for three seconds.

# Mining Difficulty
All nodes re-calculate the difficulty once an hour at exactly 0 minutes UTC of the hour.

To increase the difficulty towards 0.031 pay VFC into:
- **q15voteVFC**f7Csb8dKwaYkcYVEWa2CxJVHm96SGEpvzK

To increase the difficulty towards 0.240 pay VFC into:
- **24KvoteVFC**7JsTiFaGna9F6RhtMWdB7MUa3wZoVNm7wH3

If the balance of **24KvoteVFC** is higher than **q15voteVFC** the difficulty will be 0.240, otherwise the difference between the balance of the two addresses will be used to reduce the difficulty from 0.240 to 0.031.

Use the command ```vfc difficulty``` for more information.

# Configuration File
- **multi-threaded 1**  - Uses more CPU Cores
- **multi-threaded 0**  - Uses only one CPU Core
- **replay-threads 32** - Replays blockchain data to a maximum of 32 peers simultaneously.
- **replay-delay 1000** - Uses less TX bandwidth
- **replay-delay 1**    - Uses more TX bandwidth
- **peer-trans-limit-per-min 180** - Limits the amount of transactions a peer can send per minute, by default this value is 180, it is not recommended to set this value lower than 60.

# Expose a gateway
VF Cash is a private decentralised network, this means that the only people who get access to the network are node operators. The only way a regular client can access the network is by using one of the running nodes as a gateway to access the network.

This is why it is important that you expose some kind of gatway for end-users, at minimum this would mean installing NGINX, PHP-FPM and exposing the [php rest api](https://github.com/vfcash/VFC-PHP-API/blob/master/rest.php) for public use by copying the rest.php file to `/var/www/html` the default configured nginx www/html path.

# Third-Party Dependencies

**CRYPTO:**
- https://github.com/brainhub/SHA3IUF   [SHA3]
- https://github.com/esxgx/easy-ecc     [ECDSA]

**Additional Dependencies:**
- CRC64.c - Salvatore Sanfilippo
- Base58.c - Luke Dashjr
