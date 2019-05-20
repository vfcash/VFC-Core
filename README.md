# VF Cash

VF Cash is a Cryptocurrency project that started on the 23rd of April 2019. It has no Proof-of-Work (POW) rather it has a transaction rate limit per address / public key of 3 seconds. This prevents the sender or the receiver of a transaction from making any further transactions during this period. The chain is unordered (DAG), and the networking uses UDP. The Digital Signature algorithm uses secp384r1.

This is a non-divisible coin, pre-mined, written in C, compiled with GCC, 384-bit key length, Transactions are 60% smaller than an average Bitcoin-Core transaction, relating to total blockchain size.

The only incentive to run a Full Node is if you wish to implement a payment gateway in your website or service, if you are running an exchange, or maybe you are just a die-hard supporter of VF Cash.

Transactions are truly free, there is no charge for making a transaction on the network.

Why IOT? Well, the Full Node only takes up ~2.6MB of memory and requires no use of an FPU, even though most modern ARM architecture comes with a built-in dedicated Floating-Point Unit (FPU) the VF Cash full-node requires no floating-point arithmetic meaning it could technically run on older ARM hardware without any major drawbacks. At the moment VFC Cash only supports IPv4 which may come across as somewhat of an oxymoron however we may decide to upgrade VF Cash to IPv6 in the near future if it seems like a suitable decision to make, as of now, IPv4 is more than adequate of the network requirements of VF Cash.

What about Double Spending? So with double-spending, we restrict addresses on the network to only making one transaction per 3 seconds as mentioned above, however now even in the very rare possibility that someone tried to execute a double spend from two very distant nodes in the network there is a very rare possibility of a single address with 1 VFC sending two transactions at the same time of 1 VFC, in this instance one of the transactions (usually the first) will instantly propagate the network and dominate the other, now if any network nodes received the second transaction first what will happen is these nodes will cache the transaction until the address tops-up the balance required to process the other 1 VFC, and then, the transaction will propagate through the entire network. So attempted double-spending is not a great idea, the transaction will be cached and processed when you next have the available funds.

This is also a private decentralised network, as-in you will need control of some currency before the rest of the network considers your dedicated node viable for indexing.

Join us on Telegram https://t.me/vfcash

