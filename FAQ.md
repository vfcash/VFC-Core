
# Frequently Asked Questions (FAQ)
**Q: How do I run a node on Linux?**
- git clone https://github.com/vfcash/VFC-Core && cd VFC-Core
- chmod 0777 compile.sh
- sudo ./compile.sh
- vfc cdn_resync
- Install(s) to /usr/bin/vfc
- Ensure you have the UDP Port 8787 forwarded.
- Run "vfc mine" and earn some VFC to register your node on the network.
- Make sure you run compile.sh as root, for example: sudo ./compile.sh
- If you are behind a router, make sure you have UDP port 8787 forwarded to the correct local IP address on your network.
- If you are in China, you will find that you may have your internet connection dropped periodically due to the use of UDP.
- Please ensure you have an IPv4 address.

**Q: I am a Linux user and I don’t want to run a node. Can I still mine offline?**
- You do not need to run a local node to mine and claim VFC rewards to your rewards address. However, it is highly suggested you run a node so that you are not limited by the restrictions on the REST API.
- If you are mining offline with Linux, you can claim your mined VFC rewards by entering "vfc claim" into the console, or to see your unclaimed addresses use "vfc unclaimed".
- To launch the miner enter "vfc mine" into the console.

**Q: I am a Windows or Mac user. Can I still mine VFC?**
- Yes, you can! Please use the Portable nativeMiner here and the Portable nativeWallet here.
- You can compile the Linux node to run on Windows 10. Please refer to https://docs.microsoft.com/en-us/windows/wsl/install-win10 in order to set up the Ubuntu console, otherwise, you will need to run a VM such as https://www.virtualbox.org/wiki/Downloads. 

**Q: I see that I have unclaimed rewards. How do I claim them?**
- You can claim your mined VFC rewards by entering "vfc claim" into the console, or to see your unclaimed addresses use "vfc unclaimed".
- Your data directory is located at ~/.vfc/. You can change this by setting the Environment Variable VFCDIR to a custom directory path.
- Your reward address private key is located in ~/.vfc/private.key. This is all you need to perform a backup.
- Your minted private keys are located in ~/.vfc/minted.priv

**Q: I am still confused. Is there a Help command?**
- Once you are up and running, you just need to enter the command "vfc help" into the console.


# REST API
**Request Payment / Invoice:**
- https://vfcash.uk/transfer/?to=<public-key>&vfc=250

**Get Address Balance:**
- https://vfcash.uk/rest.php?balance=<public-key>
     
**Get all Transactions from an address:**
- https://vfcash.uk/rest.php?all=<public-key>
     
**Get all Sent Transactions from an address:**
- https://vfcash.uk/rest.php?sent_transactions=<public-key>
     
**Get all Received Transactions from an address:**
- https://vfcash.uk/rest.php?received_transactions=<public-key>
     
**Get Circulating Supply:**
- https://vfcash.uk/rest.php?circulating
     
**Get Mining Difficulty:**
- https://vfcash.uk/rest.php?difficulty
     
**Generate a Fresh Keypair:**
- https://vfcash.uk/rest.php?newkeypair
- https://vfcash.uk/rest.php?newpriv
- https://vfcash.uk/rest.php?mnemonic=<random-seed>
     
**Get Total number of Transactions on chain:**
- https://vfcash.uk/rest.php?high
- https://vfcash.uk/rest.php?highb
- https://vfcash.uk/rest.php?highkb
- https://vfcash.uk/rest.php?highmb
    
**Get a Transaction by UID:**
- https://vfcash.uk/rest.php?findtrans=<transaction-uid>
- https://vfcash.uk/rest.php?findtransjson=<transaction-uid>
- https://vfcash.uk/explore/?uid=<transaction-uid>
    
**Make a Transaction:**
- https://vfcash.uk/rest.php?frompriv=<private-key>&topub=<public-key>&amount=0.001

**Make a Secure Transaction Packet:**
- https://vfcash.uk/rest.php?stp=<base58-bytecode>
- https://vfcash.uk/rest.php?stp64=<base64-bytecode>
- These functions can be used by decentralised wallets to send a securely signed transaction to the VFC network.
     
**Get Public Key from the Private Key:**
- https://vfcash.uk/rest.php?getpubkey=<private-key>
     
**JSON Parser:**
- http://json.parser.online.fr/

