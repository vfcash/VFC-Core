/*
    VF Cash has been created by James William Fletcher
    http://github.com/mrbid

    A Cryptocurrency for Linux written in C.
    https://vf.cash
    https://vfcash.uk

    Project start date: 23rd of April (2019)
    Project updated:    27th of June  (2019)

    CRYPTO:
    - https://github.com/brainhub/SHA3IUF   [SHA3]
    - https://github.com/esxgx/easy-ecc     [ECDSA]

    Additional Dependencies:
    - CRC64.c - Salvatore Sanfilippo
    - Base58.c - Luke Dashjr

    NOTES:
    Only Supports IPv4 addresses.
    Local storage in ~/vfc

    *** In it's current state we only track peer's who send a transaction to the server. ***
    *** Send a transaction to yourself, you wont see any address balance until verified ***

    To use the VFC wallet you need to be running a full node which requires that you
    forward UDP port 8173 on your router to the local machine running the VFC full
    node.

    There is a small transaction Queue and a processing thread to make sure normal
    UDP transmissions do not get particularly blocked up.

    Peers need to be aware of each other by referal, passing the origin ip of a
    transaction across the echo chamber makes this possible, but this also exposes
    the IP address of the clients operating specific transactions. This is fine if
    you are behind a VPN but otherwise, this is generally bad for accountability.
    This could give the an attacker insights that could lead to a successfully
    poisioned block replay. Although the risks are SLIM I would suggest mixing
    this IP list up aka the ip and ipo uint32 arrays when there is more than one
    index using some kind of a random mixing algo.

    Peers can only be part of the network by proving they control VFC currency in a
    given VFC address. This is done by making a transaction from the same IP as the
    node running the full time VFC daemon. Only then will the local VFC daemon
    recieve all transactions broadcast around the VFC p2p network.

    This client will try to broadcast all transactions through the master first
    and then the peer list.

    Transactions echo two relays deep into the peers, making sure most nodes are
    repeat notified about the transactions due to the echoing of a packet around in
    a two relay deep p2p peers broadcast, making a less reliable UDP protocol
    more reliable and ensuring all peers get the transaction.

    :: Note on block replays
    I had a bit of a problem where any node could bypass the transaction limiter by
    exploiting the use of block replays, or trick individual clients into thinking
    a transactions has taken place while the rest of the network remains oblivious.
    My solution to this problem is to only allow replays from one other IP that is
    not the master at any one time. Every time a replay takes place this IP will
    change to another random peer in the local peer list. Now this means only one
    node can ever bypass the limiter and that is the randomly selected node by the
    local client.

    It is possible that a malicious user could monitor traffic on the network, identifying
    the addresses used by your nodes IP address and then by chance if you ever request a
    block replay from 'the malicious user' they could poision your blockchain.
    Also, a user could make a program to archive the addresses used by each node IP until
    one of the peers requests a replay (eventually) and then one could directly poision the
    blockchain as a result. There are no obvious benefits from doing this, if they did do
    this it would be obvious, a bit annoying, and require an enire replay. For example they
    could pretend your balance had been depleted or increased to an obscene amount, but
    that's about it. In which case you'd just assume the obvious, that your blockchain
    replay was corrupt which it was (albeit maliciously) or incomplete, and you'd resync.
    (hopefully)

    TODO:
    - Scanning for peers could do with scanning more specific ranges that are more
      worth-while

    Distributed under the MIT software license, see the accompanying
    file COPYING or http://www.opensource.org/licenses/mit-license.php.

*/

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/types.h>
#include <pwd.h>
#include <sys/stat.h> //mkdir
#include <time.h> //time()
#include <unistd.h> //sleep
#include <sys/utsname.h> //uname
#include <locale.h> //setlocale
#include <signal.h> //SIGPIPE
#include <pthread.h> //Threading

#include "ecc.h"
#include "sha3.h"
#include "crc64.h"
#include "base58.h"

#include "reward.h"

#if MASTER_NODE == 1
    #include <maxminddb.h> //Maxmind
    MMDB_s mmdb;
#endif

///////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////
//////////////////////////////////////////////
/////////////////////////////
///////////////
////////

//Client Configuration
const char version[]="0.44";
const uint16_t gport = 8787;
const char master_ip[] = "68.183.49.225";

//Error Codes
#define ERROR_NOFUNDS -1
#define ERROR_SIGFAIL -2
#define ERROR_UIDEXIST -3

//Node Settings
#define MAX_TRANS_QUEUE 256             // Maximum transaction backlog to keep in real-time (the lower the better tbh, only benefits from a higher number during block replays)
#define MAX_THREADS 6                   // Maximum replay threads this node can spawn (about 3 syncs or 6 replays)
#define MAX_PEERS 3072                  // Maximum trackable peers at once (this is a high enough number)
#define MAX_PEER_EXPIRE_SECONDS 10800   // Seconds before a peer can be replaced by another peer. secs(3 days=259200, 3 hours=10800)
#define PING_INTERVAL 180               // How often top ping the peers to see if they are still alive

//Generic Buffer Sizes
#define RECV_BUFF_SIZE 256
#define MIN_LEN 256

//Chain Paths
#define CHAIN_FILE ".vfc/blocks.dat"
#define BADCHAIN_FILE ".vfc/bad_blocks.dat"

//Vairable Definitions
#define uint uint32_t
#define mval uint32_t
#define ulong unsigned long long int

//Operating Global Variables
ulong err = 0;
uint replay_allow = 0;
uint replay_height = 0;
mval balance_accumulator = 0;
uint threads = 0;
uint thread_ip[MAX_THREADS];
char mid[8];
time_t nextreward = 0;
uint rewardindex = 0;
uint rewardpaid = 1;
char myrewardkey[MIN_LEN];

///////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////
//////////////////////////////////////////////
/////////////////////////////
///////////////
////////
///
//
//
//
/* ~ Util Functions
*/

#if MASTER_NODE == 1
int getLocation(const char *ip_address, char* continent, char* country, char* cityn)
{
    int gai_error, mmdb_error;
    MMDB_lookup_result_s result = MMDB_lookup_string(&mmdb, ip_address, &gai_error, &mmdb_error);

    if(gai_error != 0)
        return -2;

    if(mmdb_error != MMDB_SUCCESS)
        return -3;

    int r = 0;
    MMDB_entry_data_s entry_data;
    MMDB_get_value(&result.entry, &entry_data, "country", "iso_code", NULL);
    if(entry_data.has_data && entry_data.data_size < MIN_LEN-1)
    {
        memcpy(country, entry_data.utf8_string, entry_data.data_size);
        r++;
    }

    MMDB_get_value(&result.entry, &entry_data, "city", "names", "en");
    if(entry_data.has_data && entry_data.data_size < MIN_LEN-1)
    {
        memcpy(cityn, entry_data.utf8_string, entry_data.data_size);
        r++;
    }

    MMDB_get_value(&result.entry, &entry_data, "continent", "code", NULL);
    if(entry_data.has_data && entry_data.data_size < MIN_LEN-1)
    {
        memcpy(continent, entry_data.utf8_string, entry_data.data_size);
        r++;
    }
    
    if(r == 0)
        return -1;
    else
        return 0;
}
#endif

char* getHome()
{
    char *ret;
    if((ret = getenv("HOME")) == NULL)
        ret = getpwuid(getuid())->pw_dir;
    return ret;
}

uint qRand(const uint min, const uint max)
{
    static time_t ls = 0;
    if(time(0) > ls)
    {
        srand(time(0));
        ls = time(0) + 33;
    }
    return ( ((float)rand() / RAND_MAX) * (max-min) ) + min; //(rand()%(max-min))+min;
}

void timestamp()
{
    time_t ltime = time(0);
    printf("\033[1m\x1B[31m%s\x1B[0m\033[0m", asctime(localtime(&ltime)));
}

uint isalonu(char c)
{
    if(c >= 48 && c <= 57 || c >= 65 && c <= 90 || c >= 97 && c <= 122)
        return 1;
    return 0;
}

double floor(double i)
{
    if(i < 0)
        return (int)i - 1;
    else
        return (int)i;
}

///////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////
//////////////////////////////////////////////
/////////////////////////////
///////////////
////////
///
//
//
//
/* ~ Structures

    sig - signature store
    addr - public/private addr store
    trans - transaction data structure

*/

struct addr
{
    uint8_t key[ECC_CURVE+1];
};
typedef struct addr addr;

struct sig
{
    uint8_t key[ECC_CURVE*2];
};
typedef struct sig sig;

struct trans
{
    uint64_t uid;
    addr from;
    addr to;
    mval amount;
    sig owner;
};

void makHash(uint8_t *hash, const struct trans* t)
{
    sha3_context c;
    sha3_Init256(&c);
    sha3_Update(&c, t, sizeof(struct trans));
    sha3_Finalize(&c);
    memcpy(hash, &c.sb, ECC_CURVE);
}

///////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////
//////////////////////////////////////////////
/////////////////////////////
///////////////
////////
///
//
//
//
/* ~ P2P Tracker

    isMasterNode() - Check if address is master node
    setMasterNode() - Reset's the peers list setting master node at index 0

    resyncBlocks() - Download most recent blockchain version from master
    verifyChain() - verify blockchain has the original genesis block.
    
    addPeer() - Add a peer address to the peers (if free space available)
    isPeer() - Check if peer already exists in list.
    
    peersBroadcast() - Broadcast a packet to the peers (skipping master)
    sendMaster() - Only send packet to master

*/

//General peer tracking
uint peers[MAX_PEERS]; //Peer IPv4 addresses
time_t peer_timeouts[MAX_PEERS]; //Peer timeout UNIX epoch stamps
uint num_peers = 0; //Current number of indexed peers
uint peer_tcount[MAX_PEERS]; //Amount of transactions relayed by peer
char peer_ua[MAX_PEERS][64]; //Peer user agent
mval peer_ba[MAX_PEERS]; //Balance Aggregation

mval trueBalance()
{
    mval v[num_peers];
    uint c[num_peers];
    uint vm = 0;
    for(uint i = 0; i < num_peers; i++)
        c[i] = 0;
    for(uint i = 0; i < num_peers; i++)
    {
        if(peer_ba[i] == 0)
            continue;
        uint t = 0;
        for(uint i2 = 0; i2 < vm; i2++)
        {
            if(v[i2] == peer_ba[i])
            {
                c[i2]++;
                t = 1;
                break;
            }
        }
        if(t == 0)
        {
            v[vm] = peer_ba[i];
            c[vm]++;
            vm++;
        }
    }

    uint hc = 0;
    mval hv = 0;
    for(uint i = 0; i < vm; i++)
    {
        if(c[i] > hc)
        {
            hc = c[i];
            hv = v[i];
        }
    }
    return hv;
}

uint countPeers()
{
    uint c = 0;
    for(uint i = 0; i < MAX_PEERS; i++)
    {
        if(peers[i] == 0)
            return c;
        c++;
    }
    return c;
}

uint countLivingPeers()
{
    uint c = 0;
    for(uint i = 0; i < num_peers; i++)
    {
        const uint pd = time(0)-(peer_timeouts[i]-MAX_PEER_EXPIRE_SECONDS);
        if(pd <= 540)
            c++;
    }
    return c;
}

uint csend(const uint ip, const char* send, const size_t len)
{
    struct sockaddr_in server;

    int s;
    if((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
        return 0;

    memset((char*)&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(gport);
    server.sin_addr.s_addr = ip;

    if(sendto(s, send, len, 0, (struct sockaddr*)&server, sizeof(server)) < 0)
    {
        err++;
        close(s);
        return 0;
    }
    
    close(s);
    return 1;
}

void scanPeers()
{
    printf("\x1B[33m\nIt seems the Masternode is offline? We will now scan the entire IPv4 range of ~4.3 billion checking for peers.\x1B[0m\n");

    time_t s = 0;
    for(uint i = 0; i < 4294967294; ++i)
    {
        if(time(0) > s)
        {
            setlocale(LC_NUMERIC, "");
            printf("%'u of 4,294,967,294 scanned.\n", i);
            s = time(0)+3;
        }

        csend(i, mid, 8);
    }
}

uint verifyChain(const char* path)
{
    //Genesis Public Key
    uint8_t gpub[ECC_CURVE+1];
    size_t len = ECC_CURVE+1;
    b58tobin(gpub, &len, "foxXshGUtLFD24G9pz48hRh3LWM58GXPYiRhNHUyZAPJ", 44);

    //Ok let's check that genesis trans and work through chain
    FILE* f = fopen(path, "r");
    if(f)
    {
        //Is legit genesis block?
        struct trans t;
        if(fread(&t, 1, sizeof(struct trans), f) == sizeof(struct trans))
        {
            if(memcmp(t.to.key, gpub, ECC_CURVE+1) != 0)
                return 0;
        }
        else
        {
            fclose(f);
            return 0; //Could not read the first trans of the block file, fail.
        }

        //Done
        fclose(f);
    }
    else
    {
        printf("Look's like the blocks.dat cannot be found please make sure you chmod 700 ~/vfc\n");
        return 0;
    }
    
    //Look's legit
    return 1;
}

uint isMasterNode(const uint ip)
{
    if(ip == peers[0])
        return 1;
    return 0;
}

void setMasterNode()
{
    memset(peers, 0, sizeof(uint)*MAX_PEERS);
    memset(peer_timeouts, 0, sizeof(uint)*MAX_PEERS);
    struct in_addr a;
    inet_aton(master_ip, &a);
    peers[0] = a.s_addr;
    sprintf(peer_ua[0], "VFC-MASTER");
    num_peers = 1;
}

void peersBroadcast(const char* dat, const size_t len)
{
    for(uint i = 1; i < num_peers; ++i) //Start from 1, skip master
        csend(peers[i], dat, len);
}

void triBroadcast(const char* dat, const size_t len)
{
    if(num_peers > 3)
    {
        uint si = qRand(1, num_peers-1);
        do
        {
            const uint pd = time(0)-(peer_timeouts[si]-MAX_PEER_EXPIRE_SECONDS);
            if(pd <= 540)
                break;
            si++;
        }
        while(si < num_peers);

        if(si == num_peers)
            csend(peers[qRand(1, num_peers-1)], dat, len);
        else
            csend(peers[si], dat, len);
    }
    else
    {
        if(num_peers > 0)
            csend(peers[1], dat, len);
        if(num_peers > 1)
            csend(peers[2], dat, len);
        if(num_peers > 2)
            csend(peers[3], dat, len);
    }
}

void resyncBlocks(const char type)
{
    //Resync from Master
    csend(peers[0], &type, 1);

    //Also Sync from a Random Node (Sync is called fairly often so eventually the random distribution across nodes will fair well)
    replay_allow = 0;
    if(num_peers > 1)
    {
        //Look for a living peer
        uint si = qRand(1, num_peers-1); // start from random offset
        do // find next living peer from offset
        {
            const uint pd = time(0)-(peer_timeouts[si]-MAX_PEER_EXPIRE_SECONDS); //ping delta
            if(pd <= 540)
                break;
            si++;
        }
        while(si < num_peers);

        if(si == num_peers)
            replay_allow = peers[qRand(1, num_peers-1)];
        else
            replay_allow = peers[si];
    }
    else if(num_peers == 1)
    {
        replay_allow = peers[1];
    }

    //Alright ask this peer to replay to us too
    if(num_peers > 1 && replay_allow != 0)
        csend(replay_allow, &type, 1);

    //Set the file memory
    struct in_addr ip_addr;
    ip_addr.s_addr = replay_allow;
    FILE* f = fopen(".vfc/rp.mem", "w");
    if(f)
    {
        fwrite(&replay_allow, sizeof(uint), 1, f);
        fclose(f);
    }
}

uint sendMaster(const char* dat, const size_t len)
{
    return csend(peers[0], dat, len);
}

uint isPeer(const uint ip)
{
    for(uint i = 0; i < num_peers; ++i)
        if(peers[i] == ip)
            return 1;
    return 0;
}

int getPeer(const uint ip)
{
    for(uint i = 0; i < num_peers; ++i)
        if(peers[i] == ip)
            return i;
    return -1;
}

#if MASTER_NODE == 1
void RewardPeer(const uint ip, const char* pubkey)
{
    //Only reward if ready
    if(rewardpaid == 1)
        return;

    //Only reward the eligible peer
    if(peers[rewardindex] != ip)
        return;

    //Get Location
    struct in_addr ip_addr;
    ip_addr.s_addr = ip;
    char con[MIN_LEN];
    char geo[MIN_LEN];
    char cityn[MIN_LEN];
    memset(con, 0, sizeof(con));
    memset(geo, 0, sizeof(geo));
    memset(cityn, 0, sizeof(cityn));
    getLocation(inet_ntoa(ip_addr), con, geo, cityn);

    //Base amount
    uint amount = 14;

    //Double payment to USA servers
    if(geo[0] == 'U' && geo[1] == 'S')
    {
        amount *= 2;
    }

    //Six times payment to EU, JP or VG servers.
    if( (geo[0] == 'J' && geo[1] == 'P') ||
        (con[0] == 'E' && con[1] == 'U') ||
        (geo[0] == 'V' && geo[1] == 'G') )
    {
        amount *= 6;
    }

    //Wrong / not latest version? Low reward
    if(strstr(peer_ua[rewardindex], version) == NULL)
        amount = 7;

    //Workout payment amount
    //const double p = ( ( time(0) - 1559605848 ) / 20 ) * 0.000032596;
    //const uint v = floor(amount - p);
    const uint v = amount;

    //Clean the input ready for sprintf (exploit vector potential otherwise)
    char sa[MIN_LEN];
    memset(sa, 0, sizeof(sa));
    const int sal = strlen(pubkey);
    memcpy(sa, pubkey, sal);
    for(int i = 1; i < sal; ++i)
        if(isalonu(sa[i]) == 0)
            sa[i] = 0x00;

    //Construct command
    char cmd[2048];
    sprintf(cmd, reward_command, sa, v);

    //Drop info
    timestamp();
    printf("Reward Yapit (%u):%s, %u, %s, %s, %s, %s\n", rewardindex, sa, v, inet_ntoa(ip_addr), con, geo, cityn);

    pid_t fork_pid = fork();
    if(fork_pid == 0)
    {
        //Just send the transaction using the console, much easier
        system(cmd);
        exit(0);
    }

    rewardpaid = 1;
}
#endif

//Peers are only replaced if they have not responded in a week, otherwise we still consider them contactable until replaced.
uint addPeer(const uint ip)
{
    //Never add local host
    if(ip == inet_addr("127.0.0.1")) //inet_addr("127.0.0.1") //0x0100007F
        return 0;

    //Is already in peers?
    uint freeindex = 0;
    for(uint i = 0; i < num_peers; ++i)
    {
        if(peers[i] == ip)
        {
            peer_timeouts[i] = time(0) + MAX_PEER_EXPIRE_SECONDS;
            peer_tcount[i]++;
            return 0; //exists
        }

        if(freeindex == 0 && i != 0 && peer_timeouts[i] < time(0)) //0 = Master, never a free slot.
            freeindex = i;
    }

    //Try to add to a free slot first
    if(num_peers < MAX_PEERS)
    {
        peers[num_peers] = ip;
        peer_timeouts[num_peers] = time(0) + MAX_PEER_EXPIRE_SECONDS;
        peer_tcount[num_peers] = 1;
        num_peers++;
        return 1;
    }
    else if(freeindex != 0) //If not replace a node quiet for more than three hours
    {
        peers[freeindex] = ip;
        peer_timeouts[freeindex] = time(0) + MAX_PEER_EXPIRE_SECONDS;
        peer_tcount[freeindex] = 1;
        return 1;
    }

    return 0;
}

///////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////
//////////////////////////////////////////////
/////////////////////////////
///////////////
////////
///
//
//
//
/* ~ Transaction Queue

    aQue() - Add Transaction to Queue
    gQue() - Return pointer to fist valid transaction

*/

//The Variables that make up `the Queue`
struct trans tq[MAX_TRANS_QUEUE];
uint ip[MAX_TRANS_QUEUE];
uint ipo[MAX_TRANS_QUEUE];
unsigned char replay[MAX_TRANS_QUEUE]; // 1 = not replay, 0 = replay
time_t delta[MAX_TRANS_QUEUE];

//Add a transaction to the Queue
uint aQue(struct trans *t, const uint iip, const uint iipo, const unsigned char ir)
{
    //If amount is 0
    if(t->amount == 0)
        return 0; //Don't tell the other peers, pointless transaction

    //Check if duplicate transaction
    int freeindex = -1;
    for(uint i = 0; i < MAX_TRANS_QUEUE; i++)
    {
        if(tq[i].amount != 0)
        {
            //Is this a possible double spend?
            if(ir == 1 && replay[i] == 1)
            {
                if(memcmp(tq[i].from.key, t->from.key, ECC_CURVE+1) == 0 && memcmp(tq[i].to.key, t->to.key, ECC_CURVE+1) != 0)
                {
                    //Log both blocks in bad_blocks
                    FILE* f = fopen(BADCHAIN_FILE, "a");
                    if(f)
                    {
                        fwrite(&tq[i], sizeof(struct trans), 1, f);
                        fwrite(t, sizeof(struct trans), 1, f);
                        fclose(f);
                    }
                    tq[i].amount = 0; //It looks like it could be a double spend, terminate the original transaction
                    return 1; //Don't process this one either and tell our peers about this dodgy action so that they terminate also.
                }
            }

            //UID already in queue?
            if(tq[i].uid == t->uid)
                return 0; //It's not a double spend, just a repeat, don't tell our peers
        }
        
        if(freeindex == -1 && tq[i].amount == 0)
            freeindex = i;
    }

    //if fresh transaction add at available slot
    if(freeindex != -1)
    {
        memcpy(&tq[freeindex], t, sizeof(struct trans));
        ip[freeindex] = iip;
        ipo[freeindex] = iipo;
        replay[freeindex] = ir;
        delta[freeindex] = time(0);
    }

    //Success
    return 1;
}

//pop the first living transaction index off the Queue
int gQue()
{
    for(uint i = 0; i < MAX_TRANS_QUEUE; i++)
    {
        if(tq[i].amount != 0 && time(0) - delta[i] > 2) //Only process transactions more than 3 second old
            return i;
    }
    return -1;
}

//size of queue
uint gQueSize()
{
    uint size = 0;
    for(uint i = 0; i < MAX_TRANS_QUEUE; i++)
    {
        if(tq[i].amount != 0 && time(0) - delta[i] > 2)
            size++;
    }
    return size;
}

///////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////
//////////////////////////////////////////////
/////////////////////////////
///////////////
////////
///
//
//
//
/* ~ Blockchain Transversal & Functions
*/

//Replay blocks to x address
void replayBlocks(const uint ip)
{
    //Send block height
    struct stat st;
    stat(CHAIN_FILE, &st);
    if(st.st_size > 0)
    {
        char pc[MIN_LEN];
        pc[0] = 'h';
        char* ofs = pc + 1;
        const uint height = st.st_size;
        memcpy(ofs, &height, sizeof(uint));
        csend(ip, pc, 1+sizeof(uint));
        struct in_addr ip_addr;
        ip_addr.s_addr = ip;
        printf("Replaying: %.1f kb to %s\n", (double)height / 1000, inet_ntoa(ip_addr));
    }

    //Replay blocks
    FILE* f = fopen(CHAIN_FILE, "r");
    if(f)
    {
        fseek(f, 0, SEEK_END);
        const long int len = ftell(f);

        struct trans t;
        for(size_t i = sizeof(struct trans); i < len; i += sizeof(struct trans))
        {
            fseek(f, i, SEEK_SET);
            if(fread(&t, 1, sizeof(struct trans), f) == sizeof(struct trans))
            {
                //Generate Packet (pc)
                const size_t len = 1+sizeof(uint64_t)+ECC_CURVE+1+ECC_CURVE+1+sizeof(mval)+ECC_CURVE+ECC_CURVE; //lol this is always sizeof(struct trans)+1 im silly but i've done it now so..
                char pc[MIN_LEN];
                pc[0] = 'p'; //This is a re*P*lay
                char* ofs = pc + 1;
                memcpy(ofs, &t.uid, sizeof(uint64_t));
                ofs += sizeof(uint64_t);
                memcpy(ofs, t.from.key, ECC_CURVE+1);
                ofs += ECC_CURVE+1;
                memcpy(ofs, t.to.key, ECC_CURVE+1);
                ofs += ECC_CURVE+1;
                memcpy(ofs, &t.amount, sizeof(mval));
                ofs += sizeof(mval);
                memcpy(ofs, t.owner.key, ECC_CURVE*2);
                csend(ip, pc, len);
                usleep(200000); //333 = 3k, 211 byte packets / 618kb a second
            }
            else
            {
                printf("There was a problem, blocks.dat looks corrupt.\n");
                fclose(f);
                return;
            }
            
        }

        fclose(f);
    }
}
void *replayBlocksThread(void *arg)
{
    chdir(getHome());
    nice(19); //Very low priority thread
    const uint *iip = arg;
    const uint ip = *iip;
    replayBlocks(ip);
    threads--;
    for(int i = 0; i < MAX_THREADS; i++)
        if(thread_ip[i] == ip)
            thread_ip[i] = 0;
}

//(in reverse, latest first to oldest last)
void replayBlocksRev(const uint ip)
{
    //Send block height
    struct stat st;
    stat(CHAIN_FILE, &st);
    if(st.st_size > 0)
    {
        char pc[MIN_LEN];
        pc[0] = 'h';
        char* ofs = pc + 1;
        const uint height = st.st_size;
        memcpy(ofs, &height, sizeof(uint));
        csend(ip, pc, 1+sizeof(uint));
        struct in_addr ip_addr;
        ip_addr.s_addr = ip;
        printf("Replaying: %.1f kb to %s\n", (double)height / 1000, inet_ntoa(ip_addr));
    }

    //Replay blocks
    FILE* f = fopen(CHAIN_FILE, "r");
    if(f)
    {
        fseek(f, 0, SEEK_END);
        const long int len = ftell(f);

        struct trans t;
        for(size_t i = len - sizeof(struct trans); i > 0; i -= sizeof(struct trans))
        {
            fseek(f, i, SEEK_SET);
            if(fread(&t, 1, sizeof(struct trans), f) == sizeof(struct trans))
            {
                //Generate Packet (pc)
                const size_t len = 1+sizeof(uint64_t)+ECC_CURVE+1+ECC_CURVE+1+sizeof(mval)+ECC_CURVE+ECC_CURVE; //lol this is always sizeof(struct trans)+1 im silly but i've done it now so..
                char pc[MIN_LEN];
                pc[0] = 'p'; //This is a re*P*lay
                char* ofs = pc + 1;
                memcpy(ofs, &t.uid, sizeof(uint64_t));
                ofs += sizeof(uint64_t);
                memcpy(ofs, t.from.key, ECC_CURVE+1);
                ofs += ECC_CURVE+1;
                memcpy(ofs, t.to.key, ECC_CURVE+1);
                ofs += ECC_CURVE+1;
                memcpy(ofs, &t.amount, sizeof(mval));
                ofs += sizeof(mval);
                memcpy(ofs, t.owner.key, ECC_CURVE*2);
                csend(ip, pc, len);
                usleep(200000); //333 = 3k, 211 byte packets / 618kb a second
            }
            else
            {
                printf("There was a problem, blocks.dat looks corrupt.\n");
                fclose(f);
                return;
            }
            
        }

        fclose(f);
    }
}
void *replayBlocksRevThread(void *arg)
{
    sleep(3); //Offset threads--; collisions
    chdir(getHome());
    nice(19); //Very low priority thread
    const uint *iip = arg;
    const uint ip = *iip;
    replayBlocksRev(ip);
    threads--;
    for(int i = 0; i < MAX_THREADS; i++)
        if(thread_ip[i] == ip)
            thread_ip[i] = 0;
}

//dump all trans
void dumptrans()
{
    FILE* f = fopen(CHAIN_FILE, "r");
    if(f)
    {
        fseek(f, 0, SEEK_END);
        const long int len = ftell(f);

        struct trans t;
        for(size_t i = 0; i < len; i += sizeof(struct trans))
        {
            fseek(f, i, SEEK_SET);
            if(fread(&t, 1, sizeof(struct trans), f) == sizeof(struct trans))
            {
                char topub[MIN_LEN];
                memset(topub, 0, sizeof(topub));
                size_t len = MIN_LEN;
                b58enc(topub, &len, t.to.key, ECC_CURVE+1);

                char frompub[MIN_LEN];
                memset(frompub, 0, sizeof(frompub));
                len = MIN_LEN;
                b58enc(frompub, &len, t.from.key, ECC_CURVE+1);

                printf("%s > %s : %u\n", frompub, topub, t.amount);
            }
            else
            {
                printf("There was a problem, blocks.dat looks corrupt.\n");
                fclose(f);
                return;
            }
            
        }

        fclose(f);
    }
}

//dump all bad trans
void dumpbadtrans()
{
    FILE* f = fopen(BADCHAIN_FILE, "r");
    if(f)
    {
        fseek(f, 0, SEEK_END);
        const long int len = ftell(f);

        struct trans t;
        for(size_t i = 0; i < len; i += sizeof(struct trans))
        {
            fseek(f, i, SEEK_SET);
            if(fread(&t, 1, sizeof(struct trans), f) == sizeof(struct trans))
            {
                char topub[MIN_LEN];
                memset(topub, 0, sizeof(topub));
                size_t len = MIN_LEN;
                b58enc(topub, &len, t.to.key, ECC_CURVE+1);

                char frompub[MIN_LEN];
                memset(frompub, 0, sizeof(frompub));
                len = MIN_LEN;
                b58enc(frompub, &len, t.from.key, ECC_CURVE+1);

                printf("%s > %s : %u\n", frompub, topub, t.amount);
            }
            else
            {
                printf("There was a problem, bad_blocks.dat looks corrupt.\n");
                fclose(f);
                return;
            }
            
        }

        fclose(f);
    }
}

//print received transactions
void printIns(addr* a)
{
    FILE* f = fopen(CHAIN_FILE, "r");
    if(f)
    {
        fseek(f, 0, SEEK_END);
        const long int len = ftell(f);

        struct trans t;
        for(size_t i = 0; i < len; i += sizeof(struct trans))
        {
            fseek(f, i, SEEK_SET);
            if(fread(&t, 1, sizeof(struct trans), f) == sizeof(struct trans))
            {
                if(memcmp(&t.to.key, a->key, ECC_CURVE+1) == 0)
                {
                    char pub[MIN_LEN];
                    memset(pub, 0, sizeof(pub));
                    size_t len = MIN_LEN;
                    b58enc(pub, &len, t.from.key, ECC_CURVE+1);
                    printf("%s > %u\n", pub, t.amount);
                }
            }
            else
            {
                printf("There was a problem, blocks.dat looks corrupt.\n");
                fclose(f);
                return;
            }
            
        }

        fclose(f);
    }
}

//print sent transactions
void printOuts(addr* a)
{
    FILE* f = fopen(CHAIN_FILE, "r");
    if(f)
    {
        fseek(f, 0, SEEK_END);
        const long int len = ftell(f);

        struct trans t;
        for(size_t i = 0; i < len; i += sizeof(struct trans))
        {
            fseek(f, i, SEEK_SET);
            if(fread(&t, 1, sizeof(struct trans), f) == sizeof(struct trans))
            {
                if(memcmp(&t.from.key, a->key, ECC_CURVE+1) == 0)
                {
                    char pub[MIN_LEN];
                    memset(pub, 0, sizeof(pub));
                    size_t len = MIN_LEN;
                    b58enc(pub, &len, t.to.key, ECC_CURVE+1);
                    printf("%s > %u\n", pub, t.amount);
                }
            }
            else
            {
                printf("There was a problem, blocks.dat looks corrupt.\n");
                fclose(f);
                return;
            }
            
        }

        fclose(f);
    }
}

//get balance
mval getBalanceLocal(addr* from)
{
    //Get local Balance
    mval rv = 0;
    FILE* f = fopen(CHAIN_FILE, "r");
    if(f)
    {
        fseek(f, 0, SEEK_END);
        const long int len = ftell(f);

        struct trans t;
        for(size_t i = 0; i < len; i += sizeof(struct trans))
        {
            fseek(f, i, SEEK_SET);
            if(fread(&t, 1, sizeof(struct trans), f) == sizeof(struct trans))
            {
                if(memcmp(&t.to.key, from->key, ECC_CURVE+1) == 0)
                    rv += t.amount;
                if(memcmp(&t.from.key, from->key, ECC_CURVE+1) == 0)
                    rv -= t.amount;
            }
            else
            {
                printf("There was a problem, blocks.dat looks corrupt.\n");
                fclose(f);
                return 0;
            }
            
        }

        fclose(f);
    }
    return rv;
}

//get balance
mval getBalance(addr* from)
{
    //Reset our files & memory for last count
    balance_accumulator = 0;
    for(uint i = 0; i < MAX_PEERS; i++)
        peer_ba[i] = 0;
    FILE* f = fopen(".vfc/bal.mem", "w");
    if(f)
    {
        fwrite(&balance_accumulator, sizeof(mval), 1, f);
        fclose(f);
    }
    f = fopen(".vfc/balt.mem", "w");
    if(f)
    {
        fwrite(&balance_accumulator, sizeof(mval), 1, f);
        fclose(f);
    }

    //Tell peers to fill our accumulator
    char pc[ECC_CURVE+2];
    pc[0] = '$';
    char* ofs = pc+1;
    memcpy(ofs, from->key, ECC_CURVE+1);
    sendMaster(pc, ECC_CURVE+2);
    peersBroadcast(pc, ECC_CURVE+2);

    //Get local Balance
    mval rv = 0;
    f = fopen(CHAIN_FILE, "r");
    if(f)
    {
        fseek(f, 0, SEEK_END);
        const long int len = ftell(f);

        struct trans t;
        for(size_t i = 0; i < len; i += sizeof(struct trans))
        {
            fseek(f, i, SEEK_SET);
            if(fread(&t, 1, sizeof(struct trans), f) == sizeof(struct trans))
            {
                if(memcmp(&t.to.key, from->key, ECC_CURVE+1) == 0)
                    rv += t.amount;
                if(memcmp(&t.from.key, from->key, ECC_CURVE+1) == 0)
                    rv -= t.amount;
            }
            else
            {
                printf("There was a problem, blocks.dat looks corrupt.\n");
                fclose(f);
                return 0;
            }
            
        }

        fclose(f);
    }
    return rv;
}

//Calculate if an address has the value required to make a transaction of x amount.
uint hasbalance(const uint64_t uid, addr* from, mval amount)
{
    mval rv = 0;
    FILE* f = fopen(CHAIN_FILE, "r");
    if(f)
    {
        fseek(f, 0, SEEK_END);
        const long int len = ftell(f);

        struct trans t;
        for(size_t i = 0; i < len; i += sizeof(struct trans))
        {
            fseek(f, i, SEEK_SET);
            if(fread(&t, 1, sizeof(struct trans), f) == sizeof(struct trans))
            {
                if(t.uid == uid)
                {
                    fclose(f);
                    return ERROR_UIDEXIST;
                }

                if(memcmp(&t.to, from, ECC_CURVE+1) == 0)
                    rv += t.amount;
                if(memcmp(&t.from, from, ECC_CURVE+1) == 0)
                    rv -= t.amount;
            }
            else
            {
                printf("There was a problem, blocks.dat looks corrupt.\n");
                fclose(f);
                return 0;
            }
            
        }

        fclose(f);
    }
    if(rv >= amount)
        return 1;
    else
        return 0;
}

//Execute Transaction
int process_trans(const uint64_t uid, addr* from, addr* to, mval amount, sig* owner)
{
    //Create trans struct
    struct trans t;
    memset(&t, 0, sizeof(struct trans));
    t.uid = uid;
    memcpy(t.from.key, from->key, ECC_CURVE+1);
    memcpy(t.to.key, to->key, ECC_CURVE+1);
    t.amount = amount;
    
    //Lets verify if this signature is valid
    uint8_t thash[ECC_CURVE];
    makHash(thash, &t);
    if(ecdsa_verify(from->key, thash, owner->key) == 0)
        return ERROR_SIGFAIL;

    //Add the sig now we know it's valid
    memcpy(t.owner.key, owner->key, ECC_CURVE*2);
    
    //Check this address has the required value for the transaction (and that UID is actually unique)
    const int hbr = hasbalance(uid, from, amount);
    if(hbr == 0)
        return ERROR_NOFUNDS;
    else if(hbr < 0)
        return hbr;

    //Ok let's write the transaction to chain
    if(memcmp(from->key, to->key, ECC_CURVE+1) != 0) //Only log if the user was not sending VFC to themselves.
    {
        FILE* f = fopen(CHAIN_FILE, "a");
        if(f)
        {
            fwrite(&t, sizeof(struct trans), 1, f);
            fclose(f);
        }
    }

    //Success
    return 1;
}

void makAddr(addr* pub, addr* priv)
{
    //Make key pair
    ecc_make_key(pub->key, priv->key);

    //Dump Base58
    char bpub[MIN_LEN], bpriv[MIN_LEN];
    memset(bpub, 0, sizeof(bpub));
    memset(bpriv, 0, sizeof(bpriv));
    size_t len = MIN_LEN;
    b58enc(bpub, &len, pub->key, ECC_CURVE+1);
    b58enc(bpriv, &len, priv->key, ECC_CURVE);
    printf("\n\x1B[33mMade new Address / Key Pair\x1B[0m\n\nPublic: %s\n\nPrivate: %s\n\n\x1B[0m", bpub, bpriv);
}

void makGenesis()
{
    //Make genesis public key
    uint8_t gpub[ECC_CURVE+1];
    size_t len = ECC_CURVE+1;
    b58tobin(gpub, &len, "foxXshGUtLFD24G9pz48hRh3LWM58GXPYiRhNHUyZAPJ", 44);

    //Make Genesis Block (does not need to be signed or have src addr, or have a UID)
    struct trans t;
    memset(&t, 0, sizeof(struct trans));
    t.amount = 0xFFFFFFFF;
    memcpy(&t.to.key, gpub, ECC_CURVE+1);
    FILE* f = fopen(CHAIN_FILE, "w");
    if(f)
    {
        fwrite(&t, sizeof(struct trans), 1, f);
        fclose(f);
    }
}

///////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////
//////////////////////////////////////////////
/////////////////////////////
///////////////
////////
///
//
//
//
/* ~ Console & Socket I/O
*/

void savemem()
{
    FILE* f = fopen(".vfc/peers.mem", "w");
    if(f)
    {
        fwrite(peers, sizeof(uint), MAX_PEERS, f);
        fclose(f);
    }

    f = fopen(".vfc/peers1.mem", "w");
    if(f)
    {
        fwrite(peer_tcount, sizeof(uint), MAX_PEERS, f);
        fclose(f);
    }

    f = fopen(".vfc/peers2.mem", "w");
    if(f)
    {
        fwrite(peer_timeouts, sizeof(time_t), MAX_PEERS, f);
        fclose(f);
    }

    f = fopen(".vfc/peers3.mem", "w");
    if(f)
    {
        fwrite(peer_ua, 64, MAX_PEERS, f);
        fclose(f);
    }
}

void loadmem()
{
    FILE* f = fopen(".vfc/peers.mem", "r");
    if(f)
    {
        if(fread(peers, sizeof(uint), MAX_PEERS, f) != MAX_PEERS)
            printf("\033[1m\x1B[31mPeers Memory Corrupted. Load Failed.\x1B[0m\033[0m\n");
        fclose(f);
    }
    num_peers = countPeers();

    f = fopen(".vfc/peers1.mem", "r");
    if(f)
    {
        if(fread(peer_tcount, sizeof(uint), MAX_PEERS, f) != MAX_PEERS)
            printf("\033[1m\x1B[31mPeers1 Memory Corrupted. Load Failed.\x1B[0m\033[0m\n");
        fclose(f);
    }

    f = fopen(".vfc/peers2.mem", "r");
    if(f)
    {
        if(fread(peer_timeouts, sizeof(uint), MAX_PEERS, f) != MAX_PEERS)
            printf("\033[1m\x1B[31mPeers2 Memory Corrupted. Load Failed.\x1B[0m\033[0m\n");
        fclose(f);
    }

    f = fopen(".vfc/peers3.mem", "r");
    if(f)
    {
        if(fread(peer_ua, 64, MAX_PEERS, f) != MAX_PEERS)
            printf("\033[1m\x1B[31mPeers3 Memory Corrupted. Load Failed.\x1B[0m\033[0m\n");
        fclose(f);
    }
}

void sigintHandler(int sig_num) 
{
    static int m_qe = 0;
    
    if(m_qe == 0)
    {
        printf("\n\x1B[33mPlease Wait while we save the peers state...\x1B[0m\n\n");
        m_qe = 1;

        savemem();
        exit(0);
    }
}

uint isNodeRunning()
{
    struct sockaddr_in server;

    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(s == -1)
        return 0;

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(gport);
    
    if(bind(s, (struct sockaddr*)&server, sizeof(server)) < 0)
    {
        close(s);
        return 1;
    }

    close(s);
    return 0;
}

void *processThread(void *arg)
{
    chdir(getHome());
    time_t nr = time(0) + REWARD_RETRY_INTERVAL;
    time_t pr = time(0) + PING_INTERVAL;
    while(1)
    {
        //Check which of the peers are still alive, those that are, update their timestamps
        if(time(0) > pr)
        {
            peersBroadcast(mid, 8);
            peersBroadcast("a", 1); //Give us your user-agent too please
            peer_timeouts[0] = time(0)+MAX_PEER_EXPIRE_SECONDS; //Reset master timeout
            pr = time(0) + PING_INTERVAL;
        }
        
//This code is only for the masternode to execute, in-order to distribute rewards fairly.
#if MASTER_NODE == 1
        //Peers get a few chances to collect their reward
        if(rewardpaid == 0 && time(0) > nr)
        {
            csend(peers[rewardindex], "x", 1);
            nr = time(0)+1;
        }

        //Otherwise they forefit, it's time to reward the next peer.
        if(time(0) > nextreward)
        {
            //Set the next reward time / reset reward interval
            nextreward = time(0) + REWARD_INTERVAL;
            rewardpaid = 0;
            
            //Try to find a peer who has responded to a ping in atleast the last 9 minutes. Remember we check every peer with a ping every 3 minutes.
            rewardindex++;
            uint dt = (time(0)-(peer_timeouts[rewardindex]-MAX_PEER_EXPIRE_SECONDS)); //Prevent negative numbers, causes wrap
            while(dt > 540)
            {
                rewardindex++;
                dt = (time(0)-(peer_timeouts[rewardindex]-MAX_PEER_EXPIRE_SECONDS));
                if(rewardindex >= num_peers)
                {
                    //Shuffle peer list (keep it fair)
                    /*for(int i = 0; i < num_peers; i++)
                    {
                        struct trans t;
                        const int r = qRand(0, num_peers-1);
                        memcpy(&t, &peers[r], sizeof(struct trans));
                        memcpy(&peers[r], &peers[i], sizeof(struct trans));
                        memcpy(&peers[i], &t, sizeof(struct trans));
                    }*/

                    //The master should always be online, so if no other node was eligible for a reward, and we looped back to the master,
                    //wait 10 mins before we try again and try to give the reward to the master, if it really is online.
                    rewardindex = 0;
                    break;
                }
            }
        }
#endif

        //See if there is a new transaction to process
        const int i = gQue();
        if(i == -1)
        {
            usleep(333); //Little delay if queue is empty we dont want to thrash cycles
            continue;
        }  
        
        //Process the transaction
        const int r = process_trans(tq[i].uid, &tq[i].from, &tq[i].to, tq[i].amount, &tq[i].owner);

        //Good transaction!
        if(r == 1 && replay[i] == 1)
        {
            //Track this client from origin
            addPeer(ip[i]);
            if(ipo[i] != 0)
                addPeer(ipo[i]); //Track this client by attached origin

            //Construct a non-repeatable transaction and tell our peers
            const uint32_t origin = ip[i];
            const size_t len = 1+sizeof(uint64_t)+sizeof(uint32_t)+ECC_CURVE+1+ECC_CURVE+1+sizeof(mval)+ECC_CURVE+ECC_CURVE; //Again it's basically sizeof(struct trans)+uint64_t+1
            char pc[MIN_LEN];
            pc[0] = 't';
            char* ofs = pc + 1;
            memcpy(ofs, &origin, sizeof(uint32_t));
            ofs += sizeof(uint32_t);
            memcpy(ofs, &tq[i].uid, sizeof(uint64_t));
            ofs += sizeof(uint64_t);
            memcpy(ofs, tq[i].from.key, ECC_CURVE+1);
            ofs += ECC_CURVE+1;
            memcpy(ofs, tq[i].to.key, ECC_CURVE+1);
            ofs += ECC_CURVE+1;
            memcpy(ofs, &tq[i].amount, sizeof(mval));
            ofs += sizeof(mval);
            memcpy(ofs, tq[i].owner.key, ECC_CURVE*2);
            triBroadcast(pc, len);
        }

        //Alright this transaction is PROCESSED
        tq[i].amount = 0; //Signifies transaction as invalid / completed / processed (basically done)
    }
}

int main(int argc , char *argv[])
{
    //Suppress Sigpipe
    signal(SIGPIPE, SIG_IGN);

#if MASTER_NODE == 1
    //load MaxMind City
    if(MMDB_open("/root/maxmind/city.mmdb", MMDB_MODE_MMAP, &mmdb) != MMDB_SUCCESS)
        printf("\x1B[31mFailed to load MaxMind Cities MMDB File: city.mmdb\x1B[0m\n");
#endif

    //set local working directory
    chdir(getHome());

    //create vfc dir
    mkdir(".vfc", 0700);

    //Create rewards address if it doesnt exist
    if(access(".vfc/public.key", F_OK) == -1)
    {
        addr pub, priv;
        makAddr(&pub, &priv);

        char bpub[MIN_LEN], bpriv[MIN_LEN];
        memset(bpub, 0, sizeof(bpub));
        memset(bpriv, 0, sizeof(bpriv));
        size_t len = MIN_LEN;
        b58enc(bpub, &len, pub.key, ECC_CURVE+1);
        b58enc(bpriv, &len, priv.key, ECC_CURVE);

        FILE* f = fopen(".vfc/public.key", "w");
        if(f)
        {
            fwrite(bpub, sizeof(char), strlen(bpub), f);
            fclose(f);
        }
        f = fopen(".vfc/private.key", "w");
        if(f)
        {
            fwrite(bpriv, sizeof(char), strlen(bpriv), f);
            fclose(f);
        }
    }

    //Load your public key for rewards
    FILE* f = fopen(".vfc/public.key", "r");
    if(f)
    {
        fseek(f, 0, SEEK_END);
        const long int len = ftell(f);
        fseek(f, 0, SEEK_SET);

        memset(myrewardkey, 0x00, sizeof(myrewardkey));
        myrewardkey[0] = ' ';
        
        if(fread(myrewardkey+1, sizeof(char), len, f) != len)
            printf("\033[1m\x1B[31mFailed to load Rewards address, this means you are unable to receive rewards.\x1B[0m\033[0m\n");

        //clean off any new spaces at the end, etc
        const int sal = strlen(myrewardkey);
        for(int i = 1; i < sal; ++i)
            if(isalonu(myrewardkey[i]) == 0)
                myrewardkey[i] = 0x00;

        fclose(f);
    }

    //Set next reward time
    nextreward = time(0) + REWARD_INTERVAL; //9-11 minutes, add's some entropy.

    //Set the MID
    mid[0] = '\t';
    mid[1] = qRand(0, 255);
    mid[2] = qRand(0, 255);
    mid[3] = qRand(0, 255);
    mid[4] = qRand(0, 255);
    mid[5] = qRand(0, 255);
    mid[6] = qRand(0, 255);
    mid[7] = qRand(0, 255);

    //Outgoings and Incomings
    if(argc == 3)
    {
        if(strcmp(argv[1], "getpub") == 0)
        {
            //Force console to clear.
            printf("\033[H\033[J");

            //Get Private Key
            uint8_t p_privateKey[ECC_BYTES+1];
            size_t len = ECC_CURVE;
            b58tobin(p_privateKey, &len, argv[2], strlen(argv[2]));

            //Gen Public Key
            uint8_t p_publicKey[ECC_BYTES+1];
            ecc_get_pubkey(p_publicKey, p_privateKey);

            //Dump Public Key as Base58
            char bpub[MIN_LEN];
            memset(bpub, 0, sizeof(bpub));
            len = MIN_LEN;
            b58enc(bpub, &len, p_publicKey, ECC_CURVE+1);

            printf("\n\x1B[33mPublic Key Generated\x1B[0m\n\nPublic: %s\n\n\x1B[0m", bpub);
            
            exit(0);
        }

        if(strcmp(argv[1], "addpeer") == 0)
        {
            loadmem();
            addPeer(inet_addr(argv[2]));
            printf("\nThank you peer %s has been added to your peer list. Please restart your full node process to load the changes.\n\n", argv[2]);
            savemem();
            exit(0);
        }

        if(strstr(argv[1], "in") != NULL)
        {
            addr a;
            size_t len = ECC_CURVE+1;
            b58tobin(a.key, &len, argv[2], strlen(argv[2]));
            printIns(&a);
            exit(0);
        }

        if(strstr(argv[1], "out") != NULL)
        {
            addr a;
            size_t len = ECC_CURVE+1;
            b58tobin(a.key, &len, argv[2], strlen(argv[2]));
            printOuts(&a);
            exit(0);
        }
    }

    //Some basic funcs
    if(argc == 2)
    {
        //Help
        if(strcmp(argv[1], "help") == 0)
        {
            printf("\n\x1B[33mTo get an address balance use:\x1B[0m\n ./coin <address public key>\n\n");
            printf("\x1B[33mTo check sent transactions from an address use:\x1B[0m\n ./coin out <address public key>\n\n");
            printf("\x1B[33mTo check received transactions from an address use:\x1B[0m\n ./coin in <address public key>\n\n");
            printf("\x1B[33mTo make a transaction use:\x1B[0m\n ./coin <sender public key> <reciever public key> <amount> <sender private key>\x1B[0m\n\n");
            printf("\x1B[33mTo manually trigger blockchain resync use:\x1B[0m\n ./coin resync\x1B[0m\n\n");
            printf("\x1B[33mTo manually trigger blockchain sync use:\x1B[0m\n ./coin sync\x1B[0m\n\n");
            printf("\x1B[33mTo create a new Address, Public / Private Key-Pair:\x1B[0m\n ./coin new\x1B[0m\n\n");
            printf("\x1B[33mGet Public Key from Private Key:\x1B[0m\n ./coin getpub <private key>\x1B[0m\n\n");
            printf("\x1B[33mTo manually add a peer use:\x1B[0m\n ./coin addpeer <peer ip-address>\n\n");
            printf("\x1B[33mList all locally indexed peers and info:\x1B[0m\n ./coin peers\n\n");
            printf("\x1B[33mDump all transactions in the blockchain:\x1B[0m\n ./coin dump\n\n");
            printf("\x1B[33mDump all double spend transactions detected from other peers:\x1B[0m\n ./coin dumpbad\n\n");
            printf("\x1B[33mClear all double spend transactions detected from other peers:\x1B[0m\n ./coin clearbad\n\n");
            printf("\x1B[33mReturns your Public Key stored in ~/.vfc/public.key for reward collections:\x1B[0m\n ./coin reward\n\n");
            printf("\x1B[33mReturns client version:\x1B[0m\n ./coin version\n\n");
            printf("\x1B[33mReturns client blocks.dat size / height:\x1B[0m\n ./coin heigh\n\n");
            printf("\x1B[33mDoes it look like this client wont send transactions? Maybe the master server is offline and you have no saved peers, if so then scan for a peer using the following command:\x1B[0m\n ./coin scan\x1B[0m\n\n");
            
            printf("\x1B[33mTo get started running a dedicated node, execute ./coin on a seperate screen, you will need to make atleast one transaction a month to be indexed by the network.\x1B[0m\n\n");
            exit(0);
        }

        //version
        if(strcmp(argv[1], "version") == 0)
        {
            printf("\x1B[33m%s\x1B[0m\n", version);
            exit(0);
        }

        //version
        if(strcmp(argv[1], "heigh") == 0)
        {
            struct stat st;
            stat(CHAIN_FILE, &st);
            if(st.st_size > 0)
                printf("\x1B[33m%1.f\x1B[0m kb / \x1B[33m%u\x1B[0m Transactions\n", (double)st.st_size / 1000, (uint)st.st_size / 133);
            exit(0);
        }

        //sync
        if(strcmp(argv[1], "sync") == 0)
        {
            setMasterNode();
            loadmem();
            resyncBlocks('s');
            
            __off_t ls = 0;
            uint tc = 0;
            while(1)
            {
                printf("\033[H\033[J");
                if(tc >= 99)
                {
                    tc = 0;
                    resyncBlocks('s'); //Sync from a new random peer if no data after x seconds
                }
                struct stat st;
                stat(CHAIN_FILE, &st);
                if(st.st_size != ls)
                {
                    ls = st.st_size;
                    tc = 0;
                }
                struct in_addr ip_addr;
                ip_addr.s_addr = replay_allow;
                FILE* f = fopen(".vfc/rp.mem", "w");
                if(f)
                {
                    fwrite(&replay_allow, sizeof(uint), 1, f);
                    fclose(f);
                }
                f = fopen(".vfc/rph.mem", "r");
                if(f)
                {
                    if(fread(&replay_height, sizeof(uint), 1, f) != 1)
                        printf("\033[1m\x1B[31mReplay Height Corrupted. Load Failed.\x1B[0m\033[0m\n");
                    fclose(f);
                }
                if(replay_allow == 0)
                    printf("\x1B[33m%.1f\x1B[0m kb of \x1B[33m%.1f\x1B[0m kb downloaded press CTRL+C to Quit. Synchronizing only from the Master.\n", (double)st.st_size / 1000, (double)replay_height / 1000);
                else
                    printf("\x1B[33m%.1f\x1B[0m kb of \x1B[33m%.1f\x1B[0m kb downloaded press CTRL+C to Quit. Authorized Peer: %s.\n", (double)st.st_size / 1000, (double)replay_height / 1000, inet_ntoa(ip_addr));
                tc++;
                sleep(1);
            }

            exit(0);
        }

        //resync
        if(strcmp(argv[1], "resync") == 0)
        {
            makGenesis(); //Erases chain and resets it for a full resync
            setMasterNode();
            loadmem();
            resyncBlocks('r');
            FILE* f = fopen(".vfc/rp.mem", "w");
            if(f)
            {
                fwrite(&replay_allow, sizeof(uint), 1, f);
                fclose(f);
            }
            printf("\x1B[33mResync Executed.\x1B[0m\n\n");
            exit(0);
        }

        //Gen new address
        if(strcmp(argv[1], "new") == 0)
        {
            addr pub, priv;
            makAddr(&pub, &priv);
            exit(0);
        }

        //Scan for peers
        if(strcmp(argv[1], "scan") == 0)
        {
            loadmem();
            scanPeers();
            savemem();
            exit(0);
        }

        //Dump all trans
        if(strcmp(argv[1], "dump") == 0)
        {
            dumptrans();
            exit(0);
        }

        //Dump all bad trans
        if(strcmp(argv[1], "dumpbad") == 0)
        {
            dumpbadtrans();
            exit(0);
        }

        //Clear all bad trans
        if(strcmp(argv[1], "clearbad") == 0)
        {
            remove(BADCHAIN_FILE);
            exit(0);
        }

        //Return reward addr
        if(strcmp(argv[1], "reward") == 0)
        {
            loadmem();

            addr rk;
            size_t len = ECC_CURVE+1;
            b58tobin(rk.key, &len, myrewardkey+1, strlen(myrewardkey)-1); //It's got a space in it (at the beginning) ;)
            printf("Please Wait...\n");
            
            mval bal = getBalance(&rk);
            mval baln = 0;
            mval balt = 0;
            sleep(3);
            FILE* f = fopen(".vfc/bal.mem", "r");
            if(f)
            {
                if(fread(&baln, sizeof(mval), 1, f) != 1)
                    printf("\033[1m\x1B[31mbal.mem Corrupted. Load Failed.\x1B[0m\033[0m\n");
                fclose(f);
            }
            f = fopen(".vfc/balt.mem", "r");
            if(f)
            {
                if(fread(&balt, sizeof(mval), 1, f) != 1)
                    printf("\033[1m\x1B[31mbalt.mem Corrupted. Load Failed.\x1B[0m\033[0m\n");
                fclose(f);
            }

            mval fbal = bal;
            if(balt > fbal)
                fbal = balt;

            setlocale(LC_NUMERIC, "");
            printf("\x1B[33m(Local Balance / Mode Network Balance / Highest Network Balance)\x1B[0m\n");
            printf("\x1B[33mYour reward address is:\x1B[0m%s\n(\x1B[33m%'u VFC\x1B[0m / \x1B[33m%'u VFC\x1B[0m / \x1B[33m%'u VFC\x1B[0m)\n\n\x1B[33mFinal Balance:\x1B[0m %'u VFC\n\n", myrewardkey, bal, balt, baln, fbal);
            exit(0);
        }

        //Force add a peer
        if(strcmp(argv[1], "addpeer") == 0)
        {
            loadmem();
            printf("\x1B[33mPlease input Peer IP Address: \x1B[0m");
            char in[32];
            fgets(in, 32, stdin);
            addPeer(inet_addr(in));
            printf("\nThank you peer %s has been added to your peer list. Please restart your full node process to load the changes.\n\n", in);
            savemem();
            exit(0);
        }

        //List all peers and their total throughput
        if(strcmp(argv[1], "peers") == 0)
        {
            loadmem();
            printf("\n\x1B[33mTip; If you are running a full-node then consider hosting a website on port 80 where you can declare a little about your operation and a VFC address people can use to donate to you on. Thus you should be able to visit any of these IP addresses in a web-browser and find out a little about each node or obtain a VFC Address to donate to the node operator on.\x1B[0m\n\n");
            printf("\x1B[33mTotal Peers:\x1B[0m %u\x1B[33\n\n", num_peers);
            printf("\x1B[33mIP Address / Number of Transactions Relayed / Seconds since last trans or ping / user-agent [version/blockheight/nodename/machine] \x1B[0m\n");
            uint ac = 0;
            for(uint i = 0; i < num_peers; ++i)
            {
                struct in_addr ip_addr;
                ip_addr.s_addr = peers[i];
                const uint pd = time(0)-(peer_timeouts[i]-MAX_PEER_EXPIRE_SECONDS); //ping delta
                if(pd <= 540)
                {
                    printf("%s / %u / %u / %s\n", inet_ntoa(ip_addr), peer_tcount[i], pd, peer_ua[i]);
                    ac++;
                }
            }
            printf("\x1B[33mAlive Peers:\x1B[0m %u\n", ac);
            printf("\n--- Possibly Dead Peers ---\n\n");
            uint dc = 0;
            for(uint i = 0; i < num_peers; ++i)
            {
                struct in_addr ip_addr;
                ip_addr.s_addr = peers[i];
                const uint pd = time(0)-(peer_timeouts[i]-MAX_PEER_EXPIRE_SECONDS); //ping delta
                if(pd > 540)
                {
                    printf("%s / %u / %u / %s\n", inet_ntoa(ip_addr), peer_tcount[i], pd, peer_ua[i]);
                    dc++;
                }
            }
            printf("\x1B[33mDead Peers:\x1B[0m %u\n\n", dc);
            exit(0);
        }
    }

    //Let's make sure we're booting with the right damn chain
    if(verifyChain(CHAIN_FILE) == 0)
    {
        printf("\033[1m\x1B[31mSorry you're not on the right chain. Please resync by running ./coin resync\x1B[0m\033[0m\n\n");
        exit(0);
    }

    //Set Master Node
    setMasterNode();

    //Load Mem
    loadmem();

    //Does user just wish to get address balance?
    if(argc == 2)
    {
        if(isNodeRunning() == 0)
        {
            printf("\033[1m\x1B[31mPlease make sure you are running the full node and that you have synchronized to the latest blockchain before checking an address balance.\x1B[0m\033[0m\n\n");
            exit(0);
        }

        //Get balance
        addr from;
        size_t len = ECC_CURVE+1;
        b58tobin(from.key, &len, argv[1], strlen(argv[1]));
        printf("Please Wait...\n");

        //Local
        struct timespec s;
        clock_gettime(CLOCK_MONOTONIC, &s);
        mval bal = getBalance(&from);
        struct timespec e;
        clock_gettime(CLOCK_MONOTONIC, &e);
        long int td = (e.tv_nsec - s.tv_nsec);
        if(td > 0){td /= 1000000;}
        else if(td < 0){td = 0;}

        //Network
        mval baln = 0, balt = 0;
        sleep(3);
        FILE* f = fopen(".vfc/bal.mem", "r");
        if(f)
        {
            if(fread(&baln, sizeof(mval), 1, f) != 1)
                printf("\033[1m\x1B[31mbal.mem Corrupted. Load Failed.\x1B[0m\033[0m\n");
            fclose(f);
        }
        f = fopen(".vfc/balt.mem", "r");
        if(f)
        {
            if(fread(&balt, sizeof(mval), 1, f) != 1)
                printf("\033[1m\x1B[31mbalt.mem Corrupted. Load Failed.\x1B[0m\033[0m\n");
            fclose(f);
        }

        mval fbal = bal;
        if(balt > fbal)
            fbal = balt;
        
        setlocale(LC_NUMERIC, "");
        printf("\x1B[33m(Local Balance / Mode Network Balance / Highest Network Balance)\x1B[0m\n");
        printf("\x1B[33mThe Balance for Address: \x1B[0m%s\n(\x1B[33m%'u VFC\x1B[0m / \x1B[33m%'u VFC\x1B[0m / \x1B[33m%'u VFC\x1B[0m)\n\x1B[33mTime Taken\x1B[0m %li \x1B[33mMilliseconds (\x1B[0m%li ns\x1B[33m).\x1B[0m\n\n\x1B[33mFinal Balance:\x1B[0m %'u VFC\n\n", argv[1], bal, balt, baln, td, (e.tv_nsec - s.tv_nsec), fbal);
        exit(0);
    }

    //Does user just wish to execute transaction?
    if(argc == 5)
    {
    //Force console to clear.
    printf("\033[H\033[J");

        if(isNodeRunning() == 0)
        {
            printf("\033[1m\x1B[31mPlease make sure you are running the full node and that you have synchronized to the latest blockchain before making a transaction.\x1B[0m\033[0m\n\n");
            exit(0);
        }

        //Recover data from parameters
        uint8_t from[ECC_CURVE+1];
        uint8_t to[ECC_CURVE+1];
        uint8_t priv[ECC_CURVE];
        //
        size_t blen = ECC_CURVE+1;
        b58tobin(from, &blen, argv[1], strlen(argv[1]));
        b58tobin(to, &blen, argv[2], strlen(argv[2]));
        blen = ECC_CURVE;
        b58tobin(priv, &blen, argv[4], strlen(argv[4]));
        
        //Construct Transaction
        struct trans t;
        memset(&t, 0, sizeof(struct trans));
        //
        memcpy(t.from.key, from, ECC_CURVE+1);
        memcpy(t.to.key, to, ECC_CURVE+1);
        t.amount = atoi(argv[3]);

        //Too low amount?
        if(t.amount <= 0)
        {
            printf("\033[1m\x1B[31mSorry the amount you provided was too low, please try 1 VFC or above.\x1B[0m\033[0m\n\n");
            exit(0);
        }

    //Get balance..
    const mval bal0 = getBalanceLocal(&t.from);

        //UID Based on timestamp & signature
        time_t ltime = time(NULL);
        char suid[MIN_LEN];
        snprintf(suid, sizeof(suid), "%s/%s", asctime(localtime(&ltime)), argv[1]); //timestamp + base58 from public key
        t.uid = crc64(0, suid, strlen(suid));

        //Sign the block
        uint8_t thash[ECC_CURVE];
        makHash(thash, &t);
        if(ecdsa_sign(priv, thash, t.owner.key) == 0)
        {
            printf("\n\033[1m\x1B[31mSorry you're client failed to sign the Transaction.\x1B[0m\033[0m\n\n");
            exit(0);
        }

        //Generate Packet (pc)
        const uint origin = 0;
        const size_t len = 1+sizeof(uint)+sizeof(uint64_t)+ECC_CURVE+1+ECC_CURVE+1+sizeof(mval)+ECC_CURVE+ECC_CURVE;
        char pc[MIN_LEN];
        pc[0] = 't';
        char* ofs = pc + 1;
        memcpy(ofs, &origin, sizeof(uint));
        ofs += sizeof(uint);
        memcpy(ofs, &t.uid, sizeof(uint64_t));
        ofs += sizeof(uint64_t);
        memcpy(ofs, from, ECC_CURVE+1);
        ofs += ECC_CURVE+1;
        memcpy(ofs, to, ECC_CURVE+1);
        ofs += ECC_CURVE+1;
        memcpy(ofs, &t.amount, sizeof(mval));
        ofs += sizeof(mval);
        memcpy(ofs, t.owner.key, ECC_CURVE*2);

        //Broadcast
        sendMaster(pc, len);
        peersBroadcast(pc, len);

        //Log
        char howner[MIN_LEN];
        memset(howner, 0, sizeof(howner));
        size_t zlen = MIN_LEN;
        b58enc(howner, &zlen, t.owner.key, ECC_CURVE);

        printf("\n\x1B[33mPacket Size: %lu. %u VFC. Sending Transaction...\x1B[0m\n", len, t.amount);
        printf("\033[1m\x1B[31m%s > %s : %u : %s\x1B[0m\033[0m\n", argv[1], argv[2], t.amount, howner);
        printf("\x1B[33mTransaction Sent.\x1B[0m\n\n");

    //Get balance again..
    sleep(6);
    const mval bal1 = getBalanceLocal(&t.from);
    setlocale(LC_NUMERIC, "");
    if(bal0-bal1 <= 0)
        printf("\033[1m\x1B[31mTransaction Failed. (If you have not got the full blockchain, it may have succeeded)\x1B[0m\033[0m\n\n");
    else
        printf("\x1B[33mVFC Sent: \x1B[0m%'u VFC\n\n", bal0-bal1);

        //Done
        exit(0);
    }

    //How did we get here?
    if(argc > 1)
    {
        //Looks like some unknown command was executed.
        printf("Command not recognised.\n");
        exit(0);
    }

    //Hijack CTRL+C
    signal(SIGINT, sigintHandler);
    
    //Launch Info
    timestamp();
    printf("\n\x1B[33mVFC - Very Fungible Cash\n");
    printf("https://VF.CASH - https://VFCASH.UK\n");
    printf("https://github.com/vfcash\n");
    printf("v%s\x1B[0m\n\n", version);
    printf("\x1B[33mYou will have to make a transaction before your IPv4 address registers\nwith the mainnet when running a full time node/daemon.\x1B[0m\n\n");
    printf("\x1B[33mTo get a full command list use:\x1B[0m\n ./coin help\n\n");

    //Launch the Transaction Processing thread
    pthread_t tid;
    pthread_create(&tid, NULL, processThread, NULL);
	
    //Sync Blocks
    resyncBlocks('s');
     
    //Loop, until sigterm
    while(1)
    {
        //Vars
        struct sockaddr_in server, client;
        uint slen = sizeof(client);

        //Create socket
        int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if(s == -1)
        {
            printf("\033[1m\x1B[31mFailed to create write socket ...\x1B[0m\033[0m\n");
            sleep(3);
            continue;
        }

        //Prepare the sockaddr_in structure
        server.sin_family = AF_INET;
        server.sin_addr.s_addr = INADDR_ANY;
        server.sin_port = htons(gport);
        
        //Bind port to socket
        if(bind(s, (struct sockaddr*)&server, sizeof(server)) < 0)
        {
            printf("\033[1m\x1B[31mSorry the port %u seems to already be in use. Daemon must already be running, good bye.\x1B[0m\033[0m\n\n", gport);
            exit(0);
        }
        printf("Waiting for connections...\n\n");

        //Never allow process to end
        uint reqs = 0;
        time_t st = time(0);
        time_t st0 = time(0);
        time_t tt = time(0);
        int read_size;
        char rb[RECV_BUFF_SIZE];
        uint rsi = 0;
        const uint trans_size = 1+sizeof(uint)+sizeof(uint64_t)+ECC_CURVE+1+ECC_CURVE+1+sizeof(mval)+ECC_CURVE+ECC_CURVE;
        const uint replay_size = 1+sizeof(uint64_t)+ECC_CURVE+1+ECC_CURVE+1+sizeof(mval)+ECC_CURVE+ECC_CURVE;
        while(1)
        {
            //Client Command
            memset(rb, 0, sizeof(rb));
            read_size = recvfrom(s, rb, RECV_BUFF_SIZE-1, 0, (struct sockaddr *)&client, &slen);

            //Are we the same node sending to itself, if so, ignore.
            if(server.sin_addr.s_addr == client.sin_addr.s_addr) //I know, this is very rarily ever effective. If ever.
                continue;

            //It's time to payout some rewards (if eligible).
#if MASTER_NODE == 1
            if(rb[0] == ' ')
            {
                RewardPeer(client.sin_addr.s_addr, rb); //Check if the peer is eligible
            }
#endif

            //Is this a [fresh trans / dead trans] ?
            else if((rb[0] == 't' || rb[0] == 'd') && read_size == trans_size)
            {
                //Root origin peer address
                uint origin = 0;

                //Decode packet into a Transaction & Origin
                struct trans t;
                memset(&t, 0, sizeof(struct trans));
                char* ofs = rb+1;
                memcpy(&origin, ofs, sizeof(uint)); //grab root origin address
                ofs += sizeof(uint);
                memcpy(&t.uid, ofs, sizeof(uint64_t)); //grab uid
                ofs += sizeof(uint64_t);
                memcpy(t.from.key, ofs, ECC_CURVE+1);
                ofs += ECC_CURVE+1;
                memcpy(t.to.key, ofs, ECC_CURVE+1);
                ofs += ECC_CURVE+1;
                memcpy(&t.amount, ofs, sizeof(mval));
                ofs += sizeof(mval);
                memcpy(t.owner.key, ofs, ECC_CURVE*2);

                //Process Transaction (Threaded (using processThread()) not to jam up UDP relay)
                if(aQue(&t, client.sin_addr.s_addr, origin, 1) == 1)
                {
                    //Broadcast to peers
                    origin = client.sin_addr.s_addr;
                    char pc[MIN_LEN];
                    pc[0] = 'd';
                    char* ofs = pc + 1;
                    memcpy(ofs, &origin, sizeof(uint));
                    ofs += sizeof(uint);
                    memcpy(ofs, &t.uid, sizeof(uint64_t));
                    ofs += sizeof(uint64_t);
                    memcpy(ofs, t.from.key, ECC_CURVE+1);
                    ofs += ECC_CURVE+1;
                    memcpy(ofs, t.to.key, ECC_CURVE+1);
                    ofs += ECC_CURVE+1;
                    memcpy(ofs, &t.amount, sizeof(mval));
                    ofs += sizeof(mval);
                    memcpy(ofs, t.owner.key, ECC_CURVE*2);
                    triBroadcast(pc, trans_size);
                }
                
                //Increment Requests
                reqs++;
            }

            //Request to replay all my blocks? (resync)
            else if(rb[0] == 'r' && read_size == 1)
            {
                //Is this peer even registered? if not, suspect foul play, not part of verified network.
                if(isPeer(client.sin_addr.s_addr) == 1)
                {
                    //Max threads limit; reset every x time period
                    if(threads < MAX_THREADS)
                    {
                        //Check that this IP is not currently being replayed to
                        uint cp = 1;
                        for(int i = 0; i < MAX_THREADS; i++)
                        {
                            if(thread_ip[i] == client.sin_addr.s_addr)
                            {
                                cp = 0;
                            }
                        }

                        //If not replay to peer
                        if(cp == 1)
                        {
                            pthread_t tid;
                            pthread_create(&tid, NULL, replayBlocksThread, &client.sin_addr.s_addr); //Threaded not to jam up UDP relay
                            thread_ip[threads] = client.sin_addr.s_addr;
                            threads++;
                        }
                    }

                    //Increment Requests
                    reqs++;
                }
            }

            //Request to replay all my blocks? (sync)
            else if(rb[0] == 's' && read_size == 1)
            {
                //Is this peer even registered? if not, suspect foul play, not part of verified network.
                if(isPeer(client.sin_addr.s_addr) == 1)
                {
                    //Max threads limit; reset every x time period
                    if(threads < MAX_THREADS)
                    {
                        //Check that this IP is not currently being replayed to
                        uint cp = 1;
                        for(int i = 0; i < MAX_THREADS; i++)
                        {
                            if(thread_ip[i] == client.sin_addr.s_addr)
                            {
                                cp = 0;
                            }
                        }

                        //If not replay to peer
                        if(cp == 1)
                        {
                            pthread_t tid;
                            if(qRand(0, 100) < 50)
                                pthread_create(&tid, NULL, replayBlocksThread, &client.sin_addr.s_addr); //Threaded not to jam up UDP relay
                            else
                                pthread_create(&tid, NULL, replayBlocksRevThread, &client.sin_addr.s_addr);
                            thread_ip[threads] = client.sin_addr.s_addr;
                            threads++;
                        }
                    }

                    //Increment Requests
                    reqs++;
                }
            }

            //Give up our user-agent
            else if(rb[0] == 'a' && rb[1] == 0x00 && read_size == 1)
            {
                //Check this is the replay peer
                if(isPeer(client.sin_addr.s_addr))
                {
                    struct stat st;
                    stat(CHAIN_FILE, &st);

                    struct utsname ud;
                    uname(&ud);

                    char pc[MIN_LEN];
                    snprintf(pc, sizeof(pc), "a%s, %u, %s, %s", version, (uint)st.st_size / 133, ud.nodename, ud.machine);

                    csend(client.sin_addr.s_addr, pc, strlen(pc));
                }
            }

            //Save user agent
            else if(rb[0] == 'a')
            {
                //Check this is a peer
                const int p = getPeer(client.sin_addr.s_addr);
                if(p != -1)
                {
                    memcpy(peer_ua[p], rb+1, 63);
                    peer_ua[p][63] = 0x00;
                }
            }

            //Replay peer is setting block height
            else if(rb[0] == 'h' && read_size == sizeof(uint)+1)
            {
                //Check this is the replay peer
                if(client.sin_addr.s_addr == replay_allow || isMasterNode(client.sin_addr.s_addr) == 1)
                {
                    memcpy(&replay_height, rb+1, sizeof(uint)); //Set the block height
                    FILE* f = fopen(".vfc/rph.mem", "w");
                    if(f)
                    {
                        fwrite(&replay_height, sizeof(uint), 1, f);
                        fclose(f);
                    }
                }
            }

            //Requesting address balance?
            else if(rb[0] == '$' && read_size == ECC_CURVE+2)
            {
                //Check this is the replay peer
                if(isPeer(client.sin_addr.s_addr) == 1)
                {
                    //Get balance for supplied address
                    addr from;
                    memcpy(from.key, rb+1, ECC_CURVE+1);
                    const mval bal = getBalanceLocal(&from);

                    //Send back balance for the supplied address
                    char pc[16];
                    pc[0] = 'n';
                    char* ofs = pc+1;
                    memcpy(ofs, &bal, sizeof(mval));
                    csend(client.sin_addr.s_addr, pc, 1+sizeof(mval));
                }
            }

            //Returned address balance
            else if(rb[0] == 'n' && read_size == sizeof(mval)+1)
            {
                //Check this is the replay peer
                const int p = getPeer(client.sin_addr.s_addr);
                if(p != -1)
                {
                    //Load the current state (check if the client process reset the log)
                    mval baln=0, balt=0;
                    FILE* f = fopen(".vfc/bal.mem", "r");
                    if(f)
                    {
                        if(fread(&baln, sizeof(mval), 1, f) != 1)
                            printf("\033[1m\x1B[31mbal.mem Corrupted. Load Failed.\x1B[0m\033[0m\n");
                        fclose(f);
                    }
                    f = fopen(".vfc/balt.mem", "r");
                    if(f)
                    {
                        if(fread(&balt, sizeof(mval), 1, f) != 1)
                            printf("\033[1m\x1B[31mbalt.mem Corrupted. Load Failed.\x1B[0m\033[0m\n");
                        fclose(f);
                    }

                    //Is it time to reset?
                    if(baln == 0)
                        balance_accumulator = 0;
                    if(balt == 0)
                        for(uint i = 0; i < MAX_PEERS; i++)
                            peer_ba[i] = 0;

                    //Log the new balances
                    mval bal = 0;
                    memcpy(&bal, rb+1, sizeof(mval));
                    peer_ba[p] = bal;
                    if(bal > balance_accumulator) //Update accumulator if higher balance returned
                        balance_accumulator = bal;

                    //And write
                    f = fopen(".vfc/bal.mem", "w");
                    if(f)
                    {
                        fwrite(&balance_accumulator, sizeof(mval), 1, f);
                        fclose(f);
                    }
                    f = fopen(".vfc/balt.mem", "w");
                    if(f)
                    {
                        const mval tb = trueBalance();
                        fwrite(&tb, sizeof(mval), 1, f);
                        fclose(f);
                    }

                }
            }

            //Is this a replay block?
            else if(rb[0] == 'p' && read_size == replay_size)
            {
                //This replay has to be from the specific trusted node, or the master. If it's a trusted node, we know it's also a peer so. All good.
                if(client.sin_addr.s_addr == replay_allow || isMasterNode(client.sin_addr.s_addr) == 1)
                {
                    //Decode packet into a Transaction
                    struct trans t;
                    memset(&t, 0, sizeof(struct trans));
                    char* ofs = rb+1;
                    memcpy(&t.uid, ofs, sizeof(uint64_t)); //grab uid
                    ofs += sizeof(uint64_t);
                    memcpy(t.from.key, ofs, ECC_CURVE+1);
                    ofs += ECC_CURVE+1;
                    memcpy(t.to.key, ofs, ECC_CURVE+1);
                    ofs += ECC_CURVE+1;
                    memcpy(&t.amount, ofs, sizeof(mval));
                    ofs += sizeof(mval);
                    memcpy(t.owner.key, ofs, ECC_CURVE*2);

                    //Alright process it, if it was a legitimate transaction we retain it in our chain.
                    aQue(&t, 0, 0, 0);
                    
                    //Increment Requests
                    reqs++;
                }
            }

            //Is some one looking for peers? We can tell them we exist, but that doesn't make them part of the network until they make a verified transaction
            else if(rb[0] == '\t' && read_size == sizeof(mid))
            {
                rb[0] = '\r';
                csend(client.sin_addr.s_addr, rb, read_size);
                addPeer(client.sin_addr.s_addr); //I didn't want to have to do this, but it's not the end of the world.

                //Increment Requests
                reqs++;
            }
            else if(rb[0] == '\r' && read_size == sizeof(mid))
            {
                if( rb[1] == mid[1] && //Only add as a peer if they responded with our private mid code
                    rb[2] == mid[2] &&
                    rb[3] == mid[3] &&
                    rb[4] == mid[4] &&
                    rb[5] == mid[5] &&
                    rb[6] == mid[6] &&
                    rb[7] == mid[7] )
                {
                    addPeer(client.sin_addr.s_addr);

                    //Increment Requests
                    reqs++;
                }
            }

            //Is the master requesting your rewards address?
            else if(rb[0] == 'x' && read_size == 1)
            {
                //Only the master can pay out rewards from the pre-mine
                if(isMasterNode(client.sin_addr.s_addr) == 1)
                    csend(client.sin_addr.s_addr, myrewardkey, strlen(myrewardkey));
            }

            //Check replay_allow value every three seconds
            if(time(0) > st0)
            {
                //Save memory state
                savemem();
                
                //Load new replay allow value
                f = fopen(".vfc/rp.mem", "r");
                if(f)
                {
                    if(fread(&replay_allow, sizeof(uint), 1, f) != 1)
                        printf("\033[1m\x1B[31mReplay Allow IP Corrupted. Load Failed.\x1B[0m\033[0m\n");
                    fclose(f);
                }

                //Next Loop
                st0 = time(0)+3;
            }

            //Log Requests per Second
            if(st < time(0))
            {
                //Log Metrics
                printf("\x1B[33mSTAT: Req/s: %ld, Peers: %u/%u, UDP Que: %u/%u, Threads %u/%u, Errors: %llu\x1B[0m\n", reqs / (time(0)-tt), countLivingPeers(), num_peers, gQueSize(), MAX_TRANS_QUEUE, threads, MAX_THREADS, err);

                //Let's execute a Sync every 3*60 mins (3hr)
                if(rsi >= 60)
                {
                    //Reset loop
                    rsi = 0;
                    
                    //Request a resync
                    resyncBlocks('s');
                }

                //Prep next loop
                rsi++;
                reqs = 0;
                tt = time(0);
                st = time(0)+180;
            }
        }
    }
    
    //Daemon
    return 0;
}
