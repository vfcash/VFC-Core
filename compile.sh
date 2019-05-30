clear
clear
rm coin
sudo rm /usr/bin/coin
gcc -pthread base58.c crc64.c ecc.c sha3.c main.c -o coin
sudo cp coin /usr/bin/coin
