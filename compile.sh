clear
clear
rm coin
sudo rm /usr/bin/coin
gcc -pthread base58.c crc64.c ecc.c sha3.c main.c -o coin
sudo cp coin /usr/bin/coin
sudo chmod 0777 /usr/bin/coin
sudo mkdir /var/log/vfc
sudo chmod 0777 /var/log/vfc
