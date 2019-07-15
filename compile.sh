clear
clear
pkill coin
pkill vfc
rm coin
rm vfc
rm /usr/bin/coin
rm /usr/bin/vfc
gcc -pthread base58.c crc64.c ecc.c sha3.c main.c -lm -o vfc
cp vfc /usr/bin/vfc
chmod 0777 /usr/bin/vfc

crontab -l > ncron
if grep -qxF '* * * * * /usr/bin/vfc' ncron; then
    echo "Cron Exists";
else
    echo "* * * * * /usr/bin/vfc" >> ncron
    echo "Cron Added";
fi
crontab ncron
rm ncron

echo "Compiled and Installed /usr/bin/vfc and /srv/.vfc or ~/.vfc "
echo "vfc help"
