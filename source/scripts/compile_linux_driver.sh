cd ../drivers/linux
rmmod chipsec
chmod 775 run.sh
set -e
echo "Calling make"
make
echo "Calling make install"
make install
cd ../../scripts