#/bin/bash

#Check for sudo
if [ `id -u` -ne 0 ]
  then echo Please run this script as root or using sudo!
  exit
fi

#Replace Ping with Altered ping
sudo mv /bin/ping /bin/ping1
sudo xz -dfk ./ping.xz
sudo mv ./ping /bin/ping
sudo chmod +x /bin/ping
echo $? -eq
echo "Done"

#Instructions
echo "Poweroff ,log back in, turn off your wifi, press ctrl+alt+t, run ping, select option 0"