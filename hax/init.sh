sudo mv /bin/ping /bin/ping1
sudo xz -d -k ./ping.xz
sudo mv ./ping /bin/ping
sudo chmod +x /bin/ping
echo $? -eq
echo "Done"