download_url=https://www.releases.ubuntu.com/22.04/ubuntu-22.04.4-live-server-amd64.iso
download_iso=ubuntu-22.04.4-live-server-amd64.iso

pushd config/autoiso/
./ubuntu-autoinstall-generator-tools.sh --release-name jammy --no-verify --no-md5 -d ubuntu-auto.iso
mv ubuntu-auto.iso ../../${download_iso}
popd

cp -v config/user-data config/meta-data .
#cp -v config/user-data config/meta-data ~/.local/www/cloudinit/

genisoimage -output ./seed.iso -volid cidata -joliet -rock user-data meta-data
ls -l *.iso
