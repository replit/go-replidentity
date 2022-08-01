#!/bin/bash

# Get the codecov uploader, verify integrity
curl --max-time 30 https://keybase.io/codecovsecurity/pgp_keys.asc | gpg --no-default-keyring --keyring trustedkeys.gpg --import # One-time step

curl -Ov https://uploader.codecov.io/latest/linux/codecov
curl -Ov https://uploader.codecov.io/latest/linux/codecov.SHA256SUM
curl -Ov https://uploader.codecov.io/latest/linux/codecov.SHA256SUM.sig
gpgv codecov.SHA256SUM.sig codecov.SHA256SUM
shasum -a 256 -c codecov.SHA256SUM

# Make sure codecov doesn't turn this into an unclean checkout
rm -f codecov.SHA256SUM.sig codecov.SHA256SUM
chmod +x codecov
sudo mv codecov /usr/bin/