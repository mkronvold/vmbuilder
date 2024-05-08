#!/bin/bash

[ ${1} ] && name=$1 || name=host
while [ -e user-data-source.${name} ];
do
  echo "post-install.$name found"
  post64=$(cat post-install.${name} | base64 -w 0)
  echo "  - echo \"${post64}\" | base64 -d > /target/install-maas.sh" > post64.${name}
#  cat user-data-source.${name} | sed -e "s/hostname:\ local01/hostname:\ ${node}/g" > user-data-source.${name}.out
  cat post64.${name} >> user-data-source.${name}
  cat post64.${name}
  echo emacs user-data-source.${name}
  name=
done
