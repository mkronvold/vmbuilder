#!/bin/bash

outpath=./seeds/

i=1
[ ${1} ] && name=$1 || name=host
if [ -e user-data-source.${name} ]; then
  i=1
  echo "user-data-source.$name found"
else
  i=10
  echo "user-data-source.$name not found"
fi

while [ $i -le 10 ];
do
  node=${name}${i}
  userdata=user-data-${node}
  metadata=meta-data-${node}
  if [ -e meta-data-source.${name} ]; then
    metadatasource=meta-data-source.${name}
  else
    metadatasource=meta-data-source
  fi
  outfile=seed-${node}.iso
  cat user-data-source.${name} | sed -e "s/hostname:\ local01/hostname:\ ${node}/g" > user-data
  cat ${metadatasource} | sed -e "s/hostname:\ local01/hostname:\ ${node}/g" -e "s/iid-local01/iid-${node}/g" > meta-data
  genisoimage -output ${outpath}/${outfile} -volid cidata -joliet -rock user-data meta-data
  let i++
done

rm -f user-data meta-data
ls -l ${outpath}/seed-${name}*.iso
