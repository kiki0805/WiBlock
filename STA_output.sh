#!/bin/bash
testPath="./bareSSIDs"  
testFile="./bareBSSs"  

if [[ -e "$testPath" ]]; then  
    rm $testPath
fi

if [[ -e "$testFile" ]]; then  
    rm $testFile
fi


iw dev wlp3s0 scan > available_wifi
sed -n "/SSID/p" available_wifi > SSIDs
touch bareSSIDs
while read line 
do
  new_line=${line:6}
  echo $new_line >> bareSSIDs
done < SSIDs


sed -n "/^BSS/p" available_wifi > BSSs
touch bareBSSs
while read line 
do
  new_line=${line:3:18}
  echo $new_line >> bareBSSs
done < BSSs

rm "available_wifi"
rm "bareBSSs"
rm "bareSSIDs"


# iw wlp3s0 connect MyEssid
