#!/bin/bash
url=$1


for file in /usr/share/wordlists/*
do
    if [[ -d $file ]]; then

    elif [[ -f $file ]];tjem
        echo $file
    fi
    #xargs dirsearch.py -u 
done

for file in /usr/share/seclists/*
do
    echo $file
    #whatever you need with "$file"
done