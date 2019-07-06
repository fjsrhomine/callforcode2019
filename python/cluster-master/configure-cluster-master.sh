#!/bin/bash

#homine-unks

#This script is to get the latest changes on the cluster-master folder
sudo wget https://raw.githubusercontent.com/fjsrhomine/callforcode2019/master/python/cluster-master/cluster.py -O cluster.py

#This enables the SSH-AGENT to allow the connectivity without typing the password everytime
eval $(ssh-agent) 
ssh-add ~/.ssh/id_rsa_rojo 