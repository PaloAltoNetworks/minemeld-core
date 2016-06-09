#!/bin/bash

apt-get -fy install
apt-get update
apt-key update
apt-get -y install libc-ares2 libsnappy1 librabbitmq1 libleveldb1
