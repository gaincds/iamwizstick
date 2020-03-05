#! /bin/bash

##############################
#####   KT WIZSTICK     ######
##############################
#
#
# 설명 : KT WIZSTICK 설치 자동화 스크립트 입니다. 
# 만든이 : dakccom@gmail.com (스타플랫폼)
#
# 설치 방법 : sudo ./setup.sh
# 설치 위치 : /home/ktwiz (권장)
# 웹 서버 실행 & 정지 : start.sh (실행) , stop.sh (정지) 
# 프로그램 환경 : python3, nginx, django, uwsgi, mysql 
#

install_path = "/home/ktwiz/"

if [ -e "setup.tar" ]
then


#sudo apt-get install wget -y
#wget https://repo.percona.com/apt/percona-release_0.1-4.$(lsb_release -sc)_all.deb
#dpkg -i percona-release_0.1-4.$(lsb_release -sc)_all.deb

#System update
sudo apt-get update -y
sudo apt-get dist-upgrade -y
sudo apt-get autoremove -y

#Python3 install
sudo apt-get install python3 -y
sudo apt-get install python3-pip -y
sudo apt-get install python2-pip -y

#nginx install
sudo apt-get install nginx -y
sudo apt-get install uwsgi -y
sudo apt-get install uwsgi-plugin-python3 -y
sudo apt-get install python-django -y
sudo apt-get install uwsgi-plugin-python -y

#MySql install
#sudo apt-get install mysql-server -y
#sudo apt-get install mysql-client-core-5.7 -y

#sudo systemctl status mysql.service

#sudo apt-get install percona-server-server-5.6 -y
#sudo apt-get install percona-xtradb-cluster-server-5.6 -y
#sudo apt-get remove apparmor -y
#sudo mysql_secure_installation
#sudo systemctl status mysql.service


sudo pip3 install --upgrade pip
#django python package install
sudo pip3 install django
sudo pip3 install django-cors-headers
sudo pip3 install pillow
sudo pip3 install user_agents
sudo pip3 install pycurl
sudo pip3 install --upgrade pycrypto
sudo pip3 install psutil
sudo pip3 install pybase64
sudo pip3 install xlsxwriter
sudo pip3 install xlrd
sudo pip3 install django-cors-headers

#python3 pyMysql install
sudo pip3 install PyMySQL



#setup.zip unzip & temp files delete
sudo tar xvf setup.tar
sudo rm -rf __MACOSC*


#chmod upload folder
sudo chmod -R 777 wizstick/wizstick/daemon

#configs setting
sudo cp -R wizstick/default.conf /etc/nginx/conf.d/
sudo cp -R wizstick/nginx.conf /etc/nginx/

installs[0]='Success'
for (( i = 0 ; i < ${#installs[@]} ; i++ )) ; do
    echo "${installs[$i]}"
done
       

else
    echo "Setup.tar File Not found."
fi
