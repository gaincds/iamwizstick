* 우분투 서버 설치
<pre>
sudo sed -i 's/kr.archive.ubuntu.com/ftp.daumkakao.com/g' /etc/apt/sources.list

vi /etc/apt/sources.list

:%s/kr.archive.ubuntu.com/ftp.daumkakao.com/
:%s/security.ubuntu.com/ftp.daumkakao.com/

:%s/kr.archive.ubuntu.com/ftp.neowiz.com/
:%s/security.ubuntu.com/ftp.neowiz.com/

sudo sed 's/kr.archive.ubuntu.com/ftp.daumkakao.com/g' /etc/apt/sources.list
</pre>
* python 최신버전 업데이트
** 버전업
<pre>
sudo add-apt-repository ppa:jonathonf/python-2.7
sudo apt-get update
sudo apt-get install python2.7
python --version
</pre>
** 모듈추가 
<pre>
wget https://repo.percona.com/apt/percona-release_0.1-4.$(lsb_release -sc)_all.deb
dpkg -i percona-release_0.1-4.$(lsb_release -sc)_all.deb
sudo apt-get update -y
sudo apt-get dist-upgrade -y
sudo apt-get autoremove -y

sudo apt-get install iptables-persistent
sudo apt-get install wget -y
sudo apt-get install git -y
sudo apt-get install python -y
sudo apt-get install python-dev -y
sudo apt-get install python-pip -y
sudo apt-get install python-qt4 -y
sudo apt-get install libmysqlclient-dev -y
sudo apt-get install python-m2crypto -y
sudo apt-get install python-pycurl -y
sudo apt-get install redis-server -y
sudo apt-get install libffi-dev libssl-dev libxml2-dev libxslt1-dev libjpeg8-dev zlib1g-dev -y
apt-get install lrzsz -y
apt-get install ntp -y
apt-get install fail2ban -y 
apt-get install python-daemon -y


sudo pip install --upgrade pip
sudo pip install twisted
sudo pip install PyCrypto
sudo pip install MySQL-python
sudo pip install pybase64
sudo pip install asn1crypto
sudo pip install gevent
sudo pip install sqlalchemy
sudo pip install Pillow
sudo pip install redis
sudo pip install mmh3
sudo pip install pyping
sudo pip install rdpy (첨부파일 다운로드)
git clone https://github.com/AGProjects/python-cjson.git
cd python-cjson
python setup.py install
cd ../
git clone https://github.com/jruere/multiprocessing-logging.git
cd multiprocessing-logging
python setup.py install
cd ../

sudo apt-get install percona-server-server-5.6 -y
sudo apt-get remove apparmor -y
sudo apt-get install percona-xtradb-cluster-server-5.6 -y

#elasticsearch 설치
sudo add-apt-repository ppa:webupd8team/java
sudo apt-get update
sudo apt-get install oracle-java8-installer
wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-6.2.1.deb
dpkg -i elasticsearch-6.2.1.deb

#logstash 설치
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
sudo apt-get install apt-transport-https
echo "deb https://artifacts.elastic.co/packages/5.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-5.x.list
sudo apt-get update && sudo apt-get install logstash


# 실행시 문제 인코딩 문제
export LC_ALL="en_US.UTF-8"

git clone http://128.134.101.135:60007/gaincds/WEB-iamwizstick.git
</pre>
*** elasticsearch
**** /usr/share/elasticsearch/
**** /etc/elasticsearch/
**** /etc/init.d/elasticsearch
*** twisted
*** PyCrypto
*** MySQLdb
*** https://github.com/ldx/python-iptables
*** https://github.com/mayeut/pybase64 (pip install pybase64)
*** asn1crypto
*** cjson
*** M2Crypto
*** gevent
*** pycurl
*** sqlalchemy
*** https://github.com/MarkLodato/vt100-parser
*** sudo apt-get install python-qt4
*** pip install rdpy
*** pip install Pillow
*** opencv
**** https://raw.githubusercontent.com/milq/milq/master/scripts/bash/install-opencv.sh

<pre>
######################################
# INSTALL OPENCV ON UBUNTU OR DEBIAN #
######################################

# |         THIS SCRIPT IS TESTED CORRECTLY ON         |
# |----------------------------------------------------|
# | OS             | OpenCV       | Test | Last test   |
# |----------------|--------------|------|-------------|
# | Ubuntu 16.04.2 | OpenCV 3.2.0 | OK   | 20 May 2017 |
# | Debian 8.8     | OpenCV 3.2.0 | OK   | 20 May 2017 |
# | Debian 9.0     | OpenCV 3.2.0 | OK   | 25 Jun 2017 |

# 1. KEEP UBUNTU OR DEBIAN UP TO DATE

sudo apt-get -y update
sudo apt-get -y upgrade
sudo apt-get -y dist-upgrade
sudo apt-get -y autoremove


# 2. INSTALL THE DEPENDENCIES

# Build tools:
sudo apt-get install -y build-essential cmake

# GUI (if you want to use GTK instead of Qt, replace 'qt5-default' with 'libgtkglext1-dev' and remove '-DWITH_QT=ON' option in CMake):
sudo apt-get install -y qt5-default libvtk6-dev

# Media I/O:
sudo apt-get install -y zlib1g-dev libjpeg-dev libwebp-dev libpng-dev libtiff5-dev libjasper-dev libopenexr-dev libgdal-dev

# Video I/O:
sudo apt-get install -y libdc1394-22-dev libavcodec-dev libavformat-dev libswscale-dev libtheora-dev libvorbis-dev libxvidcore-dev libx264-dev yasm libopencore-amrnb-dev libopencore-amrwb-dev libv4l-dev libxine2-dev

# Parallelism and linear algebra libraries:
sudo apt-get install -y libtbb-dev libeigen3-dev

# Python:
sudo apt-get install -y python-dev python-tk python-numpy python3-dev python3-tk python3-numpy

# Java:
sudo apt-get install -y ant default-jdk

# Documentation:
sudo apt-get install -y doxygen


# 3. INSTALL THE LIBRARY (YOU CAN CHANGE '3.2.0' FOR THE LAST STABLE VERSION)

sudo apt-get install -y unzip wget
wget https://github.com/opencv/opencv/archive/3.2.0.zip
unzip 3.2.0.zip
rm 3.2.0.zip
mv opencv-3.2.0 OpenCV
cd OpenCV
mkdir build
cd build
cmake -DWITH_QT=ON -DWITH_OPENGL=ON -DFORCE_VTK=ON -DWITH_TBB=ON -DWITH_GDAL=ON -DWITH_XINE=ON -DBUILD_EXAMPLES=ON -DENABLE_PRECOMPILED_HEADERS=OFF ..
make -j4
sudo make install
sudo ldconfig


# 4. EXECUTE SOME OPENCV EXAMPLES AND COMPILE A DEMONSTRATION

# To complete this step, please visit 'http://milq.github.io/install-opencv-ubuntu-debian'.
</pre>

* nginx
** fast cgi 설정
* mysql
** https://www.percona.com
*** wget https://repo.percona.com/apt/percona-release_0.1-4.$(lsb_release -sc)_all.deb
*** dpkg -i percona-release_0.1-4.$(lsb_release -sc)_all.deb
*** sudo apt-get update
** apt-get install percona-server-server-5.6
** sudo apt-get remove apparmor
** apt-get install percona-xtradb-cluster-server-5.6
** https://www.percona.com/doc/percona-xtradb-cluster/LATEST/howtos/ubuntu_howto.html
<pre>
Configuring Percona XtraDB Cluster on Ubuntu
This tutorial describes how to install and configure three Percona XtraDB Cluster nodes on Ubuntu 12.04.2 LTS servers, using the packages from Percona repositories.

Node 1
Host name: pxc1
IP address: 192.168.70.61
Node 2
Host name: pxc2
IP address: 192.168.70.62
Node 3
Host name: pxc3
IP address: 192.168.70.63
Prerequisites
The procedure described in this tutorial requires he following:

All three nodes have Ubuntu 12.04.2 LTS installed.
Firewall on all nodes is configured to allow connecting to ports 3306, 4444, 4567 and 4568.
AppArmor profile for MySQL is disabled.
Step 1. Installing PXC
Install Percona XtraDB Cluster on all three nodes as described in Installing Percona XtraDB Cluster on Debian or Ubuntu.

Note

Debian/Ubuntu installation prompts for root password. For this tutorial, set it to Passw0rd. After the packages have been installed, mysqld will start automatically. Stop mysqld on all three nodes using /etc/init.d/mysql stop.
Step 2. Configuring the first node
Individual nodes should be configured to be able to bootstrap the cluster. For more information about bootstrapping the cluster, see Bootstrapping the First Node.

Make sure that the configuration file /etc/mysql/my.cnf for the first node (pxc1) contains the following:

[mysqld]

datadir=/var/lib/mysql
user=mysql

# Path to Galera library
wsrep_provider=/usr/lib/libgalera_smm.so

# Cluster connection URL contains the IPs of node#1, node#2 and node#3
wsrep_cluster_address=gcomm://192.168.70.61,192.168.70.62,192.168.70.63

# In order for Galera to work correctly binlog format should be ROW
binlog_format=ROW

# MyISAM storage engine has only experimental support
default_storage_engine=InnoDB

# This InnoDB autoincrement locking mode is a requirement for Galera
innodb_autoinc_lock_mode=2

# Node #1 address
wsrep_node_address=192.168.70.61

# SST method
wsrep_sst_method=xtrabackup-v2

# Cluster name
wsrep_cluster_name=my_ubuntu_cluster

# Authentication for SST method
wsrep_sst_auth="sstuser:s3cretPass"
Start the first node with the following command:

[root@pxc1 ~]# /etc/init.d/mysql bootstrap-pxc
This command will start the first node and bootstrap the cluster.
After the first node has been started, cluster status can be checked with the following command:

mysql> show status like 'wsrep%';
+----------------------------+--------------------------------------+
| Variable_name              | Value                                |
+----------------------------+--------------------------------------+
| wsrep_local_state_uuid     | b598af3e-ace3-11e2-0800-3e90eb9cd5d3 |
...
| wsrep_local_state          | 4                                    |
| wsrep_local_state_comment  | Synced                               |
...
| wsrep_cluster_size         | 1                                    |
| wsrep_cluster_status       | Primary                              |
| wsrep_connected            | ON                                   |
...
| wsrep_ready                | ON                                   |
+----------------------------+--------------------------------------+
40 rows in set (0.01 sec)
This output shows that the cluster has been successfully bootstrapped.
To perform State Snapshot Transfer using XtraBackup, set up a new user with proper privileges:

mysql@pxc1> CREATE USER 'sstuser'@'localhost' IDENTIFIED BY 's3cretPass';
mysql@pxc1> GRANT PROCESS, RELOAD, LOCK TABLES, REPLICATION CLIENT ON *.* TO 'sstuser'@'localhost';
mysql@pxc1> FLUSH PRIVILEGES;
Note

MySQL root account can also be used for performing SST, but it is more secure to use a different (non-root) user for this.
Step 3. Configuring the second node
Make sure that the configuration file /etc/mysql/my.cnf on the second node (pxc2) contains the following:

[mysqld]

datadir=/var/lib/mysql
user=mysql

# Path to Galera library
wsrep_provider=/usr/lib/libgalera_smm.so

# Cluster connection URL contains IPs of node#1, node#2 and node#3
wsrep_cluster_address=gcomm://192.168.70.61,192.168.70.62,192.168.70.63

# In order for Galera to work correctly binlog format should be ROW
binlog_format=ROW

# MyISAM storage engine has only experimental support
default_storage_engine=InnoDB

# This InnoDB autoincrement locking mode is a requirement for Galera
innodb_autoinc_lock_mode=2

# Node #2 address
wsrep_node_address=192.168.70.62

# Cluster name
wsrep_cluster_name=my_ubuntu_cluster

# SST method
wsrep_sst_method=xtrabackup-v2

#Authentication for SST method
wsrep_sst_auth="sstuser:s3cretPass"
Start the second node with the following command:

[root@pxc2 ~]# /etc/init.d/mysql start
After the server has been started, it should receive SST automatically. Cluster status can now be checked on both nodes. The following is an example of status from the second node (pxc2):

mysql> show status like 'wsrep%';
+----------------------------+--------------------------------------+
| Variable_name              | Value                                |
+----------------------------+--------------------------------------+
| wsrep_local_state_uuid     | b598af3e-ace3-11e2-0800-3e90eb9cd5d3 |
...
| wsrep_local_state          | 4                                    |
| wsrep_local_state_comment  | Synced                               |
...
| wsrep_cluster_size         | 2                                    |
| wsrep_cluster_status       | Primary                              |
| wsrep_connected            | ON                                   |
...
| wsrep_ready                | ON                                   |
+----------------------------+--------------------------------------+
40 rows in set (0.01 sec)
This output shows that the new node has been successfully added to the cluster.
Step 4. Configuring the third node
Make sure that the MySQL configuration file /etc/mysql/my.cnf on the third node (pxc3) contains the following:

[mysqld]

datadir=/var/lib/mysql
user=mysql

# Path to Galera library
wsrep_provider=/usr/lib/libgalera_smm.so

# Cluster connection URL contains IPs of node#1, node#2 and node#3
wsrep_cluster_address=gcomm://192.168.70.61,192.168.70.62,192.168.70.63

# In order for Galera to work correctly binlog format should be ROW
binlog_format=ROW

# MyISAM storage engine has only experimental support
default_storage_engine=InnoDB

# This InnoDB autoincrement locking mode is a requirement for Galera
innodb_autoinc_lock_mode=2

# Node #3 address
wsrep_node_address=192.168.70.63

# Cluster name
wsrep_cluster_name=my_ubuntu_cluster

# SST method
wsrep_sst_method=xtrabackup-v2

#Authentication for SST method
wsrep_sst_auth="sstuser:s3cretPass"
Start the third node with the following command:

[root@pxc3 ~]# /etc/init.d/mysql start
After the server has been started, it should receive SST automatically. Cluster status can be checked on all nodes. The following is an example of status from the third node (pxc3):

mysql> show status like 'wsrep%';
+----------------------------+--------------------------------------+
| Variable_name              | Value                                |
+----------------------------+--------------------------------------+
| wsrep_local_state_uuid     | b598af3e-ace3-11e2-0800-3e90eb9cd5d3 |
...
| wsrep_local_state          | 4                                    |
| wsrep_local_state_comment  | Synced                               |
...
| wsrep_cluster_size         | 3                                    |
| wsrep_cluster_status       | Primary                              |
| wsrep_connected            | ON                                   |
...
| wsrep_ready                | ON                                   |
+----------------------------+--------------------------------------+
40 rows in set (0.01 sec)
This output confirms that the third node has joined the cluster.
Testing replication
To test replication, lets create a new database on the second node, create a table for that database on the third node, and add some records to the table on the first node.

Create a new database on the second node:

mysql@pxc2> CREATE DATABASE percona;
Query OK, 1 row affected (0.01 sec)
Create a table on the third node:

mysql@pxc3> USE percona;
Database changed

mysql@pxc3> CREATE TABLE example (node_id INT PRIMARY KEY, node_name VARCHAR(30));
Query OK, 0 rows affected (0.05 sec)
Insert records on the first node:

mysql@pxc1> INSERT INTO percona.example VALUES (1, 'percona1');
Query OK, 1 row affected (0.02 sec)
Retrieve all the rows from that table on the second node:

mysql@pxc2> SELECT * FROM percona.example;
+---------+-----------+
| node_id | node_name |
+---------+-----------+
|       1 | percona1  |
+---------+-----------+
1 row in set (0.00 sec)
This simple procedure should ensure that all nodes in the cluster are synchronized and working as intended.
</pre>
** ====
** sudo apt-get install percona-server-server-5.7
** https://www.percona.com/doc/percona-repo-config/apt-repo.html
** https://www.youtube.com/watch?v=604FgTguDfE
*** sudo apt-get remove apparmor
*** apt-get install percona-xtradb-cluster-full-57
** 기타 최적화

