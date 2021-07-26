FROM keppel.eu-de-1.cloud.sap/ccloud-dockerhub-mirror/library/centos:7.6.1810

# install Python with respective dependencies
RUN echo "===> Adding Python and respective packages..."  && \
    yum -y update && \
    yum -y install epel-release && \
    yum -y install python36 python36-pip  && \
    yum -y install libffi-devel openssl-devel python-devel python36-devel libxml2-devel libxslt libxslt-devel kernel-devel openldap-devel git gcc make unzip bzip2-devel && \
    pip3 install --upgrade pip setuptools virtualenv==16.7.9 gnureadline

# compile and install Python 3.7
RUN echo "===> Compiling and installing python3.7" && \
    cd /usr/local/src && \
    curl https://www.python.org/ftp/python/3.7.4/Python-3.7.4.tgz --output Python-3.7.4.tgz && \
    tar xzf Python-3.7.4.tgz && \
    cd Python-3.7.4 && \
    ./configure --enable-optimizations && \
    make altinstall && \
    rm /usr/local/src/Python-3.7.4.tgz && rm -rf /usr/local/src/Python-3.7.4

RUN echo "===> Installing handy tools... "  && \
    yum install -y sshpass openssh-clients rsync openssl p7zip ca-certificates wget jq p7zip-plugins

# Cleanup
RUN echo "===> Clean cached installation files and deleting requirements" && \
    yum clean all && \
    rm -rf /var/cache/yum

# install Robot framework
RUN echo "===> Adding Robot framework..."  && \
    pip3 install --upgrade robotframework==4.1 robotframework-sshlibrary robotframework-pabot

ENTRYPOINT [ "/bin/bash" ]
