#!/bin/bash

# Install necessary packages
apt install gnupg2 software-properties-common curl wget git unzip -y

# Add repository for Apache2
add-apt-repository ppa:ondrej/apache2 -y
apt update -y

# Install Apache2 and ModSecurity
apt install apache2 -y
apt install libapache2-mod-security2 -y

# Enable security module
a2enmod security2

# Move and edit modsecurity.conf
mv /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf

# Enable ModSecurity in the Apache configuration
sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf

# Restart Apache service
service apache2 restart

# Download and extract Core Rule Set
wget https://github.com/coreruleset/coreruleset/archive/v3.3.0.tar.gz
tar xvf v3.3.0.tar.gz
mkdir /etc/apache2/modsecurity-crs/
mv coreruleset-3.3.0/ /etc/apache2/modsecurity-crs

# Navigate to Core Rule Set directory and configure
cd /etc/apache2/modsecurity-crs/coreruleset-3.3.0/
mv crs-setup.conf.example crs-setup.conf

# Include the necessary Core Rule Set configurations
echo "IncludeOptional /etc/apache2/modsecurity-crs/coreruleset-3.3.0/crs-setup.conf" >> /etc/apache2/mods-enabled/security2.conf
echo "IncludeOptional /etc/apache2/modsecurity-crs/coreruleset-3.3.0/rules/*.conf" >> /etc/apache2/mods-enabled/security2.conf

# Test Apache configuration
apache2ctl -t

# Install curl
apt-get install curl -y

# Test ModSecurity installation
#curl http://localhost/index.html?exec=/bin/bash

# Check ModSecurity audit log
#tail /var/log/apache2/modsec_audit.log
