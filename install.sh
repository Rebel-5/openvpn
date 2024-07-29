#!/bin/bash

function installOpenVPN() {
    PORT="1194"
    PROTOCOL="udp"
    CIPHER="AES-128-GCM"
    CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"
    HMAC_ALG="SHA256"
    CLIENT="client"

	NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
	if [[ ! -e /etc/openvpn/server.conf ]]; then
        apt-get update
        apt-get -y install ca-certificates gnupg
        apt-get install -y openvpn iptables openssl wget ca-certificates curl
		if [[ -d /etc/openvpn/easy-rsa/ ]]; then
			rm -rf /etc/openvpn/easy-rsa/
		fi
	fi

	if [[ ! -d /etc/openvpn/easy-rsa/ ]]; then
		local version="3.1.2"
		wget -O ~/easy-rsa.tgz https://github.com/OpenVPN/easy-rsa/releases/download/v${version}/EasyRSA-${version}.tgz
		mkdir -p /etc/openvpn/easy-rsa
		tar xzf ~/easy-rsa.tgz --strip-components=1 --no-same-owner --directory /etc/openvpn/easy-rsa
		rm -f ~/easy-rsa.tgz
		cd /etc/openvpn/easy-rsa/ || return
        echo "set_var EASYRSA_ALGO ec" >vars
        echo "set_var EASYRSA_CURVE prime256v1" >>vars

		SERVER_CN="cn_$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)"
		echo "$SERVER_CN" >SERVER_CN_GENERATED
		SERVER_NAME="server_$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)"
		echo "$SERVER_NAME" >SERVER_NAME_GENERATED

		./easyrsa init-pki
		EASYRSA_CA_EXPIRE=3650 ./easyrsa --batch --req-cn="$SERVER_CN" build-ca nopass

		EASYRSA_CERT_EXPIRE=3650 ./easyrsa --batch build-server-full "$SERVER_NAME" nopass
		EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl

		openvpn --genkey --secret /etc/openvpn/tls-crypt.key
		
	else
		cd /etc/openvpn/easy-rsa/ || return
		SERVER_NAME=$(cat SERVER_NAME_GENERATED)
	fi

	cp pki/ca.crt pki/private/ca.key "pki/issued/$SERVER_NAME.crt" "pki/private/$SERVER_NAME.key" /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn
	chmod 644 /etc/openvpn/crl.pem

	echo "port $PORT" >/etc/openvpn/server.conf
	echo "proto $PROTOCOL" >>/etc/openvpn/server.conf
	echo "dev tun
user nobody
group nogroup
persist-key
persist-tun
keepalive 10 120
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt" >>/etc/openvpn/server.conf

    echo 'push "dhcp-option DNS 8.8.8.8"' >>/etc/openvpn/server.conf
    echo 'push "dhcp-option DNS 8.8.4.4"' >>/etc/openvpn/server.conf
    echo 'push "redirect-gateway def1 bypass-dhcp"' >>/etc/openvpn/server.conf
    echo "dh none" >>/etc/openvpn/server.conf
    echo "ecdh-curve prime256v1" >>/etc/openvpn/server.conf
	echo "tls-crypt tls-crypt.key" >>/etc/openvpn/server.conf
	echo "crl-verify crl.pem
ca ca.crt
cert $SERVER_NAME.crt
key $SERVER_NAME.key
auth $HMAC_ALG
cipher $CIPHER
ncp-ciphers $CIPHER
tls-server
tls-version-min 1.2
tls-cipher $CC_CIPHER
client-config-dir /etc/openvpn/ccd
status /var/log/openvpn/status.log
verb 3
management localhost 7505
client-config-dir /etc/openvpn/ccd" >>/etc/openvpn/server.conf

	mkdir -p /etc/openvpn/ccd
	mkdir -p /var/log/openvpn
	echo 'net.ipv4.ip_forward=1' >/etc/sysctl.d/99-openvpn.conf
	sysctl --system
    cp /lib/systemd/system/openvpn\@.service /etc/systemd/system/openvpn\@.service
    sed -i 's|LimitNPROC|#LimitNPROC|' /etc/systemd/system/openvpn\@.service
    sed -i 's|/etc/openvpn/server|/etc/openvpn|' /etc/systemd/system/openvpn\@.service
    systemctl daemon-reload
    systemctl enable openvpn@server
    systemctl restart openvpn@server
	mkdir -p /etc/iptables
	echo "#!/bin/sh
iptables -t nat -I POSTROUTING 1 -s 10.8.0.0/24 -o $NIC -j MASQUERADE
iptables -I INPUT 1 -i tun0 -j ACCEPT
iptables -I FORWARD 1 -i $NIC -o tun0 -j ACCEPT
iptables -I FORWARD 1 -i tun0 -o $NIC -j ACCEPT
iptables -I INPUT 1 -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >/etc/iptables/add-openvpn-rules.sh
	echo "#!/bin/sh
iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o $NIC -j MASQUERADE
iptables -D INPUT -i tun0 -j ACCEPT
iptables -D FORWARD -i $NIC -o tun0 -j ACCEPT
iptables -D FORWARD -i tun0 -o $NIC -j ACCEPT
iptables -D INPUT -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >/etc/iptables/rm-openvpn-rules.sh

	chmod +x /etc/iptables/add-openvpn-rules.sh
	chmod +x /etc/iptables/rm-openvpn-rules.sh
	echo "[Unit]
Description=iptables rules for OpenVPN
Before=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/etc/iptables/add-openvpn-rules.sh
ExecStop=/etc/iptables/rm-openvpn-rules.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target" >/etc/systemd/system/iptables-openvpn.service

	systemctl daemon-reload
	systemctl enable iptables-openvpn
	systemctl start iptables-openvpn
	IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | head -1)
	echo "client" >/etc/openvpn/client-template.txt
    echo "proto udp" >>/etc/openvpn/client-template.txt
    echo "explicit-exit-notify" >>/etc/openvpn/client-template.txt
	echo "remote $IP $PORT
dev tun
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
verify-x509-name $SERVER_NAME name
auth $HMAC_ALG
auth-nocache
cipher $CIPHER
tls-client
tls-version-min 1.2
tls-cipher $CC_CIPHER
ignore-unknown-option block-outside-dns
setenv opt block-outside-dns # Prevent Windows 10 DNS leak
verb 3" >>/etc/openvpn/client-template.txt

	newClient
}

function newClient() {
    cd /etc/openvpn/easy-rsa/ || return
    EASYRSA_CERT_EXPIRE=3650 ./easyrsa --batch build-client-full "$CLIENT" nopass
    echo "Client $CLIENT added."

	cp /etc/openvpn/client-template.txt "/root/$CLIENT.ovpn"
	{
		echo "<ca>"
		cat "/etc/openvpn/easy-rsa/pki/ca.crt"
		echo "</ca>"

		echo "<cert>"
		awk '/BEGIN/,/END CERTIFICATE/' "/etc/openvpn/easy-rsa/pki/issued/$CLIENT.crt"
		echo "</cert>"

		echo "<key>"
		cat "/etc/openvpn/easy-rsa/pki/private/$CLIENT.key"
		echo "</key>"

        echo "<tls-crypt>"
        cat /etc/openvpn/tls-crypt.key
        echo "</tls-crypt>"
		
	} >>"/root/$CLIENT.ovpn"

	echo ""
	echo "The configuration file has been written to /root/$CLIENT.ovpn."
	echo "Download the .ovpn file and import it in your OpenVPN client."

	exit 0
}


installOpenVPN
