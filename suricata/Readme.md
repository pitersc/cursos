Guia para tener una debian funcionando con suricata, elasticsearch, logstash y kibana.


Guia para configurar suricata con ui web:

-Programas a utilizar:

	- Análisis previo
		Ref: http://pevma.blogspot.com.es/2013/12/suricata-and-grand-slam-of-open-source.html
	- Suricata (bajamos las fuentes y las compilamos según la guia de suricata)
		Ref: https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Debian_Installation
	- Oinkmaster (gestor de reglas)
		Ref: https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Rule_Management_with_Oinkmaster
	- Scirius (seguir la instalación de hillar)
		Ref: 
	- Elasticsearch (bajar paquete deb e instalar)
	- Logstash (bajar paquete deb e instalar)
	- Kibana (bajar paquete y templates para suricata)
		Ref: https://www.digitalocean.com/community/tutorials/how-to-install-elasticsearch-logstash-and-kibana-elk-stack-on-ubuntu-14-04
		Ref: https://www.elastic.co/guide/en/kibana/current/setup.html
	- Ngnix
	- Eveson


===============
ANALISIS PREVIO
===============

Instalar las siguientes herramientas para medir la carga de red a monitorizar:

	apt-get install ethtool bwm-ng iptraf tcpstat

	bwm-ng (pulsa h para ayuda después)

	tcpstat -i eth0  -o  "Time:%S\tn=%n\tavg=%a\tstddev=%d\tbps=%b\n"  1

	iptraf - mirar en "statistical breakdowns"->"detailed interface statistics" -> TCP/UDP port, packet size, luego ordenar con sort


	
====================
INSTALACION SURICATA
====================


Paquetes previos necesarios:

	apt-get -y install libpcre3 libpcre3-dbg libpcre3-dev build-essential autoconf automake libtool libpcap-dev libnet1-dev libyaml-0-2 libyaml-dev zlib1g zlib1g-dev libmagic-dev libcap-ng-dev libjansson-dev pkg-config libnetfilter-queue-dev libluajit-5.1-dev libjansson-dev pkg-config libcap-ng0 make libmagic-dev ethtool htp byacc flex libnuma-dev git
  	

Bajar las fuentes:

	a)
	wget http://www.openinfosecfoundation.org/download/suricata-3.0.tar.gz
	
	b)
	git clone git://phalanx.openinfosecfoundation.org/oisf.git
	cd oisf
	git clone https://github.com/OISF/libhtp.git -b 0.5.x
	./autogen.sh
	
	Para tener soporte pfring(ejecutar como usuario normal):

    git clone https://github.com/ntop/PF_RING.git
    cd PF_RING/kernel/
    make && sudo make install
    cd ../userland/lib
    ./configure --prefix=/usr/local/pfring && make && sudo make install
    cd ../libpcap
    ./configure --prefix=/usr/local/pfring && make && sudo make install
    cd ../tcpdump
    ./configure --prefix=/usr/local/pfring && make && sudo make install
    sudo ldconfig
    sudo modprobe pf_ring
    modinfo pf_ring && cat /proc/net/pf_ring/info

	
	
Configurar con las siguientes opciones:

	Sin soporte pfring:
	
	./configure --with-libhtp-libraries --enable-nfqueue --enable-profiling --enable-luajit --prefix=/usr --sysconfdir=/etc --localstatedir=/var 
	
	Con soporte pfring:
	
	./configure --with-libhtp-libraries --enable-pfring --enable-nfqueue --enable-profiling --enable-luajit --prefix=/usr --sysconfdir=/etc --localstatedir=/var --with-libpfring-includes=/usr/local/pfring/include --with-libpfring-libraries=/usr/local/pfring/lib --with-libpcap-includes=/usr/local/pfring/include --with-libpcap-libraries=/usr/local/pfring/lib 
	make
	make install-full
	ldconfig

Comprobar instalación:

	suricata --build-info
	suricata -V
	suricata -T -c /etc/suricata/suricata.yaml
	ethtool -k eth0

Establecer propiedades de la tarjeta:

	for i in rx tx sg tso ufo gso gro lro; do ethtool -K eth0 $i off; done

Arrancar suricata

	Modo nfqueue: /usr/bin/suricata -c /etc/suricata/suricata.yaml --pidfile /var/run/suricata.pid -q 0 -D -v
	Modo afpacket: /usr/bin/suricata -c /etc/suricata/suricata.yaml --pidfile /var/run/suricata.pid --af-packet -D -v
	Modo IDS: /usr/bin/suricata -c /etc/suricata/suricata.yaml --pidfile /var/run/suricata.pid -i eth0 -D -v 
	Modo pfring: /usr/bin/suricata -c /etc/suricata/suricata.yaml --pidfile /var/run/suricata.pid -D --pfring=eth0

Probar que salta alarma:

	curl -A "BlackSun" www.google.com
	
	Crear regla en local.rules:
	alert icmp any any -> any any ( msg: "ICMP packet detected!"; sid: 1; )

	Nota: poner tarjeta en promiscuo (ifconfig eth0 promisc)
	
	Reiniciar suricata para que recargue las rules:
	kill -USR2 $(pidof suricata)


=================
GESTOR OINKMASTER
=================

Poner en /etc/oinkmaster.conf el origen de las reglas:

url = http://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz

Actualizar las reglas

oinkmaster -C /etc/oinkmaster.conf -o /etc/suricata/rules

Poner en suricata.yaml el path del classification-file y del reference-config-file:

classification-file: /etc/suricata/rules/classification.config
reference-config-file: /etc/suricata/rules/reference.config

Para habilitar y deshabilitar reglas directamente a través de oinkmaster:

disablesid 2010495
enablesid: 2010495,sid2,sid3...


================
VISOR EN CONSOLA
================

Ver eve.json en modo comandos:
http://jasonish-suricata.readthedocs.org/en/latest/output/eve/eve-json-examplesjq.html

tail -f eve.json | jq -c '.'
cat eve.json | jq -s '[.[]|.http.http_user_agent]|group_by(.)|map({key:.[0],value:(.|length)})|from_entries'

tail -n500000 eve.json | jq -s 'map(select(.event_type=="netflow" and .dest_ip=="192.168.1.3").netflow.bytes)|add'|numfmt --to=iec

tail -f eve.json | jq -c 'select(.event_type=="stats")|.stats.decoder'

cat eve.json | jq -r -c 'select(.event_type=="alert")|.payload'|base64 --decode

cat eve.json | jq -c 'select(.event_type=="flow")|[.proto, .dest_port]'|sort |uniq -c|sort -nr|head -n10


================
VISOR WEB EVEBOX
================

Necesitamos instalar elasticsearch(2.0 o superior) y logstash previamente

Elasticsearch
=============
apt-get install -y openjdk-7-jre-headless
wget https://download.elasticsearch.org/elasticsearch/release/org/elasticsearch/distribution/deb/elasticsearch/2.2.0/elasticsearch-2.2.0.deb
dpkg -i 

/usr/share/elasticsearch/bin/plugin install mobz/elasticsearch-head
/usr/share/elasticsearch/bin/plugin install delete-by-query
echo "network.host: 0.0.0.0" >> /etc/elasticsearch/elasticsearch.yml
service elasticsearch restart

Comprobar que funciona con el plugin que viene por defecto:
http://IPSERVER:9200/_plugin/head/


Comprobar los indices:

curl -XGET localhost:9200/_cat/indices


Manejar indices con el plugin kopf:

Ir al directorio donde está el ejecutable de elasticsearch (whereis elasticsearch)

bin/plugin install lmenezes/elasticsearch-kopf

http://IPSERVER:9200/_plugin/kopf/



Logstash
========

wget https://download.elastic.co/logstash/logstash/packages/debian/logstash_2.2.2-1_all.deb
dpkg -i

Crear fichero logstash.conf en /etc/logstash/conf.d/logstash.conf


input {
  file {
    path => ["/var/log/suricata/eve.json"]
    #sincedb_path => ["/var/lib/logstash/"]
    codec =>   json
    type => "SuricataIDPS"
  }

}

filter {
  if [type] == "SuricataIDPS" {
    date {
      match => [ "timestamp", "ISO8601" ]
    }
    ruby {
      code => "if event['event_type'] == 'fileinfo'; event['fileinfo']['type']=event['fileinfo']['magic'].to_s.split(',')[0]; end;"
    }
  }

  if [src_ip]  {
    geoip {
      source => "src_ip"
      target => "geoip"
      #database => "/opt/logstash/vendor/geoip/GeoLiteCity.dat"
      add_field => [ "[geoip][coordinates]", "%{[geoip][longitude]}" ]
      add_field => [ "[geoip][coordinates]", "%{[geoip][latitude]}"  ]
    }
    mutate {
      convert => [ "[geoip][coordinates]", "float" ]
    }
    if ![geoip.ip] {
      if [dest_ip]  {
        geoip {
          source => "dest_ip"
          target => "geoip"
          #database => "/opt/logstash/vendor/geoip/GeoLiteCity.dat"
          add_field => [ "[geoip][coordinates]", "%{[geoip][longitude]}" ]
          add_field => [ "[geoip][coordinates]", "%{[geoip][latitude]}"  ]
        }
        mutate {
          convert => [ "[geoip][coordinates]", "float" ]
        }
      }
    }
  }
}

output {
  elasticsearch {
    hosts => localhost
    #protocol => http
  }
}



echo "127.0.0.1 elasticsearch" >> /etc/hosts
service logstash start

Probar que el archivo de configuración está bien:

/etc/init.d/logstash configtest


Dar permisos correctos al archivo /var/log/suricata/eve.json
chown root:adm eve.json

En /etc/init.d/logstash cambiar el grupo a adm en vez de logstash


EVEBOX
======

apt-get -y install unzip
cd /opt/
wget -q https://bintray.com/artifact/download/jasonish/evebox/evebox-linux-amd64.zip
unzip evebox-linux-amd64.zip
./evebox-linux-amd64/evebox --version
echo "http.cors.enabled: true" >> /etc/elasticsearch/elasticsearch.yml
echo "http.cors.allow-origin: \"/.*/\"" >> /etc/elasticsearch/elasticsearch.yml
service elasticsearch restart
/opt/evebox-linux-amd64/evebox > /var/log/evebox.log 2>&1 &

Corre en el puerto 5636

KIBANA
======

wget https://download.elastic.co/kibana/kibana/kibana-4.4.1-linux-x64.tar.gz

wget -qO - https://packages.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb http://packages.elastic.co/kibana/4.4/debian stable main" | sudo tee -a /etc/apt/sources.list.d/kibana-4.4.x.list
apt-get install kibana

vi /opt/kibana/config/kibana.yml

Poner:

server.host: "127.0.0.1"

Templates de kibana para suricata:

git clone https://github.com/pevma/Suricata-Logstash-Templates



NGNIX
=====

apt-get install nginx apache2-utils
htpasswd -c /etc/nginx/htpasswd.users admin

vi /etc/nginx/sites-available/default

    server {
        listen 80;

        server_name IPdetuHOST;

        auth_basic "Restricted Access";
        auth_basic_user_file /etc/nginx/htpasswd.users;

        location / {
            proxy_pass http://localhost:5601;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection 'upgrade';
            proxy_set_header Host $host;
            proxy_cache_bypass $http_upgrade;        
        }
    }


Crear indice y a rular



=================
OTRAS REFERENCIAS
=================

http://www.ntop.org/pf_ring/port-mirror-vs-network-tap/



