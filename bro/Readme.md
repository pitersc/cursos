###Método para instalar bro con ELK en Debian 8

Ref:
* https://www.bro.org/sphinx/install/install.html
* https://www.bro.org/sphinx/quickstart/index.html
* http://knowm.org/integrate-bro-ids-with-elk-stack/
* http://knowm.org/how-to-install-bro-network-security-monitor-on-ubuntu/
* https://www.bro.org/sphinx/script-reference/index.html
* http://try.bro.org/#/trybro?example=hello


#####1 Instalar los paquetes que necesita:
```
apt-get install cmake make gcc g++ flex bison libpcap-dev libssl-dev python-dev swig zlib1g-dev libgeoip-dev libmagic-dev
```


#####2 Instalar con el paquete de debian:
```
apt-cache search broctl
```
Si existe en el repositorio actual, no hace falta poner esto:
```
echo 'deb http://download.opensuse.org/repositories/network:/bro/Debian_8.0/ /' >> /etc/apt/sources.list.d/bro.list  
wget -q0 - http://download.opensuse.org/repositories/network:bro/Debian_8.0/Release.key | apt-key add -  
```
Instalamos el paquete:
```
apt-get update  
apt-get install bro broctl  
```


#####3 Compilar desde el código fuente:
```
wget https://www.bro.org/downloads/release/bro-2.4.1.tar.gz  
 o  
git clone --recursive git://git.bro.org/bro  
```

#####4 Configura la variable path
```
export PATH=/usr/local/bro/bin:$PATH  
o  
export PATH=/opt/bro/bin:$PATH  
```
#####5 Configurar Bro

Le decimos la tarjeta que vamos a monitorizar en /etc/bro/node.cfg  
Le decimos el rango de IP a monitorizar en /etc/bro/networks.cfg  
Configuraos el mailing y el log en /etc/bro/broctl.cfg

Esto no  hace falta ponerlo, lo puse para pruebas mias:
```
echo "@load tuning/json-logs" >> /etc/bro/site/local.bro  
echo "redef LogAscii::json_timestamps = JSON::TS_ISO8601;" >> /etc/bro/site/local.bro
```
#####6 Instalar y arrancar bro
```
broctl  
install  
exit
```
Puedes añadir /usr/bin/broctl start a /etc/rc.local

Para ejecutarlo:
```
broctl start  
```

#####7 Instalar plugin necesarios en logstash:
```
cd /opt/logstash  
bin/plugin install logstash-filter-translate  
bin/plugin install logstash-filter-de_dot
```

#####8 Descargar archivos de configuración para logstash del bro:

https://github.com/timmolter/logstash-dfir/blob/master/conf_files

Adaptar los archivos de configuración de logstash a nuestro entorno:
```
sed -i -e 's/\/nsm\/bro\/logs\/current\//\/var\/log\/bro\//g' /etc/logstash/conf.d/bro*.conf  
sed -i -e 's,host => localhost,hosts => "'${IPELASTIC}'"\n index => "bro-%{+YYYY.MM.dd.HH}",g' /etc/logstash/conf.d/bro*.conf  
sed -i -e '/date/i \ \ \ \ \de_dot{ }' /etc/logstash/conf.d/bro*.conf
```

#####9 Comprobar configuracion de logstash:
```
sudo -u logstash /opt/logstash/bin/logstash agent -f /etc/logstash/conf.d --configtest
o
/etc/init.d/logstash configtest
```

#####10 Comprobar ejecución en consola:
```
sudo -u logstash /opt/logstash/bin/logstash -f /etc/logstash/conf.d --debug
```
#####11 Puertos

Elasticsearch: 9200  
Kibana: 5601  
Grafana: 3000  
Influxdb: 8083,8086  


#####12 Manejo logs de bro

https://www.bro.org/bro-workshop-2011/solutions/logs/index.html
```
cat conn.log | bro-cut id.orig_h id.orig_p id.resp_h duration

awk '/^[^#]/ {print $3, $4, $5, $6, $9}' conn.log

/opt/bro/bin/bro-cut host uri < http.log | awk '{ print $1$2 }'

awk '$3 == "1.2.3.4" || $5 == "1.2.3.4"' conn.log
```
Ej1: List the connections by in increasing order of duration, i.e., the longest connections at the end.
```
awk 'NR > 4' < conn.log | sort -t$'\t' -k 9 -n
```
Ej2: Find all connections that are last longer than one minute.
```
awk 'NR > 4 && $9 > 60' conn.log
```

Ej3: Find all IP addresses of web servers that send more than more than 1 KB back to a client.
```
/opt/bro/bin/bro-cut service resp_bytes id.resp_h < conn.log | awk '$1 == "http" && $2 > 1000000 { print $3 }' | sort -u
```

Ej4: Are there any web servers on non-standard ports (i.e., 80 and 8080)?
```
/opt/bro/bin/bro-cut service id.resp_p id.resp_h < conn.log | awk '$1 == "http" && ! ($2 == 80 || $2 == 8080) { print $3 }' | sort -u
```

Ej5: Show a breakdown of the number of connections by service.
```
/opt/bro/bin/bro-cut service < conn.log | sort | uniq -c | sort -n
```

Ej6: Show the top 10 destination ports in descending order.
```
/opt/bro/bin/bro-cut id.resp_p < conn.log | sort | uniq -c | sort -rn | head -n 10
```

Ej7: What are the distinct browsers in this trace? What are the distinct MIME types of the downloaded URLS?
```
/opt/bro/bin/bro-cut user_agent < http.log | sort -u
/opt/bro/bin/bro-cut mime_type < http.log | sort -u
```

#####13 Notice en bro

https://www.bro.org/bro-workshop-2011/exercises/notices/index.html
