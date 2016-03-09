###Método para instalar bro con ELK en Debian 8

Ref:
* https://www.bro.org/sphinx/install/install.html
* https://www.bro.org/sphinx/quickstart/index.html
* http://knowm.org/integrate-bro-ids-with-elk-stack/
* http://knowm.org/how-to-install-bro-network-security-monitor-on-ubuntu/
* https://www.bro.org/sphinx/script-reference/index.html
* http://try.bro.org/#/trybro?example=hello


#####1 Instalar los paquetes que necesita:

> apt-get install cmake make gcc g++ flex bison libpcap-dev libssl-dev python-dev swig zlib1g-dev libgeoip-dev libmagic-dev



#####2 Instalar con el paquete de debian:

> apt-cache search broctl

Si existe en el repositorio actual, no hace falta poner esto:

> echo 'deb http://download.opensuse.org/repositories/network:/bro/Debian_8.0/ /' >> /etc/apt/sources.list.d/bro.list  
> wget -q0 - http://download.opensuse.org/repositories/network:bro/Debian_8.0/Release.key | apt-key add -  
> apt-get update  
> apt-get install bro broctl  



#####3 Compilar desde el código fuente:

> wget https://www.bro.org/downloads/release/bro-2.4.1.tar.gz  
 o  
git clone --recursive git://git.bro.org/bro  


#####4 Configura la variable path

> export PATH=/usr/local/bro/bin:$PATH  
o  
export PATH=/opt/bro/bin:$PATH  

#####5 Configurar Bro

Le decimos la tarjeta que vamos a monitorizar en /etc/bro/node.cfg
Le decimos el rango de IP a monitorizar en /etc/bro/networks.cfg
Configuraos el mailing y el log en /etc/bro/broctl.cfg

Esto no  hace falta ponerlo, lo puse para pruebas mias:
echo "@load tuning/json-logs" >> /etc/bro/site/local.bro
echo "redef LogAscii::json_timestamps = JSON::TS_ISO8601;" >> /etc/bro/site/local.bro

#####6 Instalar y arrancar bro

> broctl  
install  
exit

Puedes añadir /usr/bin/broctl start a /etc/rc.local

Para ejecutarlo:
> broctl start  


#####7 Instalar plugin necesarios en logstash:

> cd /opt/logstash  
bin/plugin install logstash-filter-translate  
bin/plugin install logstash-filter-de_dot


#####8 Descargar archivos de configuración para logstash del bro:

https://github.com/timmolter/logstash-dfir/blob/master/conf_files

Adaptar los archivos de configuración de logstash a nuestro entorno:

> sed -i -e 's/\/nsm\/bro\/logs\/current\//\/var\/log\/bro\//g' /etc/logstash/conf.d/bro*.conf  
sed -i -e 's,host => localhost,hosts => "'${ELASTIC}'"\n index => "bro-%{+YYYY.MM.dd.HH}",g' /etc/logstash/conf.d/bro*.conf  
sed -i -e '/date/i \ \ \ \ \de_dot{ }' /etc/logstash/conf.d/bro*.conf


#####9 Comprobar configuracion de logstash:

> sudo -u logstash /opt/logstash/bin/logstash agent -f /etc/logstash/conf.d --configtest


#####10 Comprobar ejecución en consola:

> sudo -u logstash /opt/logstash/bin/logstash -f /etc/logstash/conf.d --debug

