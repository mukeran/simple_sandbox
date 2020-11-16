FROM php:7.2.24-fpm

RUN sed -i s@/deb.debian.org/@/mirrors.tuna.tsinghua.edu.cn/@g /etc/apt/sources.list
RUN sed -i s@/security.debian.org/@/mirrors.tuna.tsinghua.edu.cn/@g /etc/apt/sources.list
RUN apt-get update && apt-get install -y python3 python3-requests python3-flask

COPY php_sandbox/ /root/php_sandbox/
RUN docker-php-ext-configure /root/php_sandbox && docker-php-ext-install /root/php_sandbox
RUN rm -rf /root/php_sandbox

COPY proxy.py /proxy.py
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh
ENTRYPOINT [ "/docker-entrypoint.sh" ]