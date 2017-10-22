#!/bin/sh

set -e

now=`date +%Y%m%d-%H%M%S`

mv /var/log/nginx/access.log.ltsv /var/log/nginx/access.log.ltsv.$now
systemctl reload nginx

# mv /var/log/mysql/slow.log /var/log/mysql/slow.log.$now
# mysqladmin -uisucon -pisucon flush-logs

systemctl restart isubata.nodejs.service
