all: rotate-all app-deploy

.PHONY: rotate-all
rotate-all: rotate-access-log rotate-slow-log

.PHONY: rotate-access-log
rotate-access-log:
	echo "Rotating access log"
	sudo mv /var/log/nginx/access.ndjson /var/log/nginx/access.ndjson.$(shell date +%Y%m%d)
	sudo systemctl restart nginx

.PHONY: rotate-slow-log
rotate-slow-log:
	echo "Rotating slow log"
	sudo mv /var/log/mysql/mysql-slow.log /var/log/mysql/mysql-slow.log.$(shell date +%Y%m%d)
	sudo systemctl restart mysql

.PHONY: alp
alp:
	alp json --config alp-config.yml

.PHONY: pt
pt:
	sudo pt-query-digest /var/log/mysql/mysql-slow.log

.PHONY: conf-deploy
conf-deploy: nginx-conf-deploy mysql-conf-deploy

.PHONY: nginx-conf-deploy
nginx-conf-deploy:
	echo "nginx conf deploy"
	sudo cp -r etc/nginx/* /etc/nginx
	sudo nginx -t
	sudo systemctl restart nginx

.PHONY: mysql-conf-deploy
mysql-conf-deploy:
	echo "mysql conf deploy"
	sudo cp -r etc/mysql/* /etc/mysql
	sudo systemctl restart mysql

.PHONY: app-deploy
app-deploy:
	echo "app deploy"
	cd /home/isucon/private_isu/webapp/golang && make
	sudo systemctl restart isu-go

.PHONY: pprof
pprof:
	go tool pprof -seconds 60 -http=localhost:1080 http://localhost:6060/debug/pprof/profile
