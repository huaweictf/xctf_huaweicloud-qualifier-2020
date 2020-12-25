FROM python:3.6-alpine

LABEL Author="b1ind"

ENV FLASK_APP=app.py FLASK_ENV=production

COPY app /app

RUN adduser -h /app b1ind -D && \
	sed -i 's/dl-cdn.alpinelinux.org/mirror.tuna.tsinghua.edu.cn/g' /etc/apk/repositories && \
	apk update && \
	pip install \
	-i http://mirrors.aliyun.com/pypi/simple/ \
	--trusted-host mirrors.aliyun.com \
	-r /app/requirements.txt && \
	mv /app/docker-entrypoint /usr/local/bin/docker-entrypoint && \
	chmod +x /usr/local/bin/docker-entrypoint && \
	chmod 755 -R /app

WORKDIR /app

ENTRYPOINT ["/usr/local/bin/docker-entrypoint"]
