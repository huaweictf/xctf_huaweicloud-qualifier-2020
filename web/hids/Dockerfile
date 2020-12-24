FROM python:3.8.6
ADD flag /flag
ADD web /home/ctf/web
RUN chmod -R a+r /home/ctf/web
RUN chmod 400 /flag

ADD files/readflag.c /readflag.c
RUN gcc /readflag.c -o /readflag
RUN rm -rf /readflag.c
RUN chmod +x /readflag
RUN chmod +s /readflag

RUN pip3 install flask -i https://mirrors.aliyun.com/pypi/simple/
ADD files/detect.py /detect.py
COPY files/sources.list /etc/apt/sources.list
RUN cat /etc/apt/sources.list
RUN rm -Rf /var/lib/apt/lists/*
RUN apt-get update
RUN apt-get install -y --no-install-recommends cron
COPY files/pam.d /etc/pam.d/cron
RUN echo "*/1 * * * * root /usr/local/bin/python3.8 /detect.py" > /etc/crontab
RUN echo "*/5 * * * * root rm -rf /tmp/*" >> /etc/crontab
RUN echo "*/1 * * * * ctf nohup /usr/local/bin/python3.8 /home/ctf/web/app.py &" >> /etc/crontab

# 添加用户
RUN groupadd -r ctf && useradd -r -g ctf ctf

USER root
# 运行app.py
# ENTRYPOINT /usr/sbin/cron && runuser -u ctf /usr/local/bin/python3.8 /home/ctf/web/app.py
RUN touch /var/log/cron
ENTRYPOINT /usr/sbin/cron && tail -f /var/log/cron
EXPOSE 5000