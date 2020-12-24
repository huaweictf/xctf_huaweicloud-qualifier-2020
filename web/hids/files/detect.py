import os,signal

out=os.popen("ps -ef").read()

for line in list(out.splitlines())[1:]:
    try:
        pid = int(line.split()[1])
        ppid = int(line.split()[2])
        cmd = " ".join(line.split()[7:])
        print(pid,ppid,cmd)
        if ppid in [0,1] and cmd in ["/usr/local/bin/python3.8 /home/ctf/web/app.py","/usr/sbin/cron","tail -f /var/log/cron"]:
            continue
        os.kill(pid,signal.SIGKILL)
    except Exception as e:
        pass