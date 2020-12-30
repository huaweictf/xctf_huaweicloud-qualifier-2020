1. 
```bash
docker build -t "game_pwn" . (注意最后的点)
```

2. 
```bash
docker run -d -p "0.0.0.0:pub_port:9999" -h "game_pwn" --name="game_pwn" game_pwn 
```

`pub_port` 替换成你想要开放给选手的端口

