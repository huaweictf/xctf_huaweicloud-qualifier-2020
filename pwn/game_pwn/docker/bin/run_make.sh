gcc -fno-stack-protector -o /tmp/aeg_yeah_dir/$1.bin /tmp/aeg_yeah_dir/$1.c
#rm /tmp/aeg_yeah_dir/$1.c 
strip /tmp/aeg_yeah_dir/$1.bin