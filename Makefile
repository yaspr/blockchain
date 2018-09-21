all:
	gcc -std=c99 blockchain.c -o blockchain -lyhash -L/root/Code/yhash/
run:
	LD_LIBRARY_PATH=/root/Code/yhash/ ./blockchain
