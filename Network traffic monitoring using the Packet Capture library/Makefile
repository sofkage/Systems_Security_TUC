all: monitor

monitor: monitor.c 
	gcc monitor.c -o monitor -lpcap

run: monitor
	./monitor

clean:
	rm -rf monitor