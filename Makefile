
default:	build

clean:
	rm -rf Makefile objs

build:
	$(MAKE) -f objs/Makefile

install:
	$(MAKE) -f objs/Makefile install

modules:
	$(MAKE) -f objs/Makefile modules

upgrade:
	/home/pierre/Desktop/unikernel-fork/experiments/nginx/nginx/../prefix/sbin/nginx -t

	kill -USR2 `cat /home/pierre/Desktop/unikernel-fork/experiments/nginx/nginx/../prefix/logs/nginx.pid`
	sleep 1
	test -f /home/pierre/Desktop/unikernel-fork/experiments/nginx/nginx/../prefix/logs/nginx.pid.oldbin

	kill -QUIT `cat /home/pierre/Desktop/unikernel-fork/experiments/nginx/nginx/../prefix/logs/nginx.pid.oldbin`
