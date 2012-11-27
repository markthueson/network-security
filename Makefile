all:
	./waf configure -p
	./waf build -p
	./waf install -p

clean:
	./waf uninstall -p
	./waf clean -p
	./waf distclean -p

mesh:
	./waf configure -p --32
	./waf build  -p --32
	./waf install -p --32
