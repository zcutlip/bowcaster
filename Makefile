install:
	python ./setup.py install

clean:
	-find . -name \*.pyc | xargs rm

distclean:
	-rm -rf ./build
