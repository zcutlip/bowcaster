install:
	python ./setup.py install

clean:
	-find . -name \*.pyc | xargs rm

distclean: clean
	-rm -rf ./build
