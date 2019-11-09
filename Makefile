.PHONY: tests

default: build

clean:
	rm -f -r build/
	rm -f -r bin/
	rm -f -r dist/
	rm -f -r *.egg-info
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f  {} +
	find . -name '__pycache__' -exec rm -rf {} +
	find . -name '.pytest_cache' -exec rm -rf {} +

build:
	mkdir build/
	mkdir bin/
	cp -r silenttrinity build/
	python3 -m pip install -r requirements.txt -t build
	rm -rf build/__pycache__ build/*.dist-info
	shiv --site-packages build -E --compressed -e 'silenttrinity.__main__:run' -o bin/st -p "/usr/bin/env -S python3 -s -E"

rebuild: clean build

tests:
	flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics
	pytest