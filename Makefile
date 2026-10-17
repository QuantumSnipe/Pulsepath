.PHONY: start stop restart run test check update-references

start:
	./start.command

stop:
	./stop.command

restart:
	./stop.command
	./start.command

run:
	python3 pulsepath.py --no-open

test:
	python3 -m unittest discover -s tests -v

update-references:
	python3 install_references.py

check: test
	python3 -m py_compile pulsepath.py behavior.py references.py install_geoip.py install_references.py
	node -e "const fs=require('fs'); const h=fs.readFileSync('index.html','utf8'); new Function(h.split('<script>')[1].split('</script>')[0]);"
