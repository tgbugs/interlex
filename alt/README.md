# Instructions
1. Install `python3.6`, `pip` and `pipenv`.
2. Build the package and install to create Pipfile.lock for sanity.
*NOTE* while this is correct in principle, for some reason on some
systems, gunicorn does not get pulled in if it is on the system.
In that cased skip the pipenv install step and generate the lock
on the server.
```bash
python setup.py bdist_wheel --universal &&
pipenv install
```
3. Compress this directory.
```bash
cd ../
zip -r alt.zip alt
```
4. scp the zip to the server.
5. ssh to the server and run the following.
```bash
unzip alt.zip
cd alt/run &&
pipenv install &&
pipenv shell
interlex-alt
```
