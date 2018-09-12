# Instructions
1. Install `python3.6`, `pip` and `pipenv`.
2. Build the package.
```bash
python setup.py bdist_wheel --universal &&
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
