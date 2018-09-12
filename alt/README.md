# InterLex Alt
This is a reduced set of the InterLex codebase for serving directly
from the mysql database. The necessary subset of the code that is needed
is copied into this directory and installed from the main interlex source.

# Instructions
1. Install `python3.6`, `pip` and `pipenv`.
2. Build the package ~~and install to create Pipfile.lock for sanity~~
and compress this folder for deployment.
```bash
sed -ir "s/{interlex-user}/${INTERLX_USER}" deploy_files
grep -rl interlex deploy_files/ | xargs sed -i "s/{interlex-user}/${INTERLEX_USER}/g"
python setup.py bdist_wheel --universal &&
python setup.py clean --all &&
#pipenv install  # leave this out for now due to gunicorn detection issues
cd ../
rm alt.zip;
zip -r alt.zip alt/run/ &&
zip -r alt.zip alt/dist/ &&
zip -r alt.zip alt/deploy_files/
scp alt.zip ${INTERLEX_SERVER}:
```
4. ssh to the server and run the following or run the following via ssh.
* First time.
```bash
unzip alt.zip
sudo su root  # or similar
cp alt/deploy_files/etc/systemd/system/ilxalt.service /etc/systemd/system/
cp alt/deploy_files/etc/systemd/system/ilxalt.socket /etc/systemd/system/
cp alt/deploy_files/etc/tmpfiles.d/ilxalt.conf /etc/tmpfiles.d/
cp alt/deploy_files/etc/nginx/sites-available/uri.interlex.org.conf /etc/nginx/sites-available/ # carful here
ln -s /etc/nginx/sites-available/uri.interlex.org.conf /etc/nginx/sites-enabled/uri.interlex.org.conf
systemd-tmpfiles --create
systemctl enable ilxalt
exit
cd alt/run &&
pipenv install &&
cd ~/ &&
touch .mypass &&
chmod 0600 .mypass &&
vi .mypass && # add an entry according to the pattern described below
sudo systemctl start ilxalt
```
* Other times.
```bash
sudo systemctl stop ilxalt
rm -rf alt.old/
mv alt/ alt.old
unzip -o alt.zip
cd alt/run &&
pipenv --rm &&
pipenv install &&
sudo systemctl start ilxalt
```
5. Make sure you create a `~/.mypass` file that conforms to the syntax of `~/.pgpass`
i.e. each line should look like `server.url.org:port:dbname:user:password` and should
have read write permission only for your user (`chmod 0600`).
