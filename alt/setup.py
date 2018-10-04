import os
import shutil
from setuptools import setup

files = [
    '../interlex/__init__.py',
    '../interlex/alt.py',
    '../interlex/alt_server.py',
    '../interlex/config.py',
    '../interlex/core.py',
    '../interlex/dump.py',
    '../interlex/exc.py',
    '../interlex/namespaces.py',
    '../interlex/render.py',
    '../interlex/utils.py',
]

try:
    cleanup = []
    os.mkdir('interlex')
    for f in files:
        if '../' in f:
            cpfile = f.replace('../','')
            shutil.copyfile(f, cpfile)
            cleanup.append(cpfile)

    setup(name='InterLex Alt',
          version='0.0.1',
          description='Serialize InterLex records',
          long_description=' ',
          url='https://github.com/tgbugs/interlex',
          author='Tom Gillespie',
          author_email='tgbugs@gmail.com',
          license='MIT',
          classifiers=[],
          keywords='probably dont use this',
          packages=['interlex'],
          install_requires=[
              'flask',
              'flask_sqlalchemy',
              'gevent',
              'gunicorn',
              'neurdflib-jsonld',
              'pyontutils',
          ],
          extras_require={'dev':[]},
          scripts=['../bin/interlex-alt'],
          entry_points={
              'console_scripts': [ ],
          },
    )
finally:
    for f in cleanup:
        os.remove(f)

    os.rmdir('interlex')
