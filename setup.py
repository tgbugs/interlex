import re
from pathlib import Path
from setuptools import setup


def find_version(filename):
    _version_re = re.compile(r"__version__ = '(.*)'")
    for line in open(filename):
        version_match = _version_re.match(line)
        if version_match:
            return version_match.group(1)


__version__ = find_version('interlex/__init__.py')

with open('README.md', 'rt') as f:
    long_description = f.read()

alt_require = ['mysql-connector', 'pymysql']
tests_require = ['pytest',] + alt_require
setup(name='interlex',
      version=__version__,
      description='A terminology management system.',
      long_description=long_description,
      long_description_content_type='text/markdown',
      url='https://github.com/tgbugs/interlex',
      author='Tom Gillespie',
      author_email='tgbugs@gmail.com',
      license='MIT',
      classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Programming Language :: Python :: 3.13',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Operating System :: POSIX :: Linux',
      ],
      keywords='interlex neurolex lexicon quadstore rdf owl linked-data terminology vocabulary',
      packages=['interlex'],
      python_requires='>=3.7',
      tests_require=tests_require,
      install_requires=[
          'argon2-cffi',
          'celery',
          'flask',
          'flask-login',
          'flask-restx',
          'flask_sqlalchemy',
          'orthauth',
          'rdflib>=6.0.2',
          "psycopg2; implementation_name != 'pypy'",
          "psycopg2cffi; implementation_name == 'pypy'",
          'PyJWT',
          'pyontutils>=0.1.38',
      ],
      extras_require={'dev': alt_require,
                      'elasticsearch': ['elasticsearch'],
                      'test': tests_require,
                     },
      scripts=['bin/interlex-uri', 'bin/interlex-curies', 'bin/interlex-dbsetup'],
      entry_points={
          'console_scripts': [
              'interlex=interlex.cli:main',
          ],
      },
      data_files=[('share/interlex/sql', [f.as_posix() for f in Path('sql').iterdir()]),
                  ('share/interlex/resources', [
                      f'resources/{f}' for f in
                      ('reserved-usernames-len-gt-4.txt',)]),
                  ('share/interlex/test', [f.as_posix() for f in Path('test').iterdir()
                                           if not f.is_dir()]),
                  ('share/interlex/test/data', [f.as_posix() for f in Path('test/data').iterdir()]),
                  ]  # FIXME package_data
     )
