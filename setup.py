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

tests_require = ['pytest', 'pytest-runner']
setup(name='InterLex',
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
      ],
      keywords='interlex neurolex lexicon quadstore rdf owl linked-data',
      packages=['interlex'],
      python_requires='>=3.7',
      tests_require=tests_require,
      install_requires=[
          'celery',
          'elasticsearch',
          'flask',
          'flask-restx',
          'flask_sqlalchemy',
          "psycopg2; implementation_name != 'pypy'",
          "psycopg2cffi; implementation_name == 'pypy'",
          'rdflib-jsonld>=0.5.0',
          'pyontutils>=0.1.27',
      ],
      extras_require={'dev': ['mysql-connector'],
                      'test': tests_require,
                     },
      scripts=['bin/interlex-uri', 'bin/interlex-curies', 'bin/interlex-dbsetup'],
      entry_points={
          'console_scripts': [
              'interlex=interlex.cli:main',
          ],
      },
      data_files=[('share/interlex/sql', [f.as_posix() for f in Path('sql').iterdir()])]  # FIXME package_data
     )
