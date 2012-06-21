#!/bin/sh
git clone https://github.com/termie/shred
curl http://pypi.python.org/packages/source/R/Routes/Routes-1.13.tar.gz | tar -xvz
curl http://pypi.python.org/packages/source/r/repoze.lru/repoze.lru-0.5.tar.gz | tar -xvz
curl http://pypi.python.org/packages/source/p/passlib/passlib-1.6.tar.gz | tar -xvz
curl http://pypi.python.org/packages/source/S/SQLAlchemy/SQLAlchemy-0.7.8.tar.gz | tar -xvz
mv SQLAlchemy-0.7.8/lib/sqlalchemy SQLAlchemy-0.7.8/sqlalchemy
