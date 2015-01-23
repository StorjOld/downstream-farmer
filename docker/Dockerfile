# Builds a docker image for https://github.com/Storj/downstream-farmer

FROM debian:wheezy
MAINTAINER Storj - http://storj.io/ - https://github.com/Storj

# installs dependencies, builds farmer, removes unneeded dependencies to keep the image small
RUN buildDeps='git build-essential python-pip'; \
	pythonDeps='python-dev libcrypto++-dev libgmp-dev python-pkg-resources'; \
	set -x \
	&& apt-get update && apt-get install -y $buildDeps $pythonDeps --no-install-recommends \
	&& pip install downstream-farmer \
	&& apt-get purge -y --auto-remove $buildDeps

# when running, assume working path for farmer has been mounted from the host system at this location
WORKDIR /downstream

CMD ["downstream"]
