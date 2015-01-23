Docker image for Downstream Farmer

Usage
===
1. If you've never used Docker before. Check out the installation and basic usage guides and videos [here](https://docs.docker.com/installation/).

2. Pull the Docker image:
```docker pull storj/downstream-farmer```

3. In your Farmer directory (on your Docker host), create file ```data/identities.json``` per the [instructions](https://github.com/Storj/downstream-farmer/wiki/Test-Group-A-FAQ).

4. Run
```docker run -d -v <path to your farmer directory>:/downstream storj/downstream-farmer```

* Check the container status:
```docker ps```

* View the Farmer console output:
```docker attach <container id|name>```

Build Image from Source
===
```
git clone git@github.com:Storj/downstream-farmer.git
cd docker
docker build .
```
