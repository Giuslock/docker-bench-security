Forked from Docker-Bench-Security, a script that checks for dozens of common best-practices around deploying Docker containers in production. Inspired by the [CIS Docker Benchmark v1.2.0](https://www.cisecurity.org/benchmark/docker/)

The list with all tests is available [here](tests/TESTS.md).

## Running Dockfile Creator Bench

This script focuses on the Container Image tests and Runtime tests. You have to test one Image at a time. You have to put your Image in the directory "yourimghere" and after building it you can run the script. In the directory "solutions" you will find the new dockerfile with recommendations.

### Run from your base host

You can simply run this script from your base host by running:

```sh
git clone https://github.com/Giuslock/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```

### Note

Docker bench requires Docker 1.13.0 or later in order to run.

Note that when distributions don't contain `auditctl`, the audit tests will check `/etc/audit/audit.rules` to see if a rule is present instead.

By default the Docker Bench for Security script will run all available CIS tests and produce 
logs in the log folder from current directory, named `docker-bench-security.sh.log.json` and 
`docker-bench-security.sh.log`.

If the docker container is used then the log files will be created inside the container in location `/usr/local/bin/log/`. If you wish to access them from the host after the container has been run you will need to mount a volume for storing them in.


This script was built to be POSIX 2004 compliant, so it should be portable across any Unix platform.
