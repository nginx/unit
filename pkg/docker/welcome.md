Welcome to NGINX Unit
=====================

Congratulations! NGINX Unit is installed and running.

Useful Links
------------

 * https://unit.nginx.org/
   - Get started with the 'Configuration' docs, starting with the 'Quick Start' guide.

 * https://unit.nginx.org/howto/docker/
   - Guidance for running Unit in a container and tips for containerized applications.

 * https://github.com/nginx/unit
   - See our GitHub repo to browse the code, contribute, or seek help from the community.

Current Configuration
---------------------
Unit's control API is currently listening for configuration changes on the Unix socket at
`/var/run/control.unit.sock` inside the container.

Read the current configuration with
```
docker exec -ti <containerID> curl --unix-socket /var/run/control.unit.sock http://localhost/config
```

---
NGINX Unit - the universal web app server
