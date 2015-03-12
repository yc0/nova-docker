===============================
nova-docker
===============================

Docker driver for OpenStack Nova.

Free software: Apache license

----------------------------
Installation & Configuration
----------------------------

^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
1. Install the python modules.
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

For example::

  $ python setup.py install

Note: There are better and cleaner ways of managing Python modules, such as using distribution packages or 'pip'. The setup.py file and Debian's stdeb, for instance, may be used to create Debian/Ubuntu packages.

^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
2. Enable the driver in Nova's configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In nova.conf::

  compute_driver=novadocker.virt.docker.DockerDriver

^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
3. Optionally tune site-specific settings.
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In nova.conf::

  [docker]
  # Commented out. Uncomment these if you'd like to customize:
  ## vif_driver=novadocker.virt.docker.vifs.DockerGenericVIFDriver
  ## snapshots_directory=/var/tmp/my-snapshot-tempdir

--------------------------
Uploading Images to Glance
--------------------------

^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
1. Enable the driver in Glance's configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In glance-api.conf::

  container_formats=ami,ari,aki,bare,ovf,ova,docker

^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
2. Save docker images to Glance
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Images may now be saved directly to Glance::

  $ docker pull busybox
  $ docker save busybox | glance image-create --is-public=True --container-format=docker --disk-format=raw --name busybox

**Note:** At present, only administrators should be allowed to manage images.

The name of the image in Glance should be explicitly set to the same name as the image as it is known to Docker. In the example above, an image has been tagged in Docker as 'busybox'. Matching this is the '--name busybox' argument to *glance image-create*. If these names do not align, the image will not be bootable.

-----
How to use it
-----

^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
1. Horizon
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
in horizon, while launching the new instances, you can put the parameters in **yml** or **json** format
in **script data** on **post-creation**.::

  """ Support Docker /containers/create - remote api version 1.16 .
  {
      "Hostname":"",
      "Domainname": "",
       "User":"",
       "Memory":0,
       "MemorySwap":0,
       "CpuShares": 512,
       "Cpuset": "0,1",
       "AttachStdin":false,
       "AttachStdout":true,
       "AttachStderr":true,
       "Tty":false,
       "OpenStdin":false,
       "StdinOnce":false,
       "Env":null,
       "Cmd":[
               "date"
       ],
       "Entrypoint": "",
       "Image":"base",
       "Volumes":{
               "/tmp": {}
       },
       "WorkingDir":"",
       "NetworkDisabled": false,
       "MacAddress":"12:34:56:78:9a:bc",
       "ExposedPorts":{
               "22/tcp": {}
       },
       "SecurityOpts": [""],
       "HostConfig": {
         "Binds":["/tmp:/tmp"],
         "Links":["redis3:redis"],
         "LxcConf":{"lxc.utsname":"docker"},
         "PortBindings":{ "22/tcp": [{ "HostPort": "11022" }] },
         "PublishAllPorts":false,
         "Privileged":false,
         "Dns": ["8.8.8.8"],
         "DnsSearch": [""],
         "VolumesFrom": ["parent", "other:ro"],
         "CapAdd": ["NET_ADMIN"],
         "CapDrop": ["MKNOD"],
         "RestartPolicy": { "Name": "", "MaximumRetryCount": 0 },
         "NetworkMode": "bridge",
         "Devices": []
      }
  }


If you want to convert those payload in the nova, you must use user data
to pass through parameters.

Currently, the user_data support those parameters::

  command=None, user=None,
  detach=False, stdin_open=False,
  ports=None, environment=None, dns=None,
  volumes=None, volumes_from=None,
  name=None, entrypoint=None,
  working_dir=None, domainname=None,
  memswap_limit=0, cpuset=None, host_config=None

  How to exploit user_data to pass those parameters

  environment :
      etcd : 10.144.192.168

  volumes :
      /var/run/docker.sock : /var/run/docker.sock


^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
2. Heat/CLI
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

I demostrate HOT format::
  resources:
    docker_image:
      type: OS::Nova::Server
      properties:
        flavor: {get_param: flavor}
        image: {get_param: image}
        networks:
          - network: {get_param: network_id}
        user_data: |
          volumes :
            /tmp/test112233 : /tmp/test112233

^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
3. Contact 
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

I just start the project, if you are as intersted as in the topic 
welcome to contact me: linyencheng@gmail.com


-----
Notes
-----

* Earlier releases of this driver required the deployment of a private docker registry. This is no longer required. Images are now saved and loaded from Glance.
* Images loaded from Glance may do bad things. Only allow administrators to add images. Users may create snapshots of their containers, generating images in Glance -- these images are managed and thus safe.

----------
Contact Us
----------
Join us in #nova-docker on Freenode IRC

--------
Features
--------

* TODO
