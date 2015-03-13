# Copyright (c) 2013 dotCloud, Inc.
# Copyright 2014 IBM Corp.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
A Docker Hypervisor which allows running Linux Containers instead of VMs.
"""

import os
import shutil
import socket
import time
import uuid
import base64
import re
import email


from docker import errors
from docker.utils import utils as docker_utils

from oslo.config import cfg
from oslo.serialization import jsonutils
from oslo.utils import importutils
from oslo.utils import units

from nova.compute import flavors
from nova.compute import power_state
from nova.compute import task_states
from nova import exception
from nova.i18n import _, _LI, _LE, _LW
from nova.image import glance
from nova.openstack.common import fileutils
from nova.openstack.common import log
from nova.openstack.common import excutils

from nova import utils
from nova import utils as nova_utils
from nova.virt import driver
from nova.virt import firewall
from nova.virt import hardware
from nova.virt import images
from nova.virt.libvirt import blockinfo

from novadocker.virt.docker import client as docker_client
from novadocker.virt.docker import hostinfo
from novadocker.virt.docker import network
from novadocker.virt.docker import parser
from novadocker.virt import hostutils

from nova.volume import encryptors


CONF = cfg.CONF
CONF.import_opt('my_ip', 'nova.netconf')
CONF.import_opt('instances_path', 'nova.compute.manager')

docker_opts = [
    cfg.StrOpt('root_directory',
               default='/var/lib/docker',
               help='Path to use as the root of the Docker runtime.'),
    cfg.StrOpt('host_url',
               default='unix:///var/run/docker.sock',
               help='tcp://host:port to bind/connect to or '
                    'unix://path/to/socket to use'),
    cfg.BoolOpt('api_insecure',
                default=False,
                help='If set, ignore any SSL validation issues'),
    cfg.StrOpt('ca_file',
               help='Location of CA certificates file for '
                    'securing docker api requests (tlscacert).'),
    cfg.StrOpt('cert_file',
               help='Location of TLS certificate file for '
                    'securing docker api requests (tlscert).'),
    cfg.StrOpt('key_file',
               help='Location of TLS private key file for '
                    'securing docker api requests (tlskey).'),
    cfg.StrOpt('vif_driver',
               default='novadocker.virt.docker.vifs.DockerGenericVIFDriver'),
    cfg.StrOpt('snapshots_directory',
               default='$instances_path/snapshots',
               help='Location where docker driver will temporarily store '
                    'snapshots.'),
    cfg.BoolOpt('inject_key',
                default=False,
                help='Inject the ssh public key at boot time'),
]

CONF.register_opts(docker_opts, 'docker')

LOG = log.getLogger(__name__)
import eventlet

class DockerDriver(driver.ComputeDriver):
    """Docker hypervisor driver."""

    B64_REGEX = re.compile('^(?:[A-Za-z0-9+\/]{4})*'
                           '(?:[A-Za-z0-9+\/]{2}=='
                           '|[A-Za-z0-9+\/]{3}=)?$')

    def __init__(self, virtapi):
        super(DockerDriver, self).__init__(virtapi)
        self._docker = None
        vif_class = importutils.import_class(CONF.docker.vif_driver)
        self.vif_driver = vif_class()
        self.firewall_driver = firewall.load_driver(
            default='nova.virt.firewall.NoopFirewallDriver')

    @property
    def docker(self):
        if self._docker is None:
            self._docker = docker_client.DockerHTTPClient(CONF.docker.host_url)
        return self._docker

    def init_host(self, host):
        if self._is_daemon_running() is False:
            raise exception.NovaException(
                _('Docker daemon is not running or is not reachable'
                  ' (check the rights on /var/run/docker.sock)'))

    def _is_daemon_running(self):
        return self.docker.ping()

    def _start_firewall(self, instance, network_info):
        self.firewall_driver.setup_basic_filtering(instance, network_info)
        self.firewall_driver.prepare_instance_filter(instance, network_info)
        self.firewall_driver.apply_instance_filter(instance, network_info)

    def _stop_firewall(self, instance, network_info):
        self.firewall_driver.unfilter_instance(instance, network_info)

    def refresh_security_group_rules(self, security_group_id):
        """Refresh security group rules from data store.

        Invoked when security group rules are updated.

        :param security_group_id: The security group id.

        """
        self.firewall_driver.refresh_security_group_rules(security_group_id)

    def refresh_security_group_members(self, security_group_id):
        """Refresh security group members from data store.

        Invoked when instances are added/removed to a security group.

        :param security_group_id: The security group id.

        """
        self.firewall_driver.refresh_security_group_members(security_group_id)

    def refresh_provider_fw_rules(self):
        """Triggers a firewall update based on database changes."""
        self.firewall_driver.refresh_provider_fw_rules()

    def refresh_instance_security_rules(self, instance):
        """Refresh security group rules from data store.

        Gets called when an instance gets added to or removed from
        the security group the instance is a member of or if the
        group gains or loses a rule.

        :param instance: The instance object.

        """
        self.firewall_driver.refresh_instance_security_rules(instance)

    def ensure_filtering_rules_for_instance(self, instance, network_info):
        """Set up filtering rules.

        :param instance: The instance object.
        :param network_info: Instance network information.

        """
        self.firewall_driver.setup_basic_filtering(instance, network_info)
        self.firewall_driver.prepare_instance_filter(instance, network_info)

    def unfilter_instance(self, instance, network_info):
        """Stop filtering instance.

        :param instance: The instance object.
        :param network_info: Instance network information.

        """
        self.firewall_driver.unfilter_instance(instance, network_info)

    def list_instances(self, inspect=False):
        res = []
        for container in self.docker.containers(all=True):
            info = self.docker.inspect_container(container['id'])
            if not info:
                continue
            if inspect:
                res.append(info)
            else:
                res.append(info['Config'].get('Hostname'))
        return res

    def plug_vifs(self, instance, network_info):
        """Plug VIFs into networks."""
        for vif in network_info:
            self.vif_driver.plug(instance, vif)
        self._start_firewall(instance, network_info)

    def _attach_vifs(self, instance, network_info):
        """Plug VIFs into container."""
        if not network_info:
            return
        container_id = self._get_container_id(instance)
        if not container_id:
            return
        netns_path = '/var/run/netns'
        if not os.path.exists(netns_path):
            utils.execute(
                'mkdir', '-p', netns_path, run_as_root=True)
        nspid = self._find_container_pid(container_id)
        if not nspid:
            msg = _('Cannot find any PID under container "{0}"')
            raise RuntimeError(msg.format(container_id))
        netns_path = os.path.join(netns_path, container_id)
        utils.execute(
            'ln', '-sf', '/proc/{0}/ns/net'.format(nspid),
            '/var/run/netns/{0}'.format(container_id),
            run_as_root=True)

        for vif in network_info:
            self.vif_driver.attach(instance, vif, container_id)

    def unplug_vifs(self, instance, network_info):
        """Unplug VIFs from networks."""
        for vif in network_info:
            self.vif_driver.unplug(instance, vif)
        self._stop_firewall(instance, network_info)

    def _encode_utf8(self, value):
        return unicode(value).encode('utf-8')

    def _find_container_by_name(self, name):
        try:
            for info in self.list_instances(inspect=True):
                if info['Config'].get('Hostname') == name:
                    return info
        except errors.APIError as e:
            if e.response.status_code != 404:
                raise
        return {}

    def _get_container_id(self, instance):
        return self._find_container_by_name(instance['name']).get('id')

    def get_info(self, instance):
        container = self._find_container_by_name(instance['name'])
        if not container:
            raise exception.InstanceNotFound(instance_id=instance['name'])
        running = container['State'].get('Running')
        mem = container['Config'].get('Memory', 0)

        # NOTE(ewindisch): cgroups/lxc defaults to 1024 multiplier.
        #                  see: _get_cpu_shares for further explaination
        num_cpu = container['Config'].get('CpuShares', 0) / 1024

        # FIXME(ewindisch): Improve use of statistics:
        #                   For 'mem', we should expose memory.stat.rss, and
        #                   for cpu_time we should expose cpuacct.stat.system,
        #                   but these aren't yet exposed by Docker.
        #
        #                   Also see:
        #                    docker/docs/sources/articles/runmetrics.md
        info = {
            'max_mem': mem,
            'mem': mem,
            'num_cpu': num_cpu,
            'cpu_time': 0
        }
        info['state'] = (power_state.RUNNING if running
                         else power_state.SHUTDOWN)
        return info

    def get_host_stats(self, refresh=False):
        hostname = socket.gethostname()
        stats = self.get_available_resource(hostname)
        stats['host_hostname'] = stats['hypervisor_hostname']
        stats['host_name_label'] = stats['hypervisor_hostname']
        return stats

    def get_available_nodes(self, refresh=False):
        hostname = socket.gethostname()
        return [hostname]

    def get_available_resource(self, nodename):
        if not hasattr(self, '_nodename'):
            self._nodename = nodename
        if nodename != self._nodename:
            LOG.error(_('Hostname has changed from %(old)s to %(new)s. '
                        'A restart is required to take effect.'
                        ), {'old': self._nodename,
                            'new': nodename})

        memory = hostinfo.get_memory_usage()
        disk = hostinfo.get_disk_usage()
        stats = {
            'vcpus': 1,
            'vcpus_used': 0,
            'memory_mb': memory['total'] / units.Mi,
            'memory_mb_used': memory['used'] / units.Mi,
            'local_gb': disk['total'] / units.Gi,
            'local_gb_used': disk['used'] / units.Gi,
            'disk_available_least': disk['available'] / units.Gi,
            'hypervisor_type': 'docker',
            'hypervisor_version': utils.convert_version_to_int('1.0'),
            'hypervisor_hostname': self._nodename,
            'cpu_info': '?',
            'supported_instances': jsonutils.dumps([
                ('i686', 'docker', 'lxc'),
                ('x86_64', 'docker', 'lxc')
            ])
        }
        return stats

    def _find_container_pid(self, container_id):
        n = 0
        while True:
            # NOTE(samalba): We wait for the process to be spawned inside the
            # container in order to get the the "container pid". This is
            # usually really fast. To avoid race conditions on a slow
            # machine, we allow 10 seconds as a hard limit.
            if n > 20:
                return
            info = self.docker.inspect_container(container_id)
            if info:
                pid = info['State']['Pid']
                # Pid is equal to zero if it isn't assigned yet
                if pid:
                    return pid
            time.sleep(0.5)
            n += 1

    def _get_memory_limit_bytes(self, instance):
        system_meta = utils.instance_sys_meta(instance)
        return int(system_meta.get('instance_type_memory_mb', 0)) * units.Mi

    def _get_image_name(self, context, instance, image):
        fmt = image['container_format']
        if fmt != 'docker':
            msg = _('Image container format not supported ({0})')
            raise exception.InstanceDeployFailure(msg.format(fmt),
                                                  instance_id=instance['name'])
        return image['name']

    def _pull_missing_image(self, context, image_meta, instance):
        msg = 'Image name "%s" does not exist, fetching it...'
        LOG.debug(msg, image_meta['name'])

        # TODO(imain): It would be nice to do this with file like object
        # passing but that seems a bit complex right now.
        snapshot_directory = CONF.docker.snapshots_directory
        fileutils.ensure_tree(snapshot_directory)
        with utils.tempdir(dir=snapshot_directory) as tmpdir:
            try:
                out_path = os.path.join(tmpdir, uuid.uuid4().hex)

                images.fetch(context, image_meta['id'], out_path,
                             instance['user_id'], instance['project_id'])
                self.docker.load_repository_file(
                    self._encode_utf8(image_meta['name']),
                    out_path
                )
            except Exception as e:
                LOG.warning(_('Cannot load repository file: %s'),
                            e, instance=instance, exc_info=True)
                msg = _('Cannot load repository file: {0}')
                raise exception.NovaException(msg.format(e),
                                              instance_id=image_meta['name'])

        return self.docker.inspect_image(self._encode_utf8(image_meta['name']))

    def _extract_dns_entries(self, network_info):
        dns = []
        if network_info:
            for net in network_info:
                subnets = net['network'].get('subnets', [])
                for subnet in subnets:
                    dns_entries = subnet.get('dns', [])
                    for dns_entry in dns_entries:
                        if 'address' in dns_entry:
                            dns.append(dns_entry['address'])
        return dns if dns else None

    def _get_key_binds(self, container_id, instance):
        binds = None
        # Handles the key injection.
        if CONF.docker.inject_key and instance.get('key_data'):
            key = str(instance['key_data'])
            mount_origin = self._inject_key(container_id, key)
            binds = {mount_origin: {'bind': '/root/.ssh', 'ro': True}}
        return binds

    def _start_container(self, container_id, instance, network_info=None):
        binds = self._get_key_binds(container_id, instance)
        dns = self._extract_dns_entries(network_info)
        self.docker.start(container_id, binds=binds, dns=dns)

        if not network_info:
            return
        try:
            self.plug_vifs(instance, network_info)
            self._attach_vifs(instance, network_info)
        except Exception as e:
            LOG.warning(_('Cannot setup network: %s'),
                        e, instance=instance, exc_info=True)
            msg = _('Cannot setup network: {0}')
            self.docker.kill(container_id)
            self.docker.remove_container(container_id, force=True)
            raise exception.InstanceDeployFailure(msg.format(e),
                                                  instance_id=instance['name'])

    def spawn(self, context, instance, image_meta, injected_files,
              admin_password, network_info=None, block_device_info=None,
              flavor=None):
        image_name = self._get_image_name(context, instance, image_meta)
        args = {
            'hostname': instance['name'],
            'mem_limit': self._get_memory_limit_bytes(instance),
            'cpu_shares': self._get_cpu_shares(instance),
            'network_disabled': True,
            'command': None,
            'user': None,
            'detach': False,
            'stdin_open': False,
            'tty': False,
            'ports': None,
            'environment': None,
            'dns': None,
            'volumes': None,
            'volumes_from': None,
            'name': None,
            'entrypoint': None,
            'working_dir': None,
            'domainname': None,
            'memswap_limit': 0,
            'cpuset': None,
            'host_config': None,
        }

        try:
            image = self.docker.inspect_image(self._encode_utf8(image_name))
        except errors.APIError:
            image = None

        if not image:
            image = self._pull_missing_image(context, image_meta, instance)
        if not (image and image['ContainerConfig']['Cmd']):
            args['command'] = ['sh']
        # Glance command-line overrides any set in the Docker image
        if (image_meta and
                image_meta.get('properties', {}).get('os_command_line')):
            args['command'] = image_meta['properties'].get('os_command_line')

        if 'metadata' in instance:
            args['environment'] = nova_utils.instance_meta(instance)

        """ Support Docker /containers/create - remote api version 1.16 .
            the api payload as follows
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

            Currently, the user_data support those parameters

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

        """

        if 'user_data' in instance and instance.user_data is not None and self._validate_user_data(instance.user_data):
            decoded = self._decode_base64(instance.user_data)
            LOG.debug(_('USER_DATA Data Structure: %(userdata)s '), {'userdata': decoded})

            userdata_parts = None
            try:
                userdata_parts = email.message_from_string(decoded)
            except Exception:
                pass

            user_data = decoded
            if userdata_parts and userdata_parts.is_multipart():
                for part in userdata_parts.get_payload():
                    if part.get_filename() == 'cfn-userdata':
                        user_data = part.get_payload()
                        LOG.debug(_('cfn-userdata payload: %(payload)s '), {'payload': part.get_payload()})
            yml = None
            try:
                yml = parser.parse(user_data)
            except ValueError as e:
                LOG.error(_('yml paring error: %(msg)s '), {'msg': e.message})
                pass
            if yml:
                host_config = docker_utils.create_host_config()
                for key in yml:
                    if key in args and key != 'hostname' and key != 'mem_limit' and key != 'cpu_shares' and key != 'network_disabled' and key != 'tty':
                        args[key] = yml[key]
                        LOG.debug(_('current key:%(key)s '), {'key': key})
                        if key == 'volumes':
                            host_config['Binds'] = docker_utils.convert_volume_binds(yml[key])
                            args['host_config'] = host_config
                            LOG.debug(_('in volumes condition, args value:%(args)s'), {'args': args})


            # decode_user_data = base64.b64decode(instance['user_data'])
            # user_data = parser.parse(decode_user_data)
            # LOG.debug(_('USER_DATA Data Structure: %(userdata)s '), {'userdata': user_data})
            # for key in user_data:
            #     LOG.debug(_('user_data:%(userdata)s'),{'userdata':user_data})
            #     LOG.debug(_('user_data key:%(key)s, value:%(value)s'), {'key': key,'value':user_data[key]})
            #     if key in args and key != 'hostname' and key != 'mem_limit' and key != 'cpu_shares' and key != 'network_disabled' and key != 'tty':
            #         args[key] = user_data[key]

        LOG.debug(_('DOCKER spawn args value:%(args)s'), {'args': args})

        container_id = self._create_container(instance, image_name, args)
        if not container_id:
            raise exception.InstanceDeployFailure(
                _('Cannot create container'),
                instance_id=instance['name'])

        self._start_container(container_id, instance, network_info)

    def _inject_key(self, id, key):
        if isinstance(id, dict):
            id = id.get('id')
        sshdir = os.path.join(CONF.instances_path, id, '.ssh')
        key_data = ''.join([
            '\n',
            '# The following ssh key was injected by Nova',
            '\n',
            key.strip(),
            '\n',
        ])
        fileutils.ensure_tree(sshdir)
        keys_file = os.path.join(sshdir, 'authorized_keys')
        with open(keys_file, 'a') as f:
            f.write(key_data)
        os.chmod(sshdir, 0o700)
        os.chmod(keys_file, 0o600)
        return sshdir

    def _cleanup_key(self, instance, id):
        if isinstance(id, dict):
            id = id.get('id')
        dir = os.path.join(CONF.instances_path, id)
        if os.path.exists(dir):
            LOG.info(_LI('Deleting instance files %s'), dir,
                     instance=instance)
            try:
                shutil.rmtree(dir)
            except OSError as e:
                LOG.error(_LE('Failed to cleanup directory %(target)s: '
                              '%(e)s'), {'target': dir, 'e': e},
                          instance=instance)

    def restore(self, instance):
        container_id = self._get_container_id(instance)
        if not container_id:
            return

        self._start_container(container_id, instance)

    def soft_delete(self, instance):
        container_id = self._get_container_id(instance)
        if not container_id:
            return
        try:
            self.docker.stop(container_id)
        except errors.APIError as e:
            if 'Unpause the container before stopping' not in e.explanation:
                LOG.warning(_('Cannot stop container: %s'),
                            e, instance=instance, exc_info=True)
                raise
            self.docker.unpause(container_id)
            self.docker.stop(container_id)

    def destroy(self, context, instance, network_info, block_device_info=None,
                destroy_disks=True, migrate_data=None):
        self.soft_delete(instance)
        self.cleanup(context, instance, network_info,
                     block_device_info, destroy_disks)

    def cleanup(self, context, instance, network_info, block_device_info=None,
                destroy_disks=True, migrate_data=None, destroy_vifs=True):
        """Cleanup after instance being destroyed by Hypervisor."""
        container_id = self._get_container_id(instance)
        if not container_id:
            return
        self.docker.remove_container(container_id, force=True)
        network.teardown_network(container_id)
        self.unplug_vifs(instance, network_info)
        '''
        if CONF.docker.inject_key:
            self._cleanup_key(instance, container_id)



        # FIXME(wangpan): if the instance is booted again here, such as the
        #                 the soft reboot operation boot it here, it will
        #                 become "running deleted", should we check and destroy
        #                 it at the end of this method?

        # NOTE(vish): we disconnect from volumes regardless
        block_device_mapping = driver.block_device_info_get_mapping(
            block_device_info)
        for vol in block_device_mapping:
            connection_info = vol['connection_info']
            disk_dev = vol['mount_device']
            if disk_dev is not None:
                disk_dev = disk_dev.rpartition("/")[2]

            if ('data' in connection_info and
                    'volume_id' in connection_info['data']):
                volume_id = connection_info['data']['volume_id']
                encryption = encryptors.get_encryption_metadata(
                    context, self._volume_api, volume_id, connection_info)

                if encryption:
                    # The volume must be detached from the VM before
                    # disconnecting it from its encryptor. Otherwise, the
                    # encryptor may report that the volume is still in use.
                    encryptor = self._get_volume_encryptor(connection_info,
                                                           encryption)
                    encryptor.detach_volume(**encryption)

            try:
                self._disconnect_volume(connection_info, disk_dev)
            except Exception as exc:
                with excutils.save_and_reraise_exception() as ctxt:
                    if destroy_disks:
                        # Don't block on Volume errors if we're trying to
                        # delete the instance as we may be partially created
                        # or deleted
                        ctxt.reraise = False
                        LOG.warn(_LW("Ignoring Volume Error on vol %(vol_id)s "
                                     "during delete %(exc)s"),
                                 {'vol_id': vol.get('volume_id'), 'exc': exc},
                                 instance=instance)

        if destroy_disks:
            # NOTE(haomai): destroy volumes if needed
            if CONF.libvirt.images_type == 'lvm':
                self._cleanup_lvm(instance)
            if CONF.libvirt.images_type == 'rbd':
                self._cleanup_rbd(instance)

        if destroy_disks or (
                migrate_data and migrate_data.get('is_shared_block_storage',
                                                  False)):
            self._delete_instance_files(instance)
        '''
    def reboot(self, context, instance, network_info, reboot_type,
               block_device_info=None, bad_volumes_callback=None):
        container_id = self._get_container_id(instance)
        if not container_id:
            return
        self.docker.stop(container_id)
        try:
            network.teardown_network(container_id)
            if network_info:
                self.unplug_vifs(instance, network_info)
        except Exception as e:
            LOG.warning(_('Cannot destroy the container network'
                          ' during reboot {0}').format(e),
                        exc_info=True)
            return

        binds = self._get_key_binds(container_id, instance)
        dns = self._extract_dns_entries(network_info)
        self.docker.start(container_id, binds=binds, dns=dns)
        try:
            if network_info:
                self.plug_vifs(instance, network_info)
        except Exception as e:
            LOG.warning(_('Cannot setup network on reboot: {0}'), e,
                        exc_info=True)
            return

    def power_on(self, context, instance, network_info,
                 block_device_info=None):
        container_id = self._get_container_id(instance)
        if not container_id:
            return
        binds = self._get_key_binds(container_id, instance)
        dns = self._extract_dns_entries(network_info)
        self.docker.start(container_id, binds=binds, dns=dns)
        if not network_info:
            return
        try:
            self.plug_vifs(instance, network_info)
            self._attach_vifs(instance, network_info)
        except Exception as e:
            LOG.debug(_('Cannot setup network: %s'),
                      e, instance=instance, exc_info=True)
            msg = _('Cannot setup network: {0}')
            self.docker.kill(container_id)
            self.docker.remove_container(container_id, force=True)
            raise exception.InstanceDeployFailure(msg.format(e),
                                                  instance_id=instance['name'])

    def power_off(self, instance, timeout=0, retry_interval=0):
        container_id = self._get_container_id(instance)
        if not container_id:
            return
        self.docker.stop(container_id, timeout)

    def pause(self, instance):
        """Pause the specified instance.

        :param instance: nova.objects.instance.Instance
        """
        try:
            cont_id = self._get_container_id(instance)
            if not self.docker.pause(cont_id):
                raise exception.NovaException
        except Exception as e:
            LOG.debug(_('Error pause container: %s'),
                      e, instance=instance, exc_info=True)
            msg = _('Cannot pause container: {0}')
            raise exception.NovaException(msg.format(e),
                                          instance_id=instance['name'])

    def unpause(self, instance):
        """Unpause paused VM instance.

        :param instance: nova.objects.instance.Instance
        """
        try:
            cont_id = self._get_container_id(instance)
            if not self.docker.unpause(cont_id):
                raise exception.NovaException
        except Exception as e:
            LOG.debug(_('Error unpause container: %s'),
                      e, instance=instance, exc_info=True)
            msg = _('Cannot unpause container: {0}')
            raise exception.NovaException(msg.format(e),
                                          instance_id=instance['name'])

    def get_console_output(self, context, instance):
        container_id = self._get_container_id(instance)
        if not container_id:
            return ''
        return self.docker.get_container_logs(container_id)

    def snapshot(self, context, instance, image_href, update_task_state):
        container_id = self._get_container_id(instance)
        if not container_id:
            raise exception.InstanceNotRunning(instance_id=instance['uuid'])

        update_task_state(task_state=task_states.IMAGE_PENDING_UPLOAD)
        (image_service, image_id) = glance.get_remote_image_service(
            context, image_href)
        image = image_service.show(context, image_id)
        if ':' not in image['name']:
            commit_name = self._encode_utf8(image['name'])
            tag = 'latest'
        else:
            parts = self._encode_utf8(image['name']).rsplit(':', 1)
            commit_name = parts[0]
            tag = parts[1]

        self.docker.commit(container_id, repository=commit_name, tag=tag)

        update_task_state(task_state=task_states.IMAGE_UPLOADING,
                          expected_state=task_states.IMAGE_PENDING_UPLOAD)

        metadata = {
            'is_public': False,
            'status': 'active',
            'disk_format': 'raw',
            'container_format': 'docker',
            'name': image['name'],
            'properties': {
                'image_location': 'snapshot',
                'image_state': 'available',
                'status': 'available',
                'owner_id': instance['project_id'],
                'ramdisk_id': instance['ramdisk_id']
            }
        }
        if instance['os_type']:
            metadata['properties']['os_type'] = instance['os_type']

        try:
            raw = self.docker.get_image(commit_name)
            # Patch the seek/tell as urllib3 throws UnsupportedOperation
            raw.seek = lambda x=None, y=None: None
            raw.tell = lambda: None
            image_service.update(context, image_href, metadata, raw)
        except Exception as e:
            LOG.debug(_('Error saving image: %s'),
                      e, instance=instance, exc_info=True)
            msg = _('Error saving image: {0}')
            raise exception.NovaException(msg.format(e),
                                          instance_id=instance['name'])

    def _get_cpu_shares(self, instance):
        """Get allocated CPUs from configured flavor.

        Docker/lxc supports relative CPU allocation.

        cgroups specifies following:
         /sys/fs/cgroup/lxc/cpu.shares = 1024
         /sys/fs/cgroup/cpu.shares = 1024

        For that reason we use 1024 as multiplier.
        This multiplier allows to divide the CPU
        resources fair with containers started by
        the user (e.g. docker registry) which has
        the default CpuShares value of zero.
        """
        flavor = flavors.extract_flavor(instance)
        return int(flavor['vcpus']) * 1024

    def _create_container(self, instance, image_name, args):
        name = "nova-" + instance['uuid']
        args.update({'name': self._encode_utf8(name)})
        return self.docker.create_container(image_name, **args)

    def get_host_uptime(self, host):
        return hostutils.sys_uptime()


    def _decode_base64(self, data):
        data = re.sub(r'\s', '', data)
        if not self.B64_REGEX.match(data):
            return None
        try:
            return base64.b64decode(data)
        except TypeError:
            return None

    def _validate_user_data(self, user_data):
        """Check if the user_data is encoded properly."""
        if not user_data and self._decode_base64(user_data) is None:
            return None

        return True


    def _connect_volume(self, connection_info, disk_info):
        driver_type = connection_info.get('driver_volume_type')
        if driver_type not in self.volume_drivers:
            raise exception.VolumeDriverNotFound(driver_type=driver_type)
        driver = self.volume_drivers[driver_type]
        return driver.connect_volume(connection_info, disk_info)

    def _disconnect_volume(self, connection_info, disk_dev):
        driver_type = connection_info.get('driver_volume_type')
        if driver_type not in self.volume_drivers:
            raise exception.VolumeDriverNotFound(driver_type=driver_type)
        driver = self.volume_drivers[driver_type]
        return driver.disconnect_volume(connection_info, disk_dev)

    def _get_volume_config(self, connection_info, disk_info):
        driver_type = connection_info.get('driver_volume_type')
        if driver_type not in self.volume_drivers:
            raise exception.VolumeDriverNotFound(driver_type=driver_type)
        driver = self.volume_drivers[driver_type]
        return driver.get_config(connection_info, disk_info)

    def _get_volume_encryptor(self, connection_info, encryption):
        encryptor = encryptors.get_volume_encryptor(connection_info,
                                                    **encryption)
        return encryptor

    def _create_domain_and_network(self, context, xml, instance, network_info,
                                   block_device_info=None, power_on=True,
                                   reboot=False, vifs_already_plugged=False,
                                   disk_info=None):

        """Do required network setup and create domain."""
        block_device_mapping = driver.block_device_info_get_mapping(
            block_device_info)

        for vol in block_device_mapping:
            connection_info = vol['connection_info']
            info = blockinfo.get_info_from_bdm(
                CONF.libvirt.virt_type, vol)
            conf = self._connect_volume(connection_info, info)

            # cache device_path in connection_info -- required by encryptors
            if 'data' in connection_info:
                connection_info['data']['device_path'] = conf.source_path
                vol['connection_info'] = connection_info
                vol.save(context)

            if (not reboot and 'data' in connection_info and
                    'volume_id' in connection_info['data']):
                volume_id = connection_info['data']['volume_id']
                encryption = encryptors.get_encryption_metadata(
                    context, self._volume_api, volume_id, connection_info)

                if encryption:
                    encryptor = self._get_volume_encryptor(connection_info,
                                                           encryption)
                    encryptor.attach_volume(context, **encryption)

        timeout = CONF.vif_plugging_timeout
        if (self._conn_supports_start_paused and
            utils.is_neutron() and not
            vifs_already_plugged and power_on and timeout):
            events = self._get_neutron_events(network_info)
        else:
            events = []

        launch_flags = events and libvirt.VIR_DOMAIN_START_PAUSED or 0
        domain = None
        try:
            with self.virtapi.wait_for_instance_event(
                    instance, events, deadline=timeout,
                    error_callback=self._neutron_failed_callback):
                self.plug_vifs(instance, network_info)
                self.firewall_driver.setup_basic_filtering(instance,
                                                           network_info)
                self.firewall_driver.prepare_instance_filter(instance,
                                                             network_info)
                with self._lxc_disk_handler(instance, block_device_info,
                                            disk_info):
                    domain = self._create_domain(
                        xml, instance=instance,
                        launch_flags=launch_flags,
                        power_on=power_on)

                self.firewall_driver.apply_instance_filter(instance,
                                                           network_info)
        except exception.VirtualInterfaceCreateException:
            # Neutron reported failure and we didn't swallow it, so
            # bail here
            with excutils.save_and_reraise_exception():
                if domain:
                    domain.destroy()
                self.cleanup(context, instance, network_info=network_info,
                             block_device_info=block_device_info)
        except eventlet.timeout.Timeout:
            # We never heard from Neutron
            LOG.warn(_LW('Timeout waiting for vif plugging callback for '
                         'instance %(uuid)s'), {'uuid': instance['uuid']})
            if CONF.vif_plugging_is_fatal:
                if domain:
                    domain.destroy()
                self.cleanup(context, instance, network_info=network_info,
                             block_device_info=block_device_info)
                raise exception.VirtualInterfaceCreateException()

        return domain
