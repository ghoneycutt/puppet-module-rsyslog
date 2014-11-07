# rsyslog module #
===

[![Build Status](
https://api.travis-ci.org/ghoneycutt/puppet-module-rsyslog.png?branch=master)](https://travis-ci.org/ghoneycutt/puppet-module-rsyslog)


Module to manage rsyslog. Handles both local and remote logging.

Inspired by [saz/rsyslog](https://github.com/saz/puppet-rsyslog/)

This module will ensure that sysklogd is absent, which is needed on EL5.

===

# Compatibility #

This module has been tested to work on the following systems with Puppet v3.x and Ruby versions 1.8.7, 1.9.3, and 2.0.0.

 * Debian 7
 * EL 5
 * EL 6
 * EL 7
 * Suse 10
 * Suse 11
 * Solaris 10
 * Solaris 11

===

# Parameters #

package
-------
Name of the rsyslog package.

- *Default*: 'rsyslog'

package_ensure
--------------
What state the package should be in. Valid values are 'present', 'absent', 'purged', 'held' and 'latest'.

- *Default*: 'present'

package_provider
--------------
Change package provider.

- *Default*: undef

pid_file
--------
Path to pid file.

- *Default*: based on platform

logrotate_present
-----------------
Enable logrotate.

- *Default*: based on platform

logrotate_d_config_path
-----------------------
Path of the logrotate config file.

- *Default*: '/etc/logrotate.d/syslog'

logrotate_d_config_owner
------------------------
Owner of the logrotate config file.

- *Default*: 'root'

logrotate_d_config_group
------------------------
Group of the logrotate config file.

- *Default*: 'root'

logrotate_d_config_mode
-----------------------
Mode of the logrotate config file.

- *Default*: '0644'

logrotate_syslog_files
----------------------
Array of files which should be log rotated by /etc/logrotate.d/syslog ($logrotate_d_config_path).
'USE_DEFAULTS' will choose the files based on the osfamily.

- *Default*:  'USE_DEFAULTS'

config_path
-----------
Path of the rsyslog config file.

- *Default*: '/etc/rsyslog.conf'

config_owner
------------
Owner of the rsyslog config file.

- *Default*: 'root'

config_group
------------
Group of the rsyslog config file.

- *Default*: 'root'

config_mode
-----------
Mode of the rsyslog config file.

- *Default*: '0644'

sysconfig_path
--------------
Path of the rsyslog sysconfig config file.

- *Default*: '/etc/sysconfig/rsyslog' # EL
- *Default*: '/etc/default/rsyslog'   # Debian

sysconfig_owner
---------------
Owner of the rsyslog sysconfig config file.

- *Default*: 'root'

sysconfig_group
---------------
Group of the rsyslog sysconfig config file.

- *Default*: 'root'

sysconfig_mode
--------------
Mode of the rsyslog sysconfig config file.

- *Default*: '0644'

daemon
------
Name of the rsyslog service.
'USE_DEFAULTS' will choose the service name based on the osfamily.
'rsyslog' # RHEL, Debian
'syslog'  # Suse

- *Default*: 'USE_DEFAULTS'

daemon_ensure
-------------
Whether a service should be running. Valid values are 'stopped' and 'running'.

- *Default*: 'running'

daemon_enable
-------------
Whether a service should be enabled to start at boot. Valid values are 'true', 'false', 'manual'.

- *Default*: 'true'

is_log_server
-------------
Whether the system syslog service is meant to receive messages from remote hosts. Valid values are 'true' and 'false'.

- *Default*: 'false'

log_dir
-------
Path to store logs, if $is_log_server is true.

- *Default*: '/srv/logs'

log_dir_owner
-------
Owner of the log directory.

- *Default*: 'root'

log_dir_group
-------
Group of the log directory.

- *Default*: 'root'

log_dir_mode
-------
Mode of the log directory.

- *Default*: '0750'

local_file_monitoring_enabled
-------
Enables the 'imfile' module for local file monitoring.

- *Default*: 'false'

remote_template
---------------
Template path to store logs from remote hosts, appended after log_dir

- *Default*: '%HOSTNAME%/%$YEAR%-%$MONTH%-%$DAY%.log'

remote_logging
----------------------
Whether to send logs remotely to a centralized logging service.

- *Default*: 'false'

rsyslog_conf_version
--------------------
Format version of rsyslog.conf file format. Supported are version 2 (clients only) and 3. 'USE_DEFAULTS' will choose the version based on the installed package version. Valid values are '2' '3' and 'USE_DEFAULTS'.

- *Default*: 'USE_DEFAULTS'

rsyslog_d_dir
-------------
Path to place rsyslog.d files.

- *Default*: '/etc/rsyslog.d'

rsyslog_d_dir_owner
-------------------
Owner of the rsyslog.d directory.

- *Default*: 'root'

rsyslog_d_dir_group
-------------------
Group of the rsyslog.d directory.

- *Default*: 'root'

rsyslog_d_dir_mode
------------------
Mode of the rsyslog.d directory.

- *Default*: '0755'

rsyslog_d_dir_purge
-------------------
Boolean to purge unmanaged files from rsyslog.d

- *Default*: true

rsyslog_fragments
-----------------
Hash of fragments to pass to rsyslog::fragment

- *Default*: undef

spool_dir
---------
Path to place spool files.

- *Default*: '/var/spool/rsyslog'

spool_dir_owner
---------------
Owner of the spool directory.

- *Default*: 'root'

spool_dir_group
---------------
Group of the spool directory.

- *Default*: 'root'

spool_dir_mode
--------------
Mode of the spool directory.

- *Default*: '0700'

max_spool_size
--------------
Maximum disk space used by spool files. Uses one letter units such as k, m and g.

- *Default*: '1g'

transport_protocol
------------------
Transport protocol used by rsyslog. Valid values are 'tcp' and 'udp'

- *Default*: 'tcp'

log_server
----------
Server to send logs to if remote_logging is true.

- *Default*: "log.${::domain}"

log_server_port
---------------
Port of the server to send logs to if remote_logging is true.

- *Default*: '514'

enable_tcp_server
-----------------
Whether to enable tcp listening for the service. If undefined, set by $transport_protocol.

- *Default*: undef

enable_udp_server
-----------------
Whether to enable udp listening for the service. If undefined, set by $transport_protocol.

- *Default*: undef

kernel_target
-------------
Target of kernel logs.

- *Default*: '/var/log/messages'

source_facilities
-----------------
List of source facilities to be sent to remote log server. Only used if remote_logging is true.

- *Default*: `*.*`

===

# rsyslog::fragment define #
Places a fragment in $rsyslog_d_dir directory

## Parameters for rsyslog::fragment

ensure
------
Whether the file should exist or not. Possible values are file and absent.

- *Default*: 'file'

content
-------
String with contents of the fragment file.

- *Default*: undef

## Example usage
<pre>
rsyslog::rsyslog_fragments:
  everything:
    content: "*.* /tmp/everything"
</pre>
