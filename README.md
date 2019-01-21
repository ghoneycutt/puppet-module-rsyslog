# rsyslog module #
===

[![Build Status](
https://api.travis-ci.org/ghoneycutt/puppet-module-rsyslog.png?branch=master)](https://travis-ci.org/ghoneycutt/puppet-module-rsyslog)


Module to manage rsyslog. Handles both local and remote logging.

Inspired by [saz/rsyslog](https://github.com/saz/puppet-rsyslog/)

This module will ensure that sysklogd is absent, which is needed on EL5.

===

# Compatibility #

This module has been tested to work on the following systems with the
latest Puppet v3, v3 with future parser, v4, v5 and v6.  See `.travis.yml`
for the exact matrix of supported Puppet and ruby versions.

 * Debian 7
 * EL 5
 * EL 6
 * EL 7
 * Suse 10
 * Suse 11
 * Suse 12
 * Solaris 10
 * Solaris 11

===

# Examples
Add the following entries to Hiera.

## Using TLS such as with Papertrail
You will likely have a specific host/port for your account.

<pre>
rsyslog::use_tls: true
rsyslog::permitted_peer: '*.papertrailapp.com'
rsyslog::log_server: 'logs2.papertrailapp.com'
rsyslog::log_server_port: '1234'
rsyslog::ca_file: '/etc/papertrail-bundle.pem'
</pre>

## Centralized syslog server
<pre>
rsyslog::is_log_server: true
</pre>

## Using rsyslog7
<pre>
rsyslog::package:
  - 'rsyslog7'
  - 'rsyslog7-gnutls'
</pre>


===

# Parameters #

package
-------
Name of the rsyslog package. If use_tls is true, the default is the array `['rsyslog','rsyslog-gnutls']`.

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

log_entries
-----------
Array of log entry lines for the rules section. One entry per line. It would be wise to keep it in sync with $logrotate_syslog_files option.
'USE_DEFAULTS' provides the module previous defaults values.

- *Default*: 'USE_DEFAULTS'

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

logrotate_options
-----------------
Array of options to be used for log rotation.
'USE_DEFAULTS' will choose the options based on the osfamily.

- *Default*: 'USE_DEFAULTS'

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

syslogd_options
---------------
String with startup options to pass to rsyslog.

- *Default*: 'USE_DEFAULTS' based on platform

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
Whether a service should be enabled to start at boot. Valid values are true, false, 'manual'.

- *Default*: true

is_log_server
-------------
Boolean to determine if the system syslog service is meant to receive messages from remote hosts.

- *Default*: false

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

remote_template
---------------
Template path to store logs from remote hosts, appended after log_dir

- *Default*: '%HOSTNAME%/%$YEAR%-%$MONTH%-%$DAY%.log'

remote_logging
--------------
Boolean to determine whether to send logs remotely to a centralized logging service.

- *Default*: false

rsyslog_conf_version
--------------------
Format version of rsyslog.conf file format. Supported are version 2 (clients only), 3, 4 and 5. 'USE_DEFAULTS' will choose the version based on the installed package version.

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
String or array of server to send logs to if remote_logging is true. May include an optional port number if you wish to override the log_server_port value for an entry.

*Example:*
<pre>
rsyslog::log_server: 'log'
</pre>
_OR_
<pre>
rsyslog::log_server:
  - 'log1'
  - 'log2:1514'
  - 'log3:2514'
</pre>

- *Default*: "log.${::domain}"

log_server_port
---------------
Default port of the server to send logs to if remote_logging is true. Will not be used if a log_server entry contains a port number.

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

emerg_target
-------------
Target of emergency messages as string. 'USE_DEFAULTS' decides depending on actually running rsyslog version.

- *Default*: 'USE_DEFAULTS'

source_facilities
-----------------
List of source facilities to be sent to remote log server. Only used if remote_logging is true.

- *Default*: `*.*`

use_tls
-------
Boolean to include directives related to using TLS.

- *Default*: false

ca_file
-------
Path to .pem for use with TLS. *Required* if use_tls is true.

- *Default*: undef

permitted_peer
--------------
Permitted peer for TLS. Value of `$ActionSendStreamDriverPermittedPeer` setting in rsyslog.conf. *Required* if use_tls is true.

- *Default*: undef

umask
--------------
The rsyslogd processes' umask. If not specified, the system-provided default is used. The value given must always be a 4-digit octal number, with the initial digit being zero.

- *Default*: undef

file_create_mode
--------------
The creation mode with which rsyslogd creates new files. The value given must always be a 4-digit octal number, with the initial digit being zero.

- *Default*: '0644'

dir_create_mode
--------------
The creation mode with which rsyslogd creates new directories.

- *Default*: '0700'

work_directory
--------------
The default location for work (spool) files.

- *Default*: '/var/lib/rsyslog'

journalstate_file
-----------------
The journal state file used by rsyslog.

- *Default*: 'imjournal.state'

mod_imjournal
-------------
Boolean for using the imjournal module. If set to 'USE_DEFAULTS', this will be chosen based on the platform.

- *Default*: 'USE_DEFAULTS'

manage_devlog
-------------
Boolean for managing /dev/log.  If set to 'USE_DEFAULTS', this will be chosen based on the platform.

- *Default*: 'USE_DEFAULTS'

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
