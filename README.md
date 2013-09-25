# rsyslog module #
===

[![Build Status](https://travis-ci.org/ghoneycutt/puppet-module-rsyslog.png)](https://travis-ci.org/ghoneycutt/puppet-module-rsyslog)

[![Build Status](
https://api.travis-ci.org/ghoneycutt/puppet-module-rsyslog.png?branch=master)](https://travis-ci.org/ghoneycutt/puppet-module-rsyslog)


Module to manage rsyslog. Handles both local and remote logging.

Inspired by [saz/rsyslog](https://github.com/saz/puppet-rsyslog/)

This module will ensure that sysklogd is absent, which is needed on EL5.

===

# Compatability #

This module has been tested to work on the following systems.

 * EL 5
 * EL 6

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

- *Default*: 'rsyslog'

daemon_ensure
-------------
Whether a service should be running. Valid values are 'stopped' and 'running'.

- *Default*: 'running'

is_log_server
-------------
Whether the system syslog service is meant to recieve messages from remote hosts. Valid values are 'true' and 'false'. 

- *Default*: 'false'

log_dir
-------
Path to store logs, if $is_log_server is true.

- *Default*: '/srv/logs'

remote_template
---------------
Template path to store logs from remote hosts, appended after log_dir

- *Default*: '%HOSTNAME%/%$YEAR%-%$MONTH%-%$DAY%.log'

default_remote_logging
----------------------
Wheter to send logs remotely to a centralized logging service.

- *Default*: 'false'

spool_dir
---------
Path to place spool files.

- *Default*: '/var/spool/rsyslog'

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
Server to send logs to if $default_remote_logging is 'true'.

- *Default*: "log.${::domain}"

log_server_port
---------------
Port of the server to send logs to if $default_remote_logging is 'true'.

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
