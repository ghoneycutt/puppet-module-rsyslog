# == Class: rsyslog
#
# rsyslog class manages syslog and handles both local and remote logging.
#
# Supports osfamily RedHat versions 5 and 6.
#
# == Parameters:
#
# [*is_log_server*]
# is this system a syslog server meant to receive messages from remote hosts?
# - default: false
#
# [*log_dir*]
# path to store logs, if $is_log_server is true
# rsyslog will ensure this path exists, no need to model in Puppet
# - default: /srv/logs
#
# [*default_remote_logging*]
# by default, do we log remotely to a centralized logging service?
# - default: false
#
# [*max_spool_size*]
# rsyslog uses one letter units such as k, m, and g.
# - default: 1g
#
# [*transport_protocol*]
# transport protocols can be tcp or udp
# - default: tcp
#
# [*log_server*]
# Where to send logs. This only applies if *default_remote_logging* is true.
# - default: log.${::domain}
#
class rsyslog (
  $package                  = 'rsyslog',
  $package_ensure           = 'present',
  $logrotate_d_config_path  = '/etc/logrotate.d/syslog',
  $logrotate_d_config_owner = 'root',
  $logrotate_d_config_group = 'root',
  $logrotate_d_config_mode  = '0644',
  $config_path              = '/etc/rsyslog.conf',
  $config_owner             = 'root',
  $config_group             = 'root',
  $config_mode              = '0644',
  $sysconfig_path           = '/etc/sysconfig/rsyslog',
  $sysconfig_owner          = 'root',
  $sysconfig_group          = 'root',
  $sysconfig_mode           = '0644',
  $daemon                   = 'rsyslog',
  $daemon_ensure            = 'running',
  $is_log_server            = 'false',
  $log_dir                  = '/srv/logs',
  $default_remote_logging   = 'false',
  $spool_dir                = '/var/spool/rsyslog',
  $max_spool_size           = '1g',
  $transport_protocol       = 'tcp',
  $log_server               = "log.${::domain}",
  $log_server_port          = '514',
  $enable_tcp_server        = undef,
  $enable_udp_server        = undef,
  $kernel_target            = '/var/log/messages',
) {

  # ensures that sysklogd is absent, which is needed on EL5
  require 'sysklogd'

  case $::osfamily {
    'redhat': {
      case $::lsbmajdistrelease {
        '5': {
          $sysconfig_erb = 'sysconfig.rhel5.erb'
        }
        '6': {
          $sysconfig_erb = 'sysconfig.rhel6.erb'
        }
        default: {
          fail("rsyslog supports redhat like systems with major release of 5 and 6 and you have ${::lsbmajdistrelease}")
        }
      }
    }
    default: {
      fail("rsyslog supports osfamily redhat and you have ${::osfamily}")
    }
  }

  case $is_log_server {
    # logging servers do not log elsewhere
    'true': {
      $remote_logging = 'false'

      include common

      common::mkdir_p { $log_dir: }

      file { $log_dir:
        ensure  => directory,
        owner   => 'root',
        group   => 'root',
        mode    => '0750',
        require => Common::Mkdir_p[$log_dir],
      }
    }
    # non logging servers use the default
    'false': {
      $remote_logging = $default_remote_logging
    }
    default: {
      fail("rsyslog::is_log_server must is ${is_log_server} and must be \'true\' or \'false\'.")
    }
  }

  case $transport_protocol {
    'tcp': {
      $default_enable_tcp_server = 'true'
      $default_enable_udp_server = 'false'
    }
    'udp': {
      $default_enable_tcp_server = 'false'
      $default_enable_udp_server = 'true'
    }
    default: {
      fail("rsyslog::transport_protocol is ${transport_protocol} and must be \'tcp\' or \'udp\'.")
    }
  }

  if $enable_tcp_server {
    $my_enable_tcp_server = $enable_tcp_server
  } else {
    $my_enable_tcp_server = $default_enable_tcp_server
  }

  if $enable_udp_server {
    $my_enable_udp_server = $enable_udp_server
  } else {
    $my_enable_udp_server = $default_enable_udp_server
  }

  package { 'rsyslog_package':
    ensure => $package_ensure,
    name   => $package,
  }

  file { 'rsyslog_logrotate_d_config':
    ensure  => file,
    source  => 'puppet:///modules/rsyslog/logrotate_d_config',
    path    => $logrotate_d_config_path,
    owner   => $logrotate_d_config_owner,
    group   => $logrotate_d_config_group,
    mode    => $logrotate_d_config_mode,
    require => Package['rsyslog_package'],
  }

  file { 'rsyslog_config':
    ensure  => file,
    content => template('rsyslog/rsyslog.conf.erb'),
    path    => $config_path,
    owner   => $config_owner,
    group   => $config_group,
    mode    => $config_mode,
    require => Package['rsyslog_package'],
    notify  => Service['rsyslog_daemon'],
  }

  file { 'rsyslog_sysconfig':
    ensure  => file,
    content => template("rsyslog/${sysconfig_erb}"),
    path    => $sysconfig_path,
    owner   => $sysconfig_owner,
    group   => $sysconfig_group,
    mode    => $sysconfig_mode,
    require => Package['rsyslog_package'],
    notify  => Service['rsyslog_daemon'],
  }

  service { 'rsyslog_daemon':
    ensure     => $daemon_ensure,
    name       => $daemon,
  }
}
