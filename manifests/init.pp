# ## Class: rsyslog ##
#
# Module to manage rsyslog. Handles both local and remote logging.
#
# Inspired by [saz/rsyslog](https://github.com/saz/puppet-rsyslog/)
#
# This module will ensure that sysklogd is absent, which is needed on EL5.
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
  $sysconfig_path           = 'USE_DEFAULTS',
  $sysconfig_owner          = 'root',
  $sysconfig_group          = 'root',
  $sysconfig_mode           = '0644',
  $daemon                   = 'rsyslog',
  $daemon_ensure            = 'running',
  $is_log_server            = 'false',
  $log_dir                  = '/srv/logs',
  $remote_template          = '%HOSTNAME%/%$YEAR%-%$MONTH%-%$DAY%.log',
  $remote_logging           = 'false',
  $spool_dir                = '/var/spool/rsyslog',
  $spool_dir_owner          = 'root',
  $spool_dir_group          = 'root',
  $spool_dir_mode           = '0700',
  $max_spool_size           = '1g',
  $transport_protocol       = 'tcp',
  $log_server               = "log.${::domain}",
  $log_server_port          = '514',
  $enable_tcp_server        = undef,
  $enable_udp_server        = undef,
  $kernel_target            = '/var/log/messages',
  $source_facilities        = '*.*',
) {

  # validation
  if $source_facilities == '' {
    fail("rsyslog::source_facilities cannot be empty!")
  }

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
      # ensures that sysklogd is absent, which is needed on EL5
      require 'sysklogd'

      if $sysconfig_path == 'USE_DEFAULTS' {
        $real_sysconfig_path = '/etc/sysconfig/rsyslog'
      } else {
        $real_sysconfig_path = $sysconfig_path
      }

    }
    'Debian': {
      $sysconfig_erb = 'sysconfig.debian.erb'

      if $sysconfig_path == 'USE_DEFAULTS' {
        $real_sysconfig_path = '/etc/default/rsyslog'
      } else {
        $real_sysconfig_path = $sysconfig_path
      }
    }
    default: {
      fail("rsyslog supports osfamily redhat and Debian. Detected osfamily is ${::osfamily}")
    }
  }

  case $is_log_server {
    # logging servers do not log elsewhere
    'true': {
      $remote_logging_real = 'false'

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
      $remote_logging_real = $remote_logging
    }
    default: {
      fail("rsyslog::is_log_server is ${is_log_server} and must be \'true\' or \'false\'.")
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
    path    => $real_sysconfig_path,
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

  if $remote_logging == 'true' {
    common::mkdir_p { $spool_dir: }

    file { 'ryslog_spool_directory':
      ensure  => 'directory',
      path    => $spool_dir,
      owner   => $spool_dir_owner,
      group   => $spool_dir_group,
      mode    => $spool_dir_mode,
      require => Common::Mkdir_p[$spool_dir],
    }
  }
}
