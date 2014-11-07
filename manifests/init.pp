# ## Class: rsyslog ##
#
# Module to manage rsyslog. Handles both local and remote logging.
#
# Inspired by [saz/rsyslog](https://github.com/saz/puppet-rsyslog/)
#
# This module will ensure that sysklogd is absent, which is needed on EL5.
#
class rsyslog (
  $package                       = 'rsyslog',
  $package_ensure                = 'present',
  $package_provider              = undef,
  $pid_file                      = 'USE_DEFAULTS',
  $logrotate_present             = 'USE_DEFAULTS',
  $logrotate_d_config_path       = '/etc/logrotate.d/syslog',
  $logrotate_d_config_owner      = 'root',
  $logrotate_d_config_group      = 'root',
  $logrotate_d_config_mode       = '0644',
  $logrotate_syslog_files        = 'USE_DEFAULTS',
  $config_path                   = '/etc/rsyslog.conf',
  $config_owner                  = 'root',
  $config_group                  = 'root',
  $config_mode                   = '0644',
  $sysconfig_path                = 'USE_DEFAULTS',
  $sysconfig_owner               = 'root',
  $sysconfig_group               = 'root',
  $sysconfig_mode                = '0644',
  $daemon                        = 'USE_DEFAULTS',
  $daemon_ensure                 = 'running',
  $daemon_enable                 = 'true',
  $is_log_server                 = 'false',
  $log_dir                       = '/srv/logs',
  $log_dir_owner                 = 'root',
  $log_dir_group                 = 'root',
  $log_dir_mode                  = '0750',
  $local_file_monitoring_enabled = false,
  $remote_template               = '%HOSTNAME%/%$YEAR%-%$MONTH%-%$DAY%.log',
  $remote_logging                = 'false',
  $rsyslog_conf_version          = 'USE_DEFAULTS',
  $rsyslog_d_dir                 = '/etc/rsyslog.d',
  $rsyslog_d_dir_owner           = 'root',
  $rsyslog_d_dir_group           = 'root',
  $rsyslog_d_dir_mode            = '0755',
  $rsyslog_d_dir_purge           = true,
  $rsyslog_fragments             = undef,
  $spool_dir                     = '/var/spool/rsyslog',
  $spool_dir_owner               = 'root',
  $spool_dir_group               = 'root',
  $spool_dir_mode                = '0700',
  $max_spool_size                = '1g',
  $transport_protocol            = 'tcp',
  $log_server                    = "log.${::domain}",
  $log_server_port               = '514',
  $enable_tcp_server             = undef,
  $enable_udp_server             = undef,
  $kernel_target                 = '/var/log/messages',
  $source_facilities             = '*.*',
) {

  # validation
  if $source_facilities == '' {
    fail('rsyslog::source_facilities cannot be empty!')
  }

  case $rsyslog_conf_version {
    'USE_DEFAULTS': {
      case versioncmp($::rsyslog_version, 3) {
        '0','1': {
          $rsyslog_conf_version_real = '3'
        }
        default: {
          $rsyslog_conf_version_real = '2'
        }
      }
    }
    default: {
      validate_re($rsyslog_conf_version, '^(2)|(3)$', "rsyslog_conf_version only knows <2>, <3> and <USE_DEFAULTS> as valid values and you have specified <${rsyslog_conf_version}>.")
      $rsyslog_conf_version_real = $rsyslog_conf_version
    }
  }

  if $rsyslog_fragments != undef {
    create_resources('rsyslog::fragment', $rsyslog_fragments)
  }

  case $daemon_enable {
    'true',true: {
      $daemon_enable_real = 'true'
    }
    'false',false: {
      $daemon_enable_real = 'false'
    }
    'manual': {
      $daemon_enable_real = 'manual'
    }
  }

  validate_absolute_path($rsyslog_d_dir)
  validate_re($daemon_ensure, '^(running|stopped)$', "daemon_ensure may be either 'running' or 'stopped' and is set to <${daemon_ensure}>.")
  validate_re($daemon_enable_real, '^(true|false|manual)$', "daemon_enable may be either 'true', 'false' or 'manual' and is set to <${daemon_enable}>.")

  case $::osfamily {
    'RedHat': {
      $default_logrotate_present      = true
      $default_logrotate_syslog_files = [
                                          '/var/log/messages',
                                          '/var/log/secure',
                                          '/var/log/maillog',
                                          '/var/log/spooler',
                                          '/var/log/boot.log',
                                          '/var/log/cron',
                                        ]
      $default_service_name           = 'rsyslog'
      $default_sysconfig_path         = '/etc/sysconfig/rsyslog'
      # Works around new vs. old facter issue -tthayer
      # start workaround
      if $::lsbmajdistrelease == undef {
        $majorversion = $::operatingsystemmajrelease
      }
      else {
        $majorversion = $::lsbmajdistrelease
      }
      case $majorversion {
        '5': {
          $default_pid_file = '/var/run/rsyslogd.pid'
          $sysconfig_erb    = 'sysconfig.rhel5.erb'
        }
        '6': {
          $default_pid_file = '/var/run/syslogd.pid'
          $sysconfig_erb    = 'sysconfig.rhel6.erb'
        }
        '7': {
          $default_pid_file = '/var/run/syslogd.pid'
          $sysconfig_erb    = 'sysconfig.rhel7.erb'
        }
        default: {
          fail("rsyslog supports RedHat like systems with major release of 5, 6 and 7 and you have ${majorversion}")
        }
      }
      #end workaround
      # ensures that sysklogd is absent, which is needed on EL5
      require 'sysklogd'
    }
    'Debian': {
      $default_logrotate_present      = true
      $default_logrotate_syslog_files = [
                                          '/var/log/syslog',
                                          '/var/log/mail.info',
                                          '/var/log/mail.warn',
                                          '/var/log/mail.err',
                                          '/var/log/mail.log',
                                          '/var/log/daemon.log',
                                          '/var/log/kern.log',
                                          '/var/log/auth.log',
                                          '/var/log/user.log',
                                          '/var/log/lpr.log',
                                          '/var/log/cron.log',
                                          '/var/log/debug',
                                          '/var/log/messages',
                                        ]
      $default_service_name           = 'rsyslog'
      $default_sysconfig_path         = '/etc/default/rsyslog'
      $default_pid_file               = '/var/run/rsyslogd.pid'
      $sysconfig_erb                  = 'sysconfig.debian.erb'
    }
    'Suse' : {
      $default_logrotate_present      = true
      $default_logrotate_syslog_files = [
                                          '/var/log/warn',
                                          '/var/log/messages',
                                          '/var/log/allmessages',
                                          '/var/log/localmessages',
                                          '/var/log/firewall',
                                          '/var/log/acpid',
                                          '/var/log/NetworkManager',
                                          '/var/log/mail',
                                          '/var/log/mail.info',
                                          '/var/log/mail.warn',
                                          '/var/log/mail.err',
                                          '/var/log/news/news.crit',
                                          '/var/log/news/news.err',
                                          '/var/log/news/news.notice',
                                        ]
      $default_service_name           = 'syslog'
      $default_sysconfig_path         = '/etc/sysconfig/syslog'
      $default_pid_file               = '/var/run/rsyslogd.pid'
      case $::lsbmajdistrelease {
        '10' : {
          $sysconfig_erb = 'sysconfig.suse10.erb'
        }
        '11' : {
          $sysconfig_erb = 'sysconfig.suse11.erb'
        }
        default: {
          fail("rsyslog supports Suse like systems with major release 10 and 11, and you have ${::lsbmajdistrelease}")
        }
      }
    }
    'Solaris': {
      $default_logrotate_present = false
      case $::kernelrelease {
        '5.10', '5.11' : {
          $default_service_name      = 'network/cswrsyslog'
          $default_pid_file          = '/var/run/rsyslogd.pid'
        }
        default: {
          fail("rsyslog supports Solaris like systems with kernel release 5.10 and 5.11, and you have ${::kernelrelease}")
        }
      }
    }
    default: {
      fail("rsyslog supports osfamilies RedHat, Suse, Debian and Solaris. Detected osfamily is ${::osfamily}")
    }
  }

  $logrotate_present_test = $logrotate_present ? {
    'USE_DEFAULTS' => $default_logrotate_present,
    default        => $logrotate_present
  }

  $logrotate_present_test_type = type($logrotate_present_test)

  case $logrotate_present_test_type {
    'string': {
      $logrotate_present_real = str2bool($logrotate_present_test)
    }
    'boolean': {
      $logrotate_present_real = $logrotate_present_test
    }
    default: {
      fail("rsyslog::logrotate_present must be of type boolean or string. Detected type is <${logrotate_present_test_type}>.")
    }
  }

  if $logrotate_present_real {
    $logrotate_syslog_files_real = $logrotate_syslog_files ? {
      'USE_DEFAULTS' => $default_logrotate_syslog_files,
      default        => unique($logrotate_syslog_files)
    }
    validate_array($logrotate_syslog_files_real)
  }

  $service_name_real = $daemon ? {
    'USE_DEFAULTS' => $default_service_name,
    default        => $daemon
  }

  $sysconfig_path_real = $sysconfig_path ? {
    'USE_DEFAULTS' => $default_sysconfig_path,
    default        => $sysconfig_path
  }

  $pid_file_real = $pid_file ? {
    'USE_DEFAULTS' => $default_pid_file,
    default        => $pid_file
  }
  validate_absolute_path($pid_file_real)

  case $is_log_server {
    # logging servers do not log elsewhere
    'true': {
      $remote_logging_real = 'false'

      include common

      common::mkdir_p { $log_dir: }

      file { 'log_dir':
        ensure  => directory,
        path    => $log_dir,
        owner   => $log_dir_owner,
        group   => $log_dir_group,
        mode    => $log_dir_mode,
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

  if type($rsyslog_d_dir_purge) == 'string' {
    $rsyslog_d_dir_purge_real = str2bool($rsyslog_d_dir_purge)
  } else {
    $rsyslog_d_dir_purge_real = $rsyslog_d_dir_purge
  }
  validate_bool($rsyslog_d_dir_purge_real)

  package { $package:
    ensure   => $package_ensure,
    provider => $package_provider,
  }

  if $::kernel == 'Linux' {
    file { 'rsyslog_sysconfig':
      ensure  => file,
      content => template("rsyslog/${rsyslog::sysconfig_erb}"),
      path    => $rsyslog::sysconfig_path_real,
      owner   => $rsyslog::sysconfig_owner,
      group   => $rsyslog::sysconfig_group,
      mode    => $rsyslog::sysconfig_mode,
      require => Package[$package],
      notify  => Service['rsyslog_daemon'],
    }
  }

  if $logrotate_present_real {
    file { 'rsyslog_logrotate_d_config':
      ensure  => file,
      path    => $logrotate_d_config_path,
      owner   => $logrotate_d_config_owner,
      group   => $logrotate_d_config_group,
      mode    => $logrotate_d_config_mode,
      content => template('rsyslog/logrotate.erb'),
      require => Package[$package],
    }
  }

  file { 'rsyslog_config':
    ensure  => file,
    content => template('rsyslog/rsyslog.conf.erb'),
    path    => $config_path,
    owner   => $config_owner,
    group   => $config_group,
    mode    => $config_mode,
    require => Package[$package],
    notify  => Service['rsyslog_daemon'],
  }

  common::mkdir_p { $rsyslog_d_dir: }

  file { 'rsyslog_d_dir':
    ensure  => directory,
    path    => $rsyslog_d_dir,
    owner   => $rsyslog_d_dir_owner,
    group   => $rsyslog_d_dir_group,
    mode    => $rsyslog_d_dir_mode,
    recurse => true,
    purge   => $rsyslog_d_dir_purge_real,
    require => Common::Mkdir_p[$rsyslog_d_dir],
  }

  service { 'rsyslog_daemon':
    ensure     => $daemon_ensure,
    enable     => $daemon_enable_real,
    name       => $service_name_real,
  }

  if $remote_logging == 'true' {
    common::mkdir_p { $spool_dir: }

    file { 'ryslog_spool_directory':
      ensure  => directory,
      path    => $spool_dir,
      owner   => $spool_dir_owner,
      group   => $spool_dir_group,
      mode    => $spool_dir_mode,
      require => Common::Mkdir_p[$spool_dir],
    }
  }
}
