# ## Class: rsyslog ##
#
# Module to manage rsyslog. Handles both local and remote logging.
#
# Inspired by [saz/rsyslog](https://github.com/saz/puppet-rsyslog/)
#
# This module will ensure that sysklogd is absent, which is needed on EL5.
#
class rsyslog (
  $package                  = 'USE_DEFAULTS',
  $package_ensure           = 'present',
  $package_provider         = undef,
  $pid_file                 = 'USE_DEFAULTS',
  $log_entries              = 'USE_DEFAULTS',
  $logrotate_options        = 'USE_DEFAULTS',
  $logrotate_present        = 'USE_DEFAULTS',
  $logrotate_d_config_path  = '/etc/logrotate.d/syslog',
  $logrotate_d_config_owner = 'root',
  $logrotate_d_config_group = 'root',
  $logrotate_d_config_mode  = '0644',
  $logrotate_syslog_files   = 'USE_DEFAULTS',
  $config_path              = '/etc/rsyslog.conf',
  $config_owner             = 'root',
  $config_group             = 'root',
  $config_mode              = '0644',
  $sysconfig_path           = 'USE_DEFAULTS',
  $sysconfig_owner          = 'root',
  $sysconfig_group          = 'root',
  $sysconfig_mode           = '0644',
  $syslogd_options          = 'USE_DEFAULTS',
  $daemon                   = 'USE_DEFAULTS',
  $daemon_ensure            = 'running',
  $daemon_enable            = true,
  $is_log_server            = false,
  $log_dir                  = '/srv/logs',
  $log_dir_owner            = 'root',
  $log_dir_group            = 'root',
  $log_dir_mode             = '0750',
  $remote_template          = '%HOSTNAME%/%$YEAR%-%$MONTH%-%$DAY%.log',
  $remote_logging           = false,
  $rsyslog_conf_version     = 'USE_DEFAULTS',
  $rsyslog_d_dir            = '/etc/rsyslog.d',
  $rsyslog_d_dir_owner      = 'root',
  $rsyslog_d_dir_group      = 'root',
  $rsyslog_d_dir_mode       = '0755',
  $rsyslog_d_dir_purge      = true,
  $rsyslog_fragments        = undef,
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
  $emerg_target             = 'USE_DEFAULTS',
  $source_facilities        = '*.*',
  $use_tls                  = false,
  $ca_file                  = undef,
  $permitted_peer           = undef,
  $umask                    = undef,
  $file_create_mode         = '0644',
  $dir_create_mode          = '0700',
) {

  # validation
  if $source_facilities == '' {
    fail('rsyslog::source_facilities cannot be empty!')
  }

  if is_string($use_tls) == true {
    $use_tls_real = str2bool($use_tls)
  } else {
    $use_tls_real = $use_tls
  }
  validate_bool($use_tls_real)

  if $package == 'USE_DEFAULTS' {
    if $use_tls_real == true {
      $package_real = [ 'rsyslog',
                        'rsyslog-gnutls',
                      ]
    } else {
      $package_real = 'rsyslog'
    }
  } else {
    $package_real = $package
  }

  if $use_tls_real == true {
    validate_absolute_path($ca_file)
    validate_string($permitted_peer)
  }

  if $umask {
    validate_re($umask, '^0[0-7]{3}$',
      "rsyslog::umask is <${umask}> and must be a valid four digit mode in octal notation with a leading zero.")
  }

  validate_re($file_create_mode, '^0[0-7]{3}$',
    "rsyslog::file_create_mode is <${file_create_mode}> and must be a valid four digit mode in octal notation with a leading zero.")

  validate_re($dir_create_mode, '^[0-7]{4}$',
    "rsyslog::dir_create_mode is <${dir_create_mode}> and must be a valid four digit mode in octal notation.")

  # setting default values depending on the running rsyslog version
  # Force puppet to save numbers as integers instead of strings (0 + X)
  # https://tickets.puppetlabs.com/browse/PUP-2735
  if (versioncmp("${::rsyslog_version}", '5') >= 0) { # lint:ignore:only_variable_string
    $default_rsyslog_conf_version = 0 + 5
    $default_emerg_target         = ':omusrmsg:*'
  } elsif (versioncmp("${::rsyslog_version}", '4') >= 0) { # lint:ignore:only_variable_string
    $default_rsyslog_conf_version = 0 + 4
    $default_emerg_target         = '*'
  } elsif (versioncmp("${::rsyslog_version}", '3') >= 0) { # lint:ignore:only_variable_string
    $default_rsyslog_conf_version = 0 + 3
    $default_emerg_target         = '*'
  } else {
    $default_rsyslog_conf_version = 0 + 2
    $default_emerg_target         = '*'
  }

  case $rsyslog_conf_version {
    'USE_DEFAULTS': {
      $rsyslog_conf_version_real = $default_rsyslog_conf_version
    }
    default: {
      validate_re($rsyslog_conf_version, '^(2)|(3)|(4)|(5)|(6)|(7)|(8)$', "rsyslog_conf_version only knows <2>, <3>, <4>, <5>, <6>, <7>, <8> and <USE_DEFAULTS> as valid values and you have specified <${rsyslog_conf_version}>.")
      $rsyslog_conf_version_real = 0 + $rsyslog_conf_version
    }
  }

  if $emerg_target == 'USE_DEFAULTS' {
    $emerg_target_real = $default_emerg_target
  } else {
    $emerg_target_real = $emerg_target
  }
  validate_string($emerg_target_real)

  if $rsyslog_fragments != undef {
    create_resources('rsyslog::fragment', $rsyslog_fragments)
  }

  if is_string($daemon_enable) == true and $daemon_enable != 'manual' {
    $daemon_enable_almostreal = str2bool($daemon_enable)
  } else {
    $daemon_enable_almostreal = $daemon_enable
  }

  case $daemon_enable_almostreal {
    true: {
      $daemon_enable_real = true
    }
    false: {
      $daemon_enable_real = false
    }
    'manual': {
      $daemon_enable_real = 'manual'
    }
    default: {
      fail("daemon_enable may be either true, false or 'manual' and is set to <${daemon_enable}>.")
    }
  }

  validate_absolute_path($rsyslog_d_dir)
  validate_re($daemon_ensure, '^(running|stopped)$', "daemon_ensure may be either 'running' or 'stopped' and is set to <${daemon_ensure}>.")
  validate_absolute_path($kernel_target)

  case $::osfamily {
    'RedHat': {
      $default_logrotate_present      = true
      $default_service_name           = 'rsyslog'
      $default_sysconfig_path         = '/etc/sysconfig/rsyslog'
      case $::lsbmajdistrelease {
        '5': {
          $default_pid_file        = '/var/run/rsyslogd.pid'
          $sysconfig_erb           = 'sysconfig.rhel5.erb'
          $default_syslogd_options = '-m 0'
        }
        '6': {
          $default_pid_file        = '/var/run/syslogd.pid'
          $sysconfig_erb           = 'sysconfig.rhel6.erb'
          $default_syslogd_options = ''
        }
        '7': {
          $default_pid_file        = '/var/run/syslogd.pid'
          $sysconfig_erb           = 'sysconfig.rhel7.erb'
          $default_syslogd_options = '-c 4'
        }
        default: {
          fail("rsyslog supports RedHat like systems with major release of 5, 6 and 7 and you have ${::lsbmajdistrelease}")
        }
      }
      # ensures that sysklogd is absent, which is needed on EL5
      require 'sysklogd'
    }
    'Debian': {
      $default_logrotate_present      = true
      $default_service_name           = 'rsyslog'
      $default_sysconfig_path         = '/etc/default/rsyslog'
      $default_pid_file               = '/var/run/rsyslogd.pid'
      $sysconfig_erb                  = 'sysconfig.debian.erb'
      $default_syslogd_options        = '-c5'
    }
    'Suse' : {
      $default_logrotate_present      = true
      $default_service_name           = 'syslog'
      $default_sysconfig_path         = '/etc/sysconfig/syslog'
      $default_syslogd_options        = ''
      $default_pid_file               = '/var/run/rsyslogd.pid'
      case $::lsbmajdistrelease {
        '10' : {
          $sysconfig_erb = 'sysconfig.suse10.erb'
        }
        '11' : {
          $sysconfig_erb = 'sysconfig.suse11.erb'
        }
        '12' : {
          $sysconfig_erb = 'sysconfig.suse12.erb'
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

  if is_bool($logrotate_present) == true {
    $logrotate_present_real = $logrotate_present
  } else {
    $logrotate_present_real = $logrotate_present ? {
      'USE_DEFAULTS' => $default_logrotate_present,
      default        => str2bool($logrotate_present)
    }
  }

  $syslogd_options_real = $syslogd_options ? {
    'USE_DEFAULTS' => $default_syslogd_options,
    default        => $syslogd_options
  }
  validate_string($syslogd_options_real)

  $pid_file_real = $pid_file ? {
    'USE_DEFAULTS' => $default_pid_file,
    default        => $pid_file
  }
  validate_absolute_path($pid_file_real)

  $default_log_entries = [
    '# Log all kernel messages to the console.',
    '# Logging much else clutters up the screen.',
    '#kern.*                                                 /dev/console',
    "kern.*                                                  ${kernel_target}",
    '',
    '# Log anything (except mail) of level info or higher.',
    '# Don\'t log private authentication messages!',
    '*.info;mail.none;authpriv.none;cron.none                /var/log/messages',
    '',
    '# The authpriv file has restricted access.',
    'authpriv.*                                              /var/log/secure',
    '',
    '# Log all the mail messages in one place.',
    'mail.*                                                  -/var/log/maillog',
    '',
    '# Log cron stuff',
    'cron.*                                                  /var/log/cron',
    '',
    '# Everybody gets emergency messages',
    "*.emerg                                                 ${emerg_target_real}",
    '',
    '# Save news errors of level crit and higher in a special file.',
    'uucp,news.crit                                          /var/log/spooler',
    '',
    '# Save boot messages also to boot.log',
    'local7.*                                                /var/log/boot.log',
  ]

  $log_entries_real = $log_entries ? {
    'USE_DEFAULTS' => $default_log_entries,
    default        => $log_entries
  }

  validate_array($log_entries_real)

  if $logrotate_present_real {
    case $::osfamily {
      'Debian': {
        $default_logrotate_syslog_files = [
                                            $kernel_target,
                                            '/var/log/messages',
                                            '/var/log/secure',
                                            '/var/log/maillog',
                                            '/var/log/spooler',
                                            '/var/log/boot.log',
                                            '/var/log/cron',
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
                                          ]
        $default_logrotate_options      = [
                                            'rotate 4',
                                            'weekly',
                                            'missingok',
                                            'notifempty',
                                            'compress',
                                            'delaycompress',
                                            'sharedscripts',
                                            'postrotate',
                                            '    invoke-rc.d rsyslog rotate > /dev/null',
                                            'endscript',
                                          ]
      }
      'Suse': {
        $default_logrotate_syslog_files = [
                                            $kernel_target,
                                            '/var/log/messages',
                                            '/var/log/secure',
                                            '/var/log/maillog',
                                            '/var/log/spooler',
                                            '/var/log/boot.log',
                                            '/var/log/cron',
                                            '/var/log/warn',
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
        $default_logrotate_options      = [
                                            'compress',
                                            'dateext',
                                            'maxage 365',
                                            'rotate 99',
                                            'missingok',
                                            'notifempty',
                                            'size +4096k',
                                            'create 640 root root',
                                            'sharedscripts',
                                            'postrotate',
                                            '    service syslog reload > /dev/null',
                                            'endscript',
                                          ]
      }
      'RedHat', default: {
        $default_logrotate_syslog_files = [
                                            $kernel_target,
                                            '/var/log/messages',
                                            '/var/log/secure',
                                            '/var/log/maillog',
                                            '/var/log/spooler',
                                            '/var/log/boot.log',
                                            '/var/log/cron',
                                          ]
        $default_logrotate_options      = [
                                            'sharedscripts',
                                            'postrotate',
                                            "    /bin/kill -HUP `cat ${pid_file_real} 2> /dev/null` 2> /dev/null || true",
                                            'endscript',
                                          ]
      }
    }

    $logrotate_options_real = $logrotate_options ? {
      'USE_DEFAULTS' => $default_logrotate_options,
      default        => $logrotate_options
    }
    validate_array($logrotate_options_real)

    $logrotate_syslog_files_real = $logrotate_syslog_files ? {
      'USE_DEFAULTS' => unique($default_logrotate_syslog_files),
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

  if is_string($is_log_server) == true {
    $is_log_server_real = str2bool($is_log_server)
  } else {
    $is_log_server_real = $is_log_server
  }
  validate_bool($is_log_server_real)

  if is_string($remote_logging) == true {
    $remote_logging_bool = str2bool($remote_logging)
  } else {
    $remote_logging_bool = $remote_logging
  }
  validate_bool($remote_logging_bool)

  if $is_log_server_real == true {
    # logging servers do not log elsewhere
    $remote_logging_real = false

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
  } else {
    # non logging servers use the default
    $remote_logging_real = $remote_logging_bool
  }

  case $transport_protocol {
    'tcp': {
      $default_enable_tcp_server = true
      $default_enable_udp_server = false
    }
    'udp': {
      $default_enable_tcp_server = false
      $default_enable_udp_server = true
    }
    default: {
      fail("rsyslog::transport_protocol is ${transport_protocol} and must be \'tcp\' or \'udp\'.")
    }
  }

  if $enable_tcp_server != undef {
    $my_enable_tcp_server = $enable_tcp_server
  } else {
    $my_enable_tcp_server = $default_enable_tcp_server
  }

  if $enable_udp_server != undef {
    $my_enable_udp_server = $enable_udp_server
  } else {
    $my_enable_udp_server = $default_enable_udp_server
  }

  if is_string($rsyslog_d_dir_purge) == true {
    $rsyslog_d_dir_purge_real = str2bool($rsyslog_d_dir_purge)
  } else {
    $rsyslog_d_dir_purge_real = $rsyslog_d_dir_purge
  }
  validate_bool($rsyslog_d_dir_purge_real)

  package { $package_real:
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
      require => Package[$package_real],
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
      require => Package[$package_real],
    }
  }

  if $::rsyslog_version {
    file { 'rsyslog_config':
      ensure  => file,
      content => template('rsyslog/rsyslog.conf.erb'),
      path    => $config_path,
      owner   => $config_owner,
      group   => $config_group,
      mode    => $config_mode,
      require => Package[$package_real],
      notify  => Service['rsyslog_daemon'],
    }
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
    ensure => $daemon_ensure,
    enable => $daemon_enable_real,
    name   => $service_name_real,
  }

  if $remote_logging_real == true {

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
