class rsyslog::rsyslogdb(
  $mysql_package = 'mysql-server',
  $mysql_daemon  = 'mysqld',
  $mysqlconfig_path  = '/etc/my.cnf',
  $rsyslog_mysql_package = 'rsyslog-mysql',
  $db_name = 'Syslog',
  $db_user_name = 'rsyslog',
  $db_secert = 'rsyslog',
) inherits rsyslog {
  file { 'mysql_conf' :
    ensure  => file,
    source  => 'puppet:///modules/rsyslog/my.cnf',
    path    => $mysqlconfig_path,
    owner   => $config_owner,
    group   => $config_group,
    mode    => $config_mode,
    require => Package['mysql_package'],
    notify  => Service['mysql_service'],
  }
  package { 'mysql_package' :
    ensure   => $package_ensure,
    name     => $mysql_package,

  }
  service { 'mysql_service' :
    ensure   => $daemon_ensure,
    name => $mysql_daemon,
  }

  file { '/tmp/createDB.sql' :
    ensure  => $file_ensure,
    content => template('rsyslog/createDB.sql.erb'),
    mode    => 700,
    owner   => 'root',
    } ->
  exec { 'mysql < /tmp/createDB.sql' :
    creates => "/var/lib/mysql/Syslog",
    path    => "/usr/bin:/usr/sbin",
    require => Package['mysql_package'],
  }

  package { 'rsyslog_mysql' :
    ensure => $package_ensure,
    name   => $rsyslog_mysql_package,
  }
}
