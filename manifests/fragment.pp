# == Class: rsyslog::fragment
#
# Places a fragment in $rsyslog_d_dir directory
#
define rsyslog::fragment (
  $ensure  = 'file',
  $content = undef,
) {

  include rsyslog

  validate_re($ensure, ['file','present','absent'])
  validate_string($content)

  file { "${rsyslog::rsyslog_d_dir}/${name}.conf":
    ensure  => $ensure,
    content => $content,
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    require => Common::Mkdir_p[$rsyslog::rsyslog_d_dir],
    notify  => Service['rsyslog_daemon'],
  }
}
