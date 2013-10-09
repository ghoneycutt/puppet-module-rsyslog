require 'spec_helper'

describe 'rsyslog' do
  describe 'rsyslog_config' do
    let :facts do
      {
        :osfamily          => 'RedHat',
        :lsbmajdistrelease => '6',
        :domain            => 'defaultdomain',
      }
    end
    context 'attributes' do
      context 'with default params' do
        it {
          should contain_file('rsyslog_config').with({
            'path'    => '/etc/rsyslog.conf',
            'owner'   => 'root',
            'group'   => 'root',
            'mode'    => '0644',
            'require' => 'Package[rsyslog_package]',
            'notify'  => 'Service[rsyslog_daemon]',
          })
        }
      end
    end
    context 'rsyslog config content' do
      context 'with default params' do
        it {
          should contain_file('rsyslog_config') \
            .with_content(/^kern.\*\s+\/var\/log\/messages$/)
          should_not contain_file('rsyslog_config') \
            .with_content(/^\$ModLoad imudp.so$/) \
            .with_content(/^\$ModLoad imtcp.so$/) \
            .with_content(/^\$template RemoteHost, "\/srv\/logs\/%HOSTNAME%\/%\$YEAR%-%\$MONTH%-%\$DAY%.log"$/) \
            .with_content(/^\$WorkDirectory \/var\/spool\/rsyslog # where to place spool files\n\$ActionQueueFileName queue # unique name prefix for spool files\n\$ActionQueueMaxDiskSpace 1g # 1gb space limit \(use as much as possible\)\n\$ActionQueueSaveOnShutdown on # save messages to disk on shutdown\n\$ActionQueueType LinkedList   # run asynchronously\n\$ActionResumeRetryCount -1    # infinite retries if host is down$/) \
            .with_content(/^\*.\* @@log.defaultdomain:514/) \
            .with_content(/^\$RuleSet remote\n\*.\* \?RemoteHost$/) \
            .with_content(/^\$InputTCPServerBindRuleset remote$/) \
            .with_content(/^\$InputTCPServerRun 514$/) \
            .with_content(/^\$InputUDPServerBindRuleset remote$/) \
            .with_content(/^\$UDPServerRun 514$/)
        }
      end
      context 'with is_log_server=true' do
        let :params do
          {
            :is_log_server => 'true',
          }
        end
        it {
          should contain_file('rsyslog_config') \
            .with_content(/^kern.\*\s+\/var\/log\/messages$/) \
            .with_content(/^\$ModLoad imtcp.so$/) \
            .with_content(/^\$template RemoteHost, "\/srv\/logs\/%HOSTNAME%\/%\$YEAR%-%\$MONTH%-%\$DAY%.log"$/) \
            .with_content(/^\$RuleSet remote\n\*.\* \?RemoteHost$/) \
            .with_content(/^\$InputTCPServerBindRuleset remote$/) \
            .with_content(/^\$InputTCPServerRun 514$/)
          should_not contain_file('rsyslog_config') \
            .with_content(/^\$ModLoad imudp.so$/) \
            .with_content(/^\$WorkDirectory \/var\/spool\/rsyslog # where to place spool files\n\$ActionQueueFileName queue # unique name prefix for spool files\n\$ActionQueueMaxDiskSpace 1g # 1gb space limit \(use as much as possible\)\n\$ActionQueueSaveOnShutdown on # save messages to disk on shutdown\n\$ActionQueueType LinkedList   # run asynchronously\n\$ActionResumeRetryCount -1    # infinite retries if host is down$/) \
            .with_content(/^\*.\* @@log.defaultdomain:514/) \
            .with_content(/^\$InputUDPServerBindRuleset remote$/) \
            .with_content(/^\$UDPServerRun 514$/)
        }
      end
        context 'with log_dir and remote_template set' do
        let :params do
        {
            :is_log_server => 'true',
            :log_dir => '/foo/bar',
            :remote_template => '%HOSTNAME%.log',
        }
        end
        it {
            should contain_file('rsyslog_config') \
            .with_content(/^\$template RemoteHost, "\/foo\/bar\/%HOSTNAME%.log"$/)
            }
        end
     end
 end

  describe 'rsyslog_package' do
    let :facts do
      {
        :osfamily          => 'RedHat',
        :lsbmajdistrelease => '6',
      }
    end
    context 'with default params' do
      it { should contain_package('rsyslog_package').with( { 'name' => 'rsyslog' } ) }
    end

    context 'with package_ensure=absent' do
      let (:params) { { :package_ensure => 'absent' } }
      it {
        should contain_package('rsyslog_package').with({
          'name'   => 'rsyslog',
          'ensure' => 'absent',
        })
      }
    end
  end

  describe 'rsyslog_daemon' do
    let :facts do
      {
        :osfamily          => 'RedHat',
        :lsbmajdistrelease => '6',
      }
    end
    context 'with default params' do
      it { should contain_service('rsyslog_daemon').with( { 'name' => 'rsyslog' } ) }
    end

    context 'with daemon_ensure=stopped' do
      let (:params) { { :daemon_ensure => 'stopped' } }
      it {
        should contain_service('rsyslog_daemon').with({
          'name'   => 'rsyslog',
          'ensure' => 'stopped',
        })
      }
    end
  end

  describe 'rsyslog_logrotate_d_config' do
    let :facts do
      {
        :osfamily          => 'RedHat',
        :lsbmajdistrelease => '6',
      }
    end
    context 'with default params' do
      it {
        should contain_file('rsyslog_logrotate_d_config').with({
          'path'    => '/etc/logrotate.d/syslog',
          'owner'   => 'root',
          'group'   => 'root',
          'mode'    => '0644',
          'require' => 'Package[rsyslog_package]',
        })
      }
    end
  end

  describe 'rsyslog_sysconfig' do
    context 'on Debian' do
      let :facts do
        {
          :osfamily => 'Debian',
        }
      end
      context 'with default params' do
        it {
          should contain_file('rsyslog_sysconfig').with({
            'path'    => '/etc/default/rsyslog',
            'owner'   => 'root',
            'group'   => 'root',
            'mode'    => '0644',
            'require' => 'Package[rsyslog_package]',
            'notify'  => 'Service[rsyslog_daemon]',
          })
        }
        it {
          should contain_file('rsyslog_sysconfig').with_content(/^RSYSLOGD_OPTIONS="-c5"$/)
        }
      end
    end
    context 'on EL 6' do
      let :facts do
        {
          :osfamily => 'RedHat',
          :lsbmajdistrelease => '6',
        }
      end
      context 'with default params' do
        it {
          should contain_file('rsyslog_sysconfig').with({
            'path'    => '/etc/sysconfig/rsyslog',
            'owner'   => 'root',
            'group'   => 'root',
            'mode'    => '0644',
            'require' => 'Package[rsyslog_package]',
            'notify'  => 'Service[rsyslog_daemon]',
          })
        }
        it {
          should contain_file('rsyslog_sysconfig').with_content(/^SYSLOGD_OPTIONS="-c 4"$/)
        }
      end
    end
    context 'on EL 5' do
      let :facts do
        {
          :osfamily => 'RedHat',
          :lsbmajdistrelease => '5',
        }
      end
      context 'with default params' do
        it {
          should contain_file('rsyslog_sysconfig').with({
            'path'    => '/etc/sysconfig/rsyslog',
            'owner'   => 'root',
            'group'   => 'root',
            'mode'    => '0644',
            'require' => 'Package[rsyslog_package]',
            'notify'  => 'Service[rsyslog_daemon]',
          })
        }
        it {
          should contain_file('rsyslog_sysconfig').with_content(/^SYSLOGD_OPTIONS="-m 0"$/)
          should contain_file('rsyslog_sysconfig').with_content(/^KLOGD_OPTIONS="-x"$/)
        }
      end
    end
  end

  describe 'case is_log_server, default params' do
    let :facts do
      {
        :osfamily => 'RedHat',
        :lsbmajdistrelease => '6',
      }
    end
    context 'case true' do
      let(:params) { { :is_log_server => 'true' } }
      it {
        should include_class('common')
      }

      it {
        should contain_file('/srv/logs').with({
          'require' => 'Common::Mkdir_p[/srv/logs]'
        })
      }
    end
    context 'case default' do
      let(:params) { { :is_log_server => 'undefined' } }
      it do
        expect {
          should include_class('rsyslog')
        }.to raise_error(Puppet::Error,/rsyslog::is_log_server must is undefined and must be \'true\' or \'false\'./)
      end
    end
  end

  describe 'module platform support' do
    context 'on supported osfamily, RedHat' do
      context 'on unsupported major release 4' do
        let :facts do
          {
            :osfamily          => 'RedHat',
            :lsbmajdistrelease => '4',
          }
        end
        it do
          expect {
            should include_class('rsyslog')
          }.to raise_error(Puppet::Error,/rsyslog supports redhat like systems with major release of 5 and 6 and you have 4/)
        end
      end
      context 'on supported major release 5' do
        let :facts do
          {
            :osfamily          => 'RedHat',
            :lsbmajdistrelease => '5',
          }
        end
        it { should include_class('rsyslog') }
      end
      context 'on supported major release 6' do
        let :facts do
          {
            :osfamily          => 'RedHat',
            :lsbmajdistrelease => '6',
          }
        end
        it { should include_class('rsyslog') }
      end
    end
    context 'on supported osfamily, Debian' do
        let :facts do
            {
                :osfamily         => 'Debian',
            }
        end
        it { should include_class('rsyslog') }
    end
    context 'on unsupported osfamily, Suse' do
      let(:facts) { { :osfamily => 'Suse' } }
      it do
        expect {
          should include_class('rsyslog')
        }.to raise_error(Puppet::Error,/rsyslog supports osfamily redhat and Debian. Detected osfamily is Suse/)
      end
    end
  end
end
