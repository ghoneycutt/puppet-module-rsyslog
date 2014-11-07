require 'spec_helper'
describe 'rsyslog' do

  describe 'rsyslog_config' do
    let :facts do
      {
        :kernel            => 'Linux',
        :osfamily          => 'RedHat',
        :lsbmajdistrelease => '6',
        :domain            => 'defaultdomain',
        :rsyslog_version   => '5.8.10',
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
            'require' => 'Package[rsyslog]',
            'notify'  => 'Service[rsyslog_daemon]',
          })
        }
      end
    end

    context 'rsyslog config content' do
      context 'with default params' do
        it { should contain_file('rsyslog_config').with_content(/^kern.\*\s+\/var\/log\/messages$/) }
        it { should contain_file('rsyslog_config').with_content(/^#rsyslog v3 config file$/) }

<<<<<<< HEAD
        it { should contain_file('rsyslog_config').without_content(/^\$ModLoad imudp.so$/) }
        it { should contain_file('rsyslog_config').without_content(/^\$ModLoad imtcp.so$/) }
        it { should contain_file('rsyslog_config').without_content(/^\$template RemoteHost, "\/srv\/logs\/%HOSTNAME%\/%\$YEAR%-%\$MONTH%-%\$DAY%.log"$/) }
        it { should contain_file('rsyslog_config').without_content(/^\$WorkDirectory \/var\/spool\/rsyslog # where to place spool files$/) }
        it { should contain_file('rsyslog_config').without_content(/^\$ActionQueueFileName queue # unique name prefix for spool files$/) }
        it { should contain_file('rsyslog_config').without_content(/^\$ActionQueueMaxDiskSpace 1g # 1gb space limit \(use as much as possible\)$/) }
        it { should contain_file('rsyslog_config').without_content(/^\$ActionQueueSaveOnShutdown on # save messages to disk on shutdown$/) }
        it { should contain_file('rsyslog_config').without_content(/^\$ActionQueueType LinkedList   # run asynchronously$/) }
        it { should contain_file('rsyslog_config').without_content(/^\$ActionResumeRetryCount -1    # infinite retries if host is down$/) }
        it { should contain_file('rsyslog_config').without_content(/^\*.\* @@log.defaultdomain:514/) }
        it { should contain_file('rsyslog_config').without_content(/^\$RuleSet remote\n\*.\*?RemoteHost$/) }
        it { should contain_file('rsyslog_config').without_content(/^\$InputTCPServerBindRuleset remote$/) }
        it { should contain_file('rsyslog_config').without_content(/^\$InputTCPServerRun 514$/) }
        it { should contain_file('rsyslog_config').without_content(/^\$InputUDPServerBindRuleset remote$/) }
        it { should contain_file('rsyslog_config').without_content(/^\$UDPServerRun 514$/) }
=======
        it { should_not contain_file('rsyslog_config').with_content(/^\$ModLoad imudp.so$/) }
        it { should_not contain_file('rsyslog_config').with_content(/^\$ModLoad imtcp.so$/) }
        it { should_not contain_file('rsyslog_config').with_content(/^\$ModLoad imfile$/) }
        it { should_not contain_file('rsyslog_config').with_content(/^\$template RemoteHost, "\/srv\/logs\/%HOSTNAME%\/%\$YEAR%-%\$MONTH%-%\$DAY%.log"$/) }
        it { should_not contain_file('rsyslog_config').with_content(/^\$WorkDirectory \/var\/spool\/rsyslog # where to place spool files$/) }
        it { should_not contain_file('rsyslog_config').with_content(/^\$ActionQueueFileName queue # unique name prefix for spool files$/) }
        it { should_not contain_file('rsyslog_config').with_content(/^\$ActionQueueMaxDiskSpace 1g # 1gb space limit \(use as much as possible\)$/) }
        it { should_not contain_file('rsyslog_config').with_content(/^\$ActionQueueSaveOnShutdown on # save messages to disk on shutdown$/) }
        it { should_not contain_file('rsyslog_config').with_content(/^\$ActionQueueType LinkedList   # run asynchronously$/) }
        it { should_not contain_file('rsyslog_config').with_content(/^\$ActionResumeRetryCount -1    # infinite retries if host is down$/) }
        it { should_not contain_file('rsyslog_config').with_content(/^\*.\* @@log.defaultdomain:514/) }
        it { should_not contain_file('rsyslog_config').with_content(/^\$RuleSet remote\n\*.\*?RemoteHost$/) }
        it { should_not contain_file('rsyslog_config').with_content(/^\$InputTCPServerBindRuleset remote$/) }
        it { should_not contain_file('rsyslog_config').with_content(/^\$InputTCPServerRun 514$/) }
        it { should_not contain_file('rsyslog_config').with_content(/^\$InputUDPServerBindRuleset remote$/) }
        it { should_not contain_file('rsyslog_config').with_content(/^\$UDPServerRun 514$/) }
>>>>>>> Update init_spec.rb
      end

      context 'local_file_monitoring_enabled='true'' do
        let :params do
          { :local_file_monitoring_enabled => 'true' }
        end
        it { should contain_file('rsyslog_config').with_content(/^\$ModLoad imfile$/) }
      end

      context 'with is_log_server=true' do
        let :params do
          { :is_log_server => 'true' }
        end
        it { should contain_file('rsyslog_config').with_content(/^kern.\*\s+\/var\/log\/messages$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$ModLoad imtcp.so$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$template RemoteHost, "\/srv\/logs\/%HOSTNAME%\/%\$YEAR%-%\$MONTH%-%\$DAY%.log"$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$RuleSet remote$/) }
        it { should contain_file('rsyslog_config').with_content(/^\*.\* \?RemoteHost$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$InputTCPServerBindRuleset remote$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$InputTCPServerRun 514$/) }
        it { should contain_file('rsyslog_config').without_content(/^\$ModLoad imudp.so$/) }
        it { should contain_file('rsyslog_config').without_content(/^\*.\* @@log.defaultdomain:514/) }
        it { should contain_file('rsyslog_config').without_content(/^\$InputUDPServerBindRuleset remote$/) }
        it { should contain_file('rsyslog_config').without_content(/^\$UDPServerRun 514$/) }
        it { should contain_file('rsyslog_config').without_content(/^\$WorkDirectory \/var\/spool\/rsyslog # where to place spool files$/) }
        it { should contain_file('rsyslog_config').without_content(/^\$ActionQueueFileName queue # unique name prefix for spool files$/) }
        it { should contain_file('rsyslog_config').without_content(/^\$ActionQueueMaxDiskSpace 1g # 1gb space limit \(use as much as possible\)$/) }
        it { should contain_file('rsyslog_config').without_content(/^\$ActionQueueSaveOnShutdown on # save messages to disk on shutdown$/) }
        it { should contain_file('rsyslog_config').without_content(/^\$ActionQueueType LinkedList   # run asynchronously$/) }
        it { should contain_file('rsyslog_config').without_content(/^\$ActionResumeRetryCount -1    # infinite retries if host is down$/) }
      end

      context 'with is_log_server enabled and transport_protocol=tcp specified' do
        let :params do
          {
            :is_log_server      => 'true',
            :transport_protocol => 'tcp',
          }
        end
        it { should contain_file('rsyslog_config').with_content(/^kern.\*\s+\/var\/log\/messages$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$template RemoteHost, "\/srv\/logs\/%HOSTNAME%\/%\$YEAR%-%\$MONTH%-%\$DAY%.log"$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$RuleSet remote$/) }
        it { should contain_file('rsyslog_config').with_content(/^\*.\* \?RemoteHost$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$InputTCPServerBindRuleset remote$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$InputTCPServerRun 514$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$ModLoad imtcp.so$/) }
        it { should contain_file('rsyslog_config').without_content(/^\$ModLoad imudp.so$/) }
      end

      context 'with is_log_server enabled and transport_protocol=udp specified' do
        let :params do
          {
            :is_log_server      => 'true',
            :transport_protocol => 'udp',
          }
        end
        it { should contain_file('rsyslog_config').with_content(/^kern.\*\s+\/var\/log\/messages$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$template RemoteHost, "\/srv\/logs\/%HOSTNAME%\/%\$YEAR%-%\$MONTH%-%\$DAY%.log"$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$RuleSet remote$/) }
        it { should contain_file('rsyslog_config').with_content(/^\*.\* \?RemoteHost$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$InputUDPServerBindRuleset remote$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$UDPServerRun 514$/) }
        it { should contain_file('rsyslog_config').without_content(/^\$ModLoad imtcp.so$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$ModLoad imudp.so$/) }
      end

      context 'with is_log_server enabled and enable_tcp_server enabled and enable_udp_server enabled' do
        let :params do
          {
            :is_log_server     => 'true',
            :enable_tcp_server => 'true',
            :enable_udp_server => 'true',
          }
        end
        it { should contain_file('rsyslog_config').with_content(/^kern.\*\s+\/var\/log\/messages$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$template RemoteHost, "\/srv\/logs\/%HOSTNAME%\/%\$YEAR%-%\$MONTH%-%\$DAY%.log"$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$RuleSet remote$/) }
        it { should contain_file('rsyslog_config').with_content(/^\*.\* \?RemoteHost$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$InputTCPServerBindRuleset remote$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$InputTCPServerRun 514$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$InputUDPServerBindRuleset remote$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$UDPServerRun 514$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$ModLoad imtcp.so$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$ModLoad imudp.so$/) }
      end

      context 'with remote_logging enabled' do
        let :params do
          { :remote_logging => 'true' }
        end
        it { should contain_file('rsyslog_config').with_content(/^kern.\*\s+\/var\/log\/messages$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$WorkDirectory \/var\/spool\/rsyslog # where to place spool files$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$ActionQueueFileName queue # unique name prefix for spool files$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$ActionQueueMaxDiskSpace 1g # 1gb space limit \(use as much as possible\)$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$ActionQueueSaveOnShutdown on # save messages to disk on shutdown$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$ActionQueueType LinkedList   # run asynchronously$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$ActionResumeRetryCount -1    # infinite retries if host is down$/) }
        it { should contain_file('rsyslog_config').with_content(/^\*.\* @@log.defaultdomain:514/) }
      end

      context 'with remote_logging enabled and source_facilities specified' do
        let :params do
          {
            :remote_logging    => 'true',
            :source_facilities => '*.*;user.none',
          }
        end
        it { should contain_file('rsyslog_config').with_content(/^kern.\*\s+\/var\/log\/messages$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$WorkDirectory \/var\/spool\/rsyslog # where to place spool files$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$ActionQueueFileName queue # unique name prefix for spool files$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$ActionQueueMaxDiskSpace 1g # 1gb space limit \(use as much as possible\)$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$ActionQueueSaveOnShutdown on # save messages to disk on shutdown$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$ActionQueueType LinkedList   # run asynchronously$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$ActionResumeRetryCount -1    # infinite retries if host is down$/) }
        it { should contain_file('rsyslog_config').with_content(/^\*.\*;user.none @@log.defaultdomain:514/) }
      end

      context 'with remote_logging enabled and transport_protocol=tcp specified' do
        let :params do
          {
            :remote_logging     => 'true',
            :transport_protocol => 'tcp',
          }
        end
        it { should contain_file('rsyslog_config').with_content(/^kern.\*\s+\/var\/log\/messages$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$WorkDirectory \/var\/spool\/rsyslog # where to place spool files$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$ActionQueueFileName queue # unique name prefix for spool files$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$ActionQueueMaxDiskSpace 1g # 1gb space limit \(use as much as possible\)$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$ActionQueueSaveOnShutdown on # save messages to disk on shutdown$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$ActionQueueType LinkedList   # run asynchronously$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$ActionResumeRetryCount -1    # infinite retries if host is down$/) }
        it { should contain_file('rsyslog_config').with_content(/^\*.\* @@log.defaultdomain:514$/) }
        it { should contain_file('rsyslog_config').without_content(/^\$ModLoad imtcp.so$/) }
        it { should contain_file('rsyslog_config').without_content(/^\$ModLoad imudp.so$/) }
      end

      context 'with remote_logging enabled and transport_protocol=udp specified' do
        let :params do
          {
            :remote_logging     => 'true',
            :transport_protocol => 'udp',
          }
        end
        it { should contain_file('rsyslog_config').with_content(/^kern.\*\s+\/var\/log\/messages$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$WorkDirectory \/var\/spool\/rsyslog # where to place spool files$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$ActionQueueFileName queue # unique name prefix for spool files$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$ActionQueueMaxDiskSpace 1g # 1gb space limit \(use as much as possible\)$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$ActionQueueSaveOnShutdown on # save messages to disk on shutdown$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$ActionQueueType LinkedList   # run asynchronously$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$ActionResumeRetryCount -1    # infinite retries if host is down$/) }
        it { should contain_file('rsyslog_config').with_content(/^\*.\* @log.defaultdomain:514$/) }
        it { should contain_file('rsyslog_config').without_content(/^\$ModLoad imudp.so$/) }
        it { should contain_file('rsyslog_config').without_content(/^\$ModLoad imtcp.so$/) }
      end

      context 'with source_facilities set to an empty string' do
        let :params do
          { :source_facilities => '' }
        end
        it do
          expect {
            should contain_class('rsyslog')
          }.to raise_error(Puppet::Error,/rsyslog::source_facilities cannot be empty!/)
        end
      end

      context 'with logrotate_syslog_files set to an invalid type' do
        let :params do
          { :logrotate_syslog_files => 'string' }
        end
        it do
          expect {
            should contain_class('rsyslog')
          }.to raise_error(Puppet::Error,/\"string\" is not an Array.  It looks to be a String/)
        end
      end

      context 'with log_dir and remote_template set' do
        let :params do
          {
            :is_log_server   => 'true',
            :log_dir         => '/foo/bar',
            :remote_template => '%HOSTNAME%.log',
          }
        end
        it {
          should contain_file('rsyslog_config') \
          .with_content(/^\$template RemoteHost, "\/foo\/bar\/%HOSTNAME%.log"$/)
        }
      end

      context 'with rsyslog_conf_version=2 specified' do
        let :params do
          {
            :rsyslog_conf_version => '2',
          }
        end
        it { should contain_file('rsyslog_config').with_content(/^#rsyslog v2 config file$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$template TraditionalFormat,\"%timegenerated% %HOSTNAME% %syslogtag%%msg:::drop-last-lf%0\"$/) }
        it { should contain_file('rsyslog_config').without_content(/^\$ModLoad imuxsock.so	# provides support for local system logging (e.g. via logger command)/) }
        it { should contain_file('rsyslog_config').without_content(/^\$ModLoad imklog.so	# provides kernel logging support (previously done by rklogd)/) }
        it { should contain_file('rsyslog_config').without_content(/^\$ModLoad imudp.so$/) }
        it { should contain_file('rsyslog_config').without_content(/^\$ModLoad imtcp.so$/) }
        it { should contain_file('rsyslog_config').without_content(/^\$template RemoteHost, "\/srv\/logs\/%HOSTNAME%\/%\$YEAR%-%\$MONTH%-%\$DAY%.log"$/) }
        it { should contain_file('rsyslog_config').without_content(/^\$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat$/) }
        it { should contain_file('rsyslog_config').without_content(/^\$RuleSet local$/) }
        it { should contain_file('rsyslog_config').without_content(/^\$DefaultRuleset local$/) }
        it { should contain_file('rsyslog_config').without_content(/^\$IncludeConfig \/etc\/rsyslog.d\/*.conf$/) }
        it { should contain_file('rsyslog_config').without_content(/^\$WorkDirectory \/var\/spool\/rsyslog # where to place spool files$/) }
        it { should contain_file('rsyslog_config').without_content(/^\$ActionQueueFileName queue # unique name prefix for spool files$/) }
        it { should contain_file('rsyslog_config').without_content(/^\$ActionQueueMaxDiskSpace 1g # 1gb space limit \(use as much as possible\)$/) }
        it { should contain_file('rsyslog_config').without_content(/^\$ActionQueueSaveOnShutdown on # save messages to disk on shutdown$/) }
        it { should contain_file('rsyslog_config').without_content(/^\$ActionQueueType LinkedList   # run asynchronously$/) }
        it { should contain_file('rsyslog_config').without_content(/^\$ActionResumeRetryCount -1    # infinite retries if host is down$/) }
        it { should contain_file('rsyslog_config').without_content(/^\*.\* @@log.defaultdomain:514/) }
        it { should contain_file('rsyslog_config').without_content(/^\$RuleSet remote\n\*.\*?RemoteHost$/) }
        it { should contain_file('rsyslog_config').without_content(/^\$InputTCPServerBindRuleset remote$/) }
        it { should contain_file('rsyslog_config').without_content(/^\$InputTCPServerRun 514$/) }
        it { should contain_file('rsyslog_config').without_content(/^\$InputUDPServerBindRuleset remote$/) }
        it { should contain_file('rsyslog_config').without_content(/^\$UDPServerRun 514$/) }
      end

      context 'with rsyslog_conf_version specified as invalid value' do
        let :params do
          {
            :rsyslog_conf_version => 'invalid',
          }
        end
        it do
          expect {
            should contain_class('rsyslog')
          }.to raise_error(Puppet::Error,/^rsyslog_conf_version only knows <2>, <3> and <USE_DEFAULTS> as valid values and you have specified <invalid>/)
        end
      end
    end
  end

  describe 'rsyslog_package' do
    let :facts do
      {
        :kernel            => 'Linux',
        :osfamily          => 'RedHat',
        :lsbmajdistrelease => '6',
      }
    end

    context 'with default params' do
      it {
        should contain_package('rsyslog').with({
          'ensure' => 'present'
        })
      }
    end

    context 'specified as an array' do
      let(:params) { { :package => ['rsyslog', 'andfriends'] } }

      it {
        should contain_package('rsyslog').with({
          'ensure' => 'present'
        })
      }

      it {
        should contain_package('andfriends').with({
          'ensure' => 'present'
        })
      }
    end

    context 'with package_provider=pkgutil' do
      let (:params) { { :package_provider => 'pkgutil' } }
      it {
        should contain_package('rsyslog').with({
          'ensure'   => 'present',
          'provider' => 'pkgutil',
        })
      }
    end

    context 'with package_ensure=absent' do
      let (:params) { { :package_ensure => 'absent' } }
      it {
        should contain_package('rsyslog').with({
          'ensure' => 'absent',
        })
      }
    end
  end

  describe 'rsyslog_daemon' do
    let :facts do
      {
        :kernel            => 'Linux',
        :osfamily          => 'RedHat',
        :lsbmajdistrelease => '6',
      }
    end

    context 'with default params' do
      it {
        should contain_service('rsyslog_daemon').with({
          'name'   => 'rsyslog',
          'ensure' => 'running',
          'enable' => 'true',
        })
      }
    end

    ['stopped','running'].each do |value|
      context "with daemon_ensure=#{value}" do
        let (:params) { { :daemon_ensure => value } }

        it {
          should contain_service('rsyslog_daemon').with({
            'name'   => 'rsyslog',
            'ensure' => value,
          })
        }
      end
    end

    context 'with daemon_ensure=invalid' do
      let (:params) { { :daemon_ensure => 'invalid' } }
      it 'should fail' do
        expect {
          should contain_class('rsyslog')
        }.to raise_error(Puppet::Error,/daemon_ensure may be either \'running\' or \'stopped\' and is set to <invalid>./)
      end
    end

    ['true',true,'false',false,'manual'].each do |value|
      context "with daemon_enable=#{value}" do
        let (:params) { { :daemon_enable => value } }

        it {
          should contain_service('rsyslog_daemon').with({
            'name'   => 'rsyslog',
            'enable' => value,
          })
        }
      end
    end

    context 'with daemon_enable=invalid' do
      let (:params) { { :daemon_enable => 'invalid' } }
      it 'should fail' do
        expect {
          should contain_class('rsyslog')
        }.to raise_error(Puppet::Error,/daemon_enable may be either \'true\', \'false\' or \'manual\' and is set to <invalid>./)
      end
    end

  end

  logrotate_hash = {
    'redhat5'   => { :kernel => 'Linux',   :osfamily => 'RedHat',  :release => '5',    :logrotate_present => true },
    'redhat6'   => { :kernel => 'Linux',   :osfamily => 'RedHat',  :release => '6',    :logrotate_present => true },
    'redhat7'   => { :kernel => 'Linux',   :osfamily => 'RedHat',  :release => '7',    :logrotate_present => true },
    'debian7'   => { :kernel => 'Linux',   :osfamily => 'Debian',  :release => '7',    :logrotate_present => true },
    'suse10'    => { :kernel => 'Linux',   :osfamily => 'Suse',    :release => '10',   :logrotate_present => true },
    'suse11'    => { :kernel => 'Linux',   :osfamily => 'Suse',    :release => '11',   :logrotate_present => true },
    'solaris10' => { :kernel => 'Solaris', :osfamily => 'Solaris', :release => '5.10', :logrotate_present => false },
    'solaris11' => { :kernel => 'Solaris', :osfamily => 'Solaris', :release => '5.11', :logrotate_present => false },
  }

  describe 'rsyslog_logrotate_d_config' do
    logrotate_hash.sort.each do |k,v|
      if v[:logrotate_present]
        logrotate_fixture = File.read(fixtures("#{k}.logrotate"))
      end

      context "with default params on #{v[:osfamily]} #{v[:release]}" do
        let :params do
          { :logrotate_present => v[:logrotate_present] }
        end

        if v[:kernel] == 'Linux'
          let :facts do
            {
              :kernel            => v[:kernel],
              :osfamily          => v[:osfamily],
              :lsbmajdistrelease => v[:release],
            }
          end
        elsif v[:kernel] == 'Solaris'
          let :facts do
            {
              :kernel        => v[:kernel],
              :osfamily      => v[:osfamily],
              :kernelrelease => v[:release],
            }
          end
        end

        if v[:logrotate_present]
          it {
            should contain_file('rsyslog_logrotate_d_config').with({
              'path'    => '/etc/logrotate.d/syslog',
              'owner'   => 'root',
              'group'   => 'root',
              'mode'    => '0644',
              'require' => 'Package[rsyslog]',
            })
          }

          it { should contain_file('rsyslog_logrotate_d_config').with_content(logrotate_fixture) }
        else
          it { should_not contain_file('rsyslog_logrotate_d_config') }

          it { should_not contain_file('rsyslog_logrotate_d_config').with_content(logrotate_fixture) }
        end
      end
    end
  end

  describe 'with logrotate_syslog_files with duplicate files' do
    context 'specified' do
      let(:params) { { :logrotate_syslog_files => [ '/var/log/messages', '/var/log/secure', '/var/log/maillog', '/var/log/spooler', '/var/log/boot.log', '/var/log/cron', '/var/log/cron', ]  } }
      let :facts do
        {
          :kernel            => 'Linux',
          :osfamily          => 'RedHat',
          :lsbmajdistrelease => '5',
        }
      end

      it {
        should contain_file('rsyslog_logrotate_d_config').with({
          'path'    => '/etc/logrotate.d/syslog',
          'owner'   => 'root',
          'group'   => 'root',
          'mode'    => '0644',
          'require' => 'Package[rsyslog]',
        })
      }

      it { should contain_file('rsyslog_logrotate_d_config').with_content(
%{# This file is being maintained by Puppet.
# DO NOT EDIT

/var/log/messages
/var/log/secure
/var/log/maillog
/var/log/spooler
/var/log/boot.log
/var/log/cron
{
    sharedscripts
    postrotate
        /bin/kill -HUP `cat /var/run/rsyslogd.pid 2> /dev/null` 2> /dev/null || true
    endscript
}
})
        }
    end
  end

  describe 'with pid_file parameter' do
    context 'specified' do
      let(:params) { { :pid_file => '/path/to/syslog.pid' } }
      let :facts do
        {
          :kernel            => 'Linux',
          :osfamily          => 'RedHat',
          :lsbmajdistrelease => '6',
        }
      end

      it {
        should contain_file('rsyslog_logrotate_d_config').with({
          'path'    => '/etc/logrotate.d/syslog',
          'owner'   => 'root',
          'group'   => 'root',
          'mode'    => '0644',
          'require' => 'Package[rsyslog]',
        })
      }

      it { should contain_file('rsyslog_logrotate_d_config').with_content(
%{# This file is being maintained by Puppet.
# DO NOT EDIT

/var/log/messages
/var/log/secure
/var/log/maillog
/var/log/spooler
/var/log/boot.log
/var/log/cron
{
    sharedscripts
    postrotate
        /bin/kill -HUP `cat /path/to/syslog.pid 2> /dev/null` 2> /dev/null || true
    endscript
}
})
        }
    end

    context 'with pid_file specified as an invalid value' do
      let(:params) { { :pid_file => 'invalid/path/to/syslog.pid' } }
      let :facts do
        {
          :kernel            => 'Linux',
          :osfamily          => 'Debian',
          :lsbmajdistrelease => '7',
        }
      end

      it do
        expect {
          should contain_class('rsyslog')
        }.to raise_error(Puppet::Error)
      end
    end
  end

  describe 'rsyslog_sysconfig' do
    context 'on Debian' do
      let :facts do
        {
          :kernel   => 'Linux',
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
            'require' => 'Package[rsyslog]',
            'notify'  => 'Service[rsyslog_daemon]',
          })
        }

        it { should contain_file('rsyslog_sysconfig').with_content(/^RSYSLOGD_OPTIONS="-c5"$/) }
      end
    end

    context 'on EL 7' do
      let :facts do
        {
          :kernel            => 'Linux',
          :osfamily          => 'RedHat',
          :lsbmajdistrelease => '7',
        }
      end

      context 'with default params' do
        it {
          should contain_file('rsyslog_sysconfig').with({
            'path'    => '/etc/sysconfig/rsyslog',
            'owner'   => 'root',
            'group'   => 'root',
            'mode'    => '0644',
            'require' => 'Package[rsyslog]',
            'notify'  => 'Service[rsyslog_daemon]',
          })
        }
        it {
          should contain_file('rsyslog_sysconfig').with_content(/^SYSLOGD_OPTIONS="-c 4"$/)
        }
      end
    end

    context 'on EL 6' do
      let :facts do
        {
          :kernel            => 'Linux',
          :osfamily          => 'RedHat',
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
            'require' => 'Package[rsyslog]',
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
          :kernel            => 'Linux',
          :osfamily          => 'RedHat',
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
            'require' => 'Package[rsyslog]',
            'notify'  => 'Service[rsyslog_daemon]',
          })
        }
        it { should contain_file('rsyslog_sysconfig').with_content(/^SYSLOGD_OPTIONS="-m 0"$/) }
        it { should contain_file('rsyslog_sysconfig').with_content(/^KLOGD_OPTIONS="-x"$/) }
      end
    end

    context 'on Suse 10' do
      let :facts do
        {
          :kernel            => 'Linux',
          :osfamily          => 'Suse',
          :lsbmajdistrelease => '10',
        }
      end

      context 'with default params' do
        it {
          should contain_file('rsyslog_sysconfig').with({
            'path' => '/etc/sysconfig/syslog',
            'owner' => 'root',
            'group' => 'root',
            'mode' => '0644',
            'require' => 'Package[rsyslog]',
            'notify' => 'Service[rsyslog_daemon]',
          })
        }
        it { should contain_file('rsyslog_sysconfig').with_content(/^KERNEL_LOGLEVEL=1$/) }
        it { should contain_file('rsyslog_sysconfig').with_content(/^SYSLOGD_PARAMS=""$/) }
        it { should contain_file('rsyslog_sysconfig').with_content(/^KLOGD_PARAMS="-x"$/) }
        it { should contain_file('rsyslog_sysconfig').with_content(/^SYSLOG_DAEMON="rsyslogd"$/) }
        it { should contain_file('rsyslog_sysconfig').with_content(/^SYSLOG_NG_CREATE_CONFIG="yes"$/) }
        it { should contain_file('rsyslog_sysconfig').with_content(/^SYSLOG_NG_PARAMS=""$/) }
      end
    end

    context 'on Suse 11' do
      let :facts do
        {
          :kernel            => 'Linux',
          :osfamily          => 'Suse',
          :lsbmajdistrelease => '11',
        }
      end

      context 'with default params' do
        it {
          should contain_file('rsyslog_sysconfig').with({
            'path'    => '/etc/sysconfig/syslog',
            'owner'   => 'root',
            'group'   => 'root',
            'mode'    => '0644',
            'require' => 'Package[rsyslog]',
            'notify'  => 'Service[rsyslog_daemon]',
          })
        }
        it { should contain_file('rsyslog_sysconfig').with_content(/^KERNEL_LOGLEVEL=1$/) }
        it { should contain_file('rsyslog_sysconfig').with_content(/^SYSLOGD_PARAMS=""$/) }
        it { should contain_file('rsyslog_sysconfig').with_content(/^KLOGD_PARAMS="-x"$/) }
        it { should contain_file('rsyslog_sysconfig').with_content(/^SYSLOG_DAEMON="rsyslogd"$/) }
        it { should contain_file('rsyslog_sysconfig').with_content(/^SYSLOG_NG_PARAMS=""$/) }
        it { should contain_file('rsyslog_sysconfig').with_content(/^RSYSLOGD_NATIVE_VERSION="5"$/) }
        it { should contain_file('rsyslog_sysconfig').with_content(/^RSYSLOGD_COMPAT_VERSION=""$/) }
        it { should contain_file('rsyslog_sysconfig').with_content(/^RSYSLOGD_PARAMS=""$/) }
      end
    end
  end

  describe 'rsyslog_d_dir' do
    context "with default params" do
      let :facts do
        {
          :kernel            => 'Linux',
          :osfamily          => 'RedHat',
          :lsbmajdistrelease => '6',
        }
      end
      it {
        should contain_file('rsyslog_d_dir').with({
          'ensure'  => 'directory',
          'path'    => '/etc/rsyslog.d',
          'owner'   => 'root',
          'group'   => 'root',
          'mode'    => '0755',
          'purge'   => true,
          'recurse' => true,
          'require' => 'Common::Mkdir_p[/etc/rsyslog.d]',
        })
      }
    end

    context "with rsyslog_d_dir parameters specified" do
      let :facts do
        {
          :kernel            => 'Linux',
          :osfamily          => 'RedHat',
          :lsbmajdistrelease => '6',
        }
      end
      let :params do
        { :rsyslog_d_dir       => '/custom/rsyslog.d',
          :rsyslog_d_dir_owner => 'other',
          :rsyslog_d_dir_group => 'othergroup',
          :rsyslog_d_dir_mode  => '0775',
          :rsyslog_d_dir_purge => false,
        }
      end
      it {
        should contain_file('rsyslog_d_dir').with({
          'ensure'  => 'directory',
          'path'    => '/custom/rsyslog.d',
          'owner'   => 'other',
          'group'   => 'othergroup',
          'mode'    => '0775',
          'recurse' => true,
          'purge'   => false,
          'require' => 'Common::Mkdir_p[/custom/rsyslog.d]',
        })
      }
    end

    context "with rsyslog_d_dir specified as invalid path" do
      let :facts do
        {
          :kernel            => 'Linux',
          :osfamily          => 'RedHat',
          :lsbmajdistrelease => '6',
        }
      end
      let (:params) { { :rsyslog_d_dir => 'custom/rsyslog.d' } }
      it 'should fail' do
        expect {
          should contain_class('rsyslog')
        }.to raise_error(Puppet::Error)
      end
    end

    ['true',true].each do |value|
      context "with rsyslog_d_dir_purge specified as #{value}" do
        let :facts do
          {
            :kernel            => 'Linux',
            :osfamily          => 'RedHat',
            :lsbmajdistrelease => '6',
          }
        end
        let (:params) { { :rsyslog_d_dir_purge => value } }

        it {
          should contain_file('rsyslog_d_dir').with({
            'recurse' => true,
            'purge'   => true,
          })
        }
      end
    end

    ['false',false].each do |value|
      context "with rsyslog_d_dir_purge specified as #{value}" do
        let :facts do
          {
            :kernel            => 'Linux',
            :osfamily          => 'RedHat',
            :lsbmajdistrelease => '6',
          }
        end
        let (:params) { { :rsyslog_d_dir_purge => value } }

        it {
          should contain_file('rsyslog_d_dir').with({
            'recurse' => true,
            'purge'   => false,
          })
        }
      end
    end

    context 'with rsyslog_d_dir_purge specified as an invalid value' do
      let :facts do
        {
          :kernel            => 'Linux',
          :osfamily          => 'RedHat',
          :lsbmajdistrelease => '6',
        }
      end
      let (:params) { { :rsyslog_d_dir_purge => 'invalid' } }

      it 'should fail' do
        expect {
          should contain_class('rsyslog')
        }.to raise_error(Puppet::Error)
      end
    end
  end

  describe 'case is_log_server, default params' do
    let :facts do
      {
        :kernel            => 'Linux',
        :osfamily          => 'RedHat',
        :lsbmajdistrelease => '6',
      }
    end

    context 'case true' do
      let(:params) { { :is_log_server => 'true' } }
      it { should contain_class('common') }

      it {
        should contain_file('log_dir').with({
          'ensure'  => 'directory',
          'path'    => '/srv/logs',
          'owner'   => 'root',
          'group'   => 'root',
          'mode'    => '0750',
          'require' => 'Common::Mkdir_p[/srv/logs]'
        })
      }
    end

    context 'case true, log_dir set' do
      let :params do
      {
        :is_log_server => 'true',
        :log_dir       => '/foo/bar',
        :log_dir_owner => 'nobody',
        :log_dir_group => 'staff',
        :log_dir_mode  => '0755',
      }
      end
      it {
        should contain_file('log_dir').with({
          'ensure'  => 'directory',
          'path'    => '/foo/bar',
          'owner'   => 'nobody',
          'group'   => 'staff',
          'mode'    => '0755',
          'require' => 'Common::Mkdir_p[/foo/bar]',
        })
      }
    end

    context 'case default' do
      let(:params) { { :is_log_server => 'undefined' } }
      it do
        expect {
          should contain_class('rsyslog')
        }.to raise_error(Puppet::Error,/rsyslog::is_log_server is undefined and must be \'true\' or \'false\'./)
      end
    end
  end

  describe 'case transport_protocol, default params' do
    let :facts do
      {
        :kernel            => 'Linux',
        :osfamily          => 'RedHat',
        :lsbmajdistrelease => '6',
      }
    end

    context 'with transport_protocol set to invalid value' do
      let(:params) { { :transport_protocol => 'invalid' } }
      it do
        expect {
          should contain_class('rsyslog')
        }.to raise_error(Puppet::Error,/rsyslog::transport_protocol is invalid and must be \'tcp\' or \'udp\'./)
      end
    end

  end

  describe 'case remote_logging, default params' do
    let :facts do
      {
        :kernel            => 'Linux',
        :osfamily          => 'RedHat',
        :lsbmajdistrelease => '6',
      }
    end
    context 'case true' do
      let(:params) { { :remote_logging => 'true' } }
      it {
        should contain_file('ryslog_spool_directory').with({
          'ensure'  => 'directory',
          'path'    => '/var/spool/rsyslog',
          'owner'   => 'root',
          'group'   => 'root',
          'mode'    => '0700',
          'require' => 'Common::Mkdir_p[/var/spool/rsyslog]'
        })
      }
      it {
        should contain_exec('mkdir_p-/var/spool/rsyslog').with({
          'command' => 'mkdir -p /var/spool/rsyslog',
          'unless'  => 'test -d /var/spool/rsyslog',
        })
      }
    end
    context 'case false' do
      let(:params) { { :remote_logging => 'false' } }
      it {
        should_not contain_file('ryslog_spool_directory')
      }
      it {
        should_not contain_exec('mkdir_p-/var/spool/rsyslog')
      }
    end
  end

  describe 'module platform support' do
    support_matrix = {
      'redhat4'   => { :kernel => 'Linux',   :osfamily => 'RedHat',  :release => '4',    :support => 'unsupported', },
      'redhat5'   => { :kernel => 'Linux',   :osfamily => 'RedHat',  :release => '5',    :support => 'supported', },
      'redhat6'   => { :kernel => 'Linux',   :osfamily => 'RedHat',  :release => '6',    :support => 'supported', },
      'redhat7'   => { :kernel => 'Linux',   :osfamily => 'RedHat',  :release => '7',    :support => 'supported', },
      'debian7'   => { :kernel => 'Linux',   :osfamily => 'Debian',  :release => '7',    :support => 'supported', },
      'suse9'     => { :kernel => 'Linux',   :osfamily => 'Suse',    :release => '9',    :support => 'unsupported', },
      'suse10'    => { :kernel => 'Linux',   :osfamily => 'Suse',    :release => '10',   :support => 'supported', },
      'suse11'    => { :kernel => 'Linux',   :osfamily => 'Suse',    :release => '11',   :support => 'supported', },
      'solaris9'  => { :kernel => 'Solaris', :osfamily => 'Solaris', :release => '5.9',  :support => 'unsupported', },
      'solaris10' => { :kernel => 'Solaris', :osfamily => 'Solaris', :release => '5.10', :support => 'supported', },
      'solaris11' => { :kernel => 'Solaris', :osfamily => 'Solaris', :release => '5.11', :support => 'supported', },
    }

    support_matrix.sort.each do |k,v|
      context "on osfamily #{v[:osfamily]} with major release #{v[:release]} which is #{v[:support]}" do
        if v[:kernel] == 'Linux'
          let :facts do
            {
              :kernel            => v[:kernel],
              :osfamily          => v[:osfamily],
              :lsbmajdistrelease => v[:release],
            }
          end
        elsif v[:kernel] == 'Solaris'
          let :facts do
            {
              :kernel        => v[:kernel],
              :osfamily      => v[:osfamily],
              :kernelrelease => v[:release],
            }
          end
        end

        if v[:support] == 'supported'
          it { should contain_class('rsyslog') }
        else
          it do
            expect {
              should contain_class('rsyslog')
            }.to raise_error(Puppet::Error,/rsyslog supports #{v[:osfamily]} like systems with (kernel|major) release .* and .* and you have #{v[:release]}/)
          end
        end

      end
    end

  end

end
