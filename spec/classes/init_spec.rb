require 'spec_helper'
describe 'rsyslog' do
  let :default_facts do
    {
      :kernel                 => 'Linux',
      :osfamily               => 'RedHat',
      :operatingsystemrelease => '6.4',
      :domain                 => 'defaultdomain',
      :rsyslog_version        => '5.8.10',
    }
  end

  describe 'rsyslog_config' do
    let(:facts) { default_facts }

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
        it { should contain_file('rsyslog_config').with_content(/^#rsyslog v5 config file$/) }
        it { should contain_file('rsyslog_config').with_content(/^\*.emerg\s*:omusrmsg:\*$/) }

        it { should contain_file('rsyslog_config').without_content(/^\$ModLoad imudp$/) }
        it { should contain_file('rsyslog_config').without_content(/^\$ModLoad imtcp$/) }
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
      end

      [true,'true'].each do |value|
        context "with manage_devlog set to #{value}" do
          let :params do
            { :manage_devlog => value }
          end

          it {
            should contain_exec('manage devlog').with({
              'command' => 'systemctl restart systemd-journald.socket',
              'creates' => '/dev/log',
              'path'    => '/bin:/usr/bin:/sbin:/usr/sbin',
            })
          }
        end
      end

      [false,'false'].each do |value|
        context "with manage_devlog set to #{value}" do
          let :params do
            { :manage_devlog => value }
          end

          it { should_not contain_exec('manage devlog') }
        end
      end

      [true,'true'].each do |value|
        context "with is_log_server set to #{value}" do
          let :params do
            { :is_log_server => value }
          end
          it { should contain_file('rsyslog_config').with_content(/^kern.\*\s+\/var\/log\/messages$/) }
          it { should contain_file('rsyslog_config').with_content(/^\$ModLoad imtcp$/) }
          it { should contain_file('rsyslog_config').with_content(/^\$template RemoteHost, "\/srv\/logs\/%HOSTNAME%\/%\$YEAR%-%\$MONTH%-%\$DAY%.log"$/) }
          it { should contain_file('rsyslog_config').with_content(/^\$RuleSet remote$/) }
          it { should contain_file('rsyslog_config').with_content(/^\*.\* \?RemoteHost$/) }
          it { should contain_file('rsyslog_config').with_content(/^\$InputTCPServerBindRuleset remote$/) }
          it { should contain_file('rsyslog_config').with_content(/^\$InputTCPServerRun 514$/) }
          it { should contain_file('rsyslog_config').without_content(/^\$ModLoad imudp$/) }
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
      end

      [false,'false'].each do |value|
        context "with is_log_server set to #{value}" do
          let :params do
            { :is_log_server => value }
          end
          it { should contain_file('rsyslog_config').with_content(/^kern.\*\s+\/var\/log\/messages$/) }
          it { should contain_file('rsyslog_config').without_content(/^\$ModLoad imtcp$/) }
          it { should contain_file('rsyslog_config').without_content(/^\$template RemoteHost, "\/srv\/logs\/%HOSTNAME%\/%\$YEAR%-%\$MONTH%-%\$DAY%.log"$/) }
          it { should contain_file('rsyslog_config').without_content(/^\$RuleSet remote$/) }
          it { should contain_file('rsyslog_config').without_content(/^\*.\* \?RemoteHost$/) }
          it { should contain_file('rsyslog_config').without_content(/^\$InputTCPServerBindRuleset remote$/) }
          it { should contain_file('rsyslog_config').without_content(/^\$InputTCPServerRun 514$/) }
          it { should contain_file('rsyslog_config').without_content(/^\$ModLoad imudp$/) }
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
      end

      context 'with is_log_server enabled and transport_protocol=tcp specified' do
        let :params do
          {
            :is_log_server      => true,
            :transport_protocol => 'tcp',
          }
        end
        it { should contain_file('rsyslog_config').with_content(/^kern.\*\s+\/var\/log\/messages$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$template RemoteHost, "\/srv\/logs\/%HOSTNAME%\/%\$YEAR%-%\$MONTH%-%\$DAY%.log"$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$RuleSet remote$/) }
        it { should contain_file('rsyslog_config').with_content(/^\*.\* \?RemoteHost$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$InputTCPServerBindRuleset remote$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$InputTCPServerRun 514$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$ModLoad imtcp$/) }
        it { should contain_file('rsyslog_config').without_content(/^\$ModLoad imudp$/) }
      end

      context 'with is_log_server enabled and transport_protocol=udp specified' do
        let :params do
          {
            :is_log_server      => true,
            :transport_protocol => 'udp',
          }
        end
        it { should contain_file('rsyslog_config').with_content(/^kern.\*\s+\/var\/log\/messages$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$template RemoteHost, "\/srv\/logs\/%HOSTNAME%\/%\$YEAR%-%\$MONTH%-%\$DAY%.log"$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$RuleSet remote$/) }
        it { should contain_file('rsyslog_config').with_content(/^\*.\* \?RemoteHost$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$InputUDPServerBindRuleset remote$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$UDPServerRun 514$/) }
        it { should contain_file('rsyslog_config').without_content(/^\$ModLoad imtcp$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$ModLoad imudp$/) }
      end

      context 'with is_log_server enabled and enable_tcp_server enabled and enable_udp_server enabled' do
        let :params do
          {
            :is_log_server     => true,
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
        it { should contain_file('rsyslog_config').with_content(/^\$ModLoad imtcp$/) }
        it { should contain_file('rsyslog_config').with_content(/^\$ModLoad imudp$/) }
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
        it { should contain_file('rsyslog_config').without_content(/^\$ModLoad imtcp$/) }
        it { should contain_file('rsyslog_config').without_content(/^\$ModLoad imudp$/) }
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
        it { should contain_file('rsyslog_config').without_content(/^\$ModLoad imudp$/) }
        it { should contain_file('rsyslog_config').without_content(/^\$ModLoad imtcp$/) }
      end

      ['logserver', %w(logserver1 logserver2 logserver3:1514 logserver4:2514)].each do |values|
        context "with remote_logging enabled and log_server=#{values} (as #{values.class})" do
          let :params do
            {
              :remote_logging => true,
              :log_server     => values,
            }
          end

          if values.class == Array
            values.each do |value|
              if value.include? ":"
                it { should contain_file('rsyslog_config').with_content(/^\*\.\* @@#{value}$/) }
              else
                it { should contain_file('rsyslog_config').with_content(/^\*\.\* @@#{value}:514$/) }
              end
            end
          else
            it { should contain_file('rsyslog_config').with_content(/^\*\.\* @@logserver:514$/) }
          end

        end
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
          }.to raise_error(Puppet::Error,/\"string\" is not an Array\.  It looks to be a String/)
        end
      end

      context 'with log_dir and remote_template set' do
        let :params do
          {
            :is_log_server   => true,
            :log_dir         => '/foo/bar',
            :remote_template => '%HOSTNAME%.log',
          }
        end
        it {
          should contain_file('rsyslog_config') \
          .with_content(/^\$template RemoteHost, "\/foo\/bar\/%HOSTNAME%.log"$/)
        }
      end

      ['2','3','4','5','6','7','8',].each do |value|
        context "with rsyslog_conf_version=v#{value} specified" do
          let :params do
            {
              :rsyslog_conf_version => value,
            }
          end

          it { should contain_file('rsyslog_config').with_content(/^#rsyslog v#{value} config file$/) }

        end
      end

      ['1','9','invalid',].each do |value|
        context "with rsyslog_conf_version=v#{value} specified as invalid value" do
          let :params do
            {
              :rsyslog_conf_version => value,
            }
          end
          it do
            expect {
              should contain_class('rsyslog')
            }.to raise_error(Puppet::Error,/rsyslog_conf_version only knows <2>, <3>, <4>, <5>, <6>, <7>, <8> and <USE_DEFAULTS> as valid values and you have specified <#{value}>/)
          end
        end
      end

      context 'with kernel_target specified as an invalid value' do
        let(:params) { { :kernel_target => 'var/log/messages' } }

        it do
          expect {
            should contain_class('rsyslog')
          }.to raise_error(Puppet::Error,/is not an absolute path/)
        end
      end

      context 'with log_entries paramter specified as valid array' do
        let :params do
          {
            :log_entries => [ '*.* /var/log/catchall', 'kern.* /var/log/kern.log' ],
          }
        end

        it {
          should contain_file('rsyslog_config').with_content(/^\*.\* \/var\/log\/catchall\nkern.\* \/var\/log\/kern.log$/)
        }

      end

      context 'with log_entries specified as an invalid value' do
        let(:params) { { :log_entries => 'i_am_simply_not_an_array' } }

        it do
          expect {
            should contain_class('rsyslog')
          }.to raise_error(Puppet::Error,/is not an Array/)
        end
      end

      context 'with emerg_target set to an invalid type (non-string)' do
        let(:params) { { :emerg_target => ['invalid','type'] } }

        it do
          expect {
            should contain_class('rsyslog')
          }.to raise_error(Puppet::Error,/\["invalid", "type"\] is not a string\./)
        end

      end

      context 'with emerg_target containing specific destination' do
        let(:params) { { :emerg_target => '/special/emerg_target', } }

        it {
          should contain_file('rsyslog_config').with_content(/\*.emerg\s+\/special\/emerg_target$/)
        }

      end

      ['umask', 'file_create_mode'].each do |modeparam|
        ['1000','8800',].each do |value|
          context "with #{modeparam}=#{value} specified as invalid value" do
            let :params do
              {
                modeparam.to_sym => value,
              }
            end
            it do
              expect {
                should contain_class('rsyslog')
              }.to raise_error(Puppet::Error,/rsyslog::#{modeparam} is <#{value}> and must be a valid four digit mode in octal notation with a leading zero\./)
            end
          end
        end
      end
      ['1900','0800',].each do |value|
        context "with dir_create_mode=#{value} specified as invalid value" do
          let :params do
            {
              :dir_create_mode => value,
            }
          end
          it do
            expect {
              should contain_class('rsyslog')
            }.to raise_error(Puppet::Error,/rsyslog::dir_create_mode is <#{value}> and must be a valid four digit mode in octal notation\./)
          end
        end
      end
    end

    context 'with fact rsyslog_version empty' do
      let(:facts) { default_facts.merge({ :rsyslog_version => nil, }) }

      it {
        should_not contain_file('rsyslog_config')
      }
    end
#  end
####

    # rsyslog version specific differences in rsyslog_config
    ['2.4.2','3.4.56','4.56.7','5.0.0','6.7.8','7','8.9',].each do |value|
      describe "running on rsyslog v#{value}" do
        let(:facts) { default_facts.merge({ :rsyslog_version => value, }) }

        context "with default params" do
          if value.to_i >= 5
            it { should contain_file('rsyslog_config').with_content(/^#rsyslog v5 config file$/) }
          elsif value.to_i >= 4
            it { should contain_file('rsyslog_config').with_content(/^#rsyslog v4 config file$/) }
          elsif value.to_i >= 3
            it { should contain_file('rsyslog_config').with_content(/^#rsyslog v3 config file$/) }
          else value.to_i >= 2
            it { should contain_file('rsyslog_config').with_content(/^#rsyslog v2 config file$/) }
          end

          #### MODULES ####
          if value.to_i > 2
            it { should contain_file('rsyslog_config').with_content(/^\$ModLoad imuxsock/) }
            it { should contain_file('rsyslog_config').with_content(/^\$ModLoad imklog/) }
            it { should contain_file('rsyslog_config').with_content(/^#\$ModLoad immark/) }
          else
            it { should contain_file('rsyslog_config').without_content(/\$ModLoad imuxsock/) }
            it { should contain_file('rsyslog_config').without_content(/\$ModLoad imklog/) }
            it { should contain_file('rsyslog_config').without_content(/\#\$ModLoad immark/) }
          end

          #### GLOBAL DIRECTIVES ####
          if value.to_i == 2
            it { should contain_file('rsyslog_config').with_content(/^\$template TraditionalFormat,\"%timegenerated% %HOSTNAME% %syslogtag%%msg:::drop-last-lf%0\"$/) }
          else
            it { should contain_file('rsyslog_config').with_content(/^\$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat$/) }
          end
          it { should contain_file('rsyslog_config').without_content(/^\s*\$umask/) }
          it { should contain_file('rsyslog_config').with_content(/^\$FileCreateMode 0644$/) }
          it { should contain_file('rsyslog_config').with_content(/^\$DirCreateMode 0700$/) }

          #### RULES ####
          if value.to_i > 3
            it { should contain_file('rsyslog_config').with_content(/^\$RuleSet local$/) }
            it { should contain_file('rsyslog_config').with_content(/^\$DefaultRuleset local$/) }
            it { should contain_file('rsyslog_config').with_content(/^\$IncludeConfig \/etc\/rsyslog.d\/\*.conf$/) }
          elsif value.to_i > 2
            it { should contain_file('rsyslog_config').with_content(/^\$IncludeConfig \/etc\/rsyslog.d\/\*.conf$/) }
            it { should contain_file('rsyslog_config').without_content(/^\$RuleSet local$/) }
            it { should contain_file('rsyslog_config').without_content(/^\$DefaultRuleset local$/) }
          else
            it { should contain_file('rsyslog_config').without_content(/^\$RuleSet local$/) }
            it { should contain_file('rsyslog_config').without_content(/^\$DefaultRuleset local$/) }
            it { should contain_file('rsyslog_config').without_content(/^\$IncludeConfig \/etc\/rsyslog.d\/\*.conf$/) }
          end

          if value.to_i >= 5
            it { should contain_file('rsyslog_config').with_content(/^\*.emerg\s+:omusrmsg:\*$/) }
          else
            it { should contain_file('rsyslog_config').with_content(/^\*.emerg\s+\*$/) }
          end
        end

        context "with is_log_server=true, enable_udp_server=true, enable_tcp_server=true" do
          let :params do
            {
              :is_log_server     => true,
              :enable_udp_server => 'true',
              :enable_tcp_server => 'true',
            }
          end

          if value.to_i > 2
            it { should contain_file('rsyslog_config').with_content(/^\$ModLoad imudp$/) }
            it { should contain_file('rsyslog_config').with_content(/^\$ModLoad imtcp$/) }
            it { should contain_file('rsyslog_config').with_content(/^\$template RemoteHost, "\/srv\/logs\/%HOSTNAME%\/%\$YEAR%-%\$MONTH%-%\$DAY%.log"$/) }
            it { should contain_file('rsyslog_config').with_content(/^\$RuleSet remote$/) }
            it { should contain_file('rsyslog_config').with_content(/^\*.\* \?RemoteHost$/) }
            it { should contain_file('rsyslog_config').with_content(/^\$InputTCPServerBindRuleset remote$/) }
            it { should contain_file('rsyslog_config').with_content(/^\$InputTCPServerRun 514$/) }
            it { should contain_file('rsyslog_config').with_content(/^\$InputUDPServerBindRuleset remote$/) }
            it { should contain_file('rsyslog_config').with_content(/^\$UDPServerRun 514$/) }
          else
            it { should contain_file('rsyslog_config').without_content(/^\$ModLoad imudp$/) }
            it { should contain_file('rsyslog_config').without_content(/^\$ModLoad imtcp$/) }
            it { should contain_file('rsyslog_config').without_content(/^\$template RemoteHost, "\/srv\/logs\/%HOSTNAME%\/%\$YEAR%-%\$MONTH%-%\$DAY%.log"$/) }
            it { should contain_file('rsyslog_config').without_content(/^\$RuleSet remote$/) }
            it { should contain_file('rsyslog_config').without_content(/^\*.\* \?RemoteHost$/) }
            it { should contain_file('rsyslog_config').without_content(/^\$InputTCPServerBindRuleset remote$/) }
            it { should contain_file('rsyslog_config').without_content(/^\$InputTCPServerRun 514$/) }
            it { should contain_file('rsyslog_config').without_content(/^\$InputUDPServerBindRuleset remote$/) }
            it { should contain_file('rsyslog_config').without_content(/^\$UDPServerRun 514$/) }
          end
        end

        context "with remote_logging=true" do
          let :params do
            {
              :remote_logging => 'true',
            }
          end

          if value.to_i > 2
            it { should contain_file('rsyslog_config').with_content(/^\$WorkDirectory \/var\/spool\/rsyslog/) }
            it { should contain_file('rsyslog_config').with_content(/^\$ActionQueueFileName queue/) }
            it { should contain_file('rsyslog_config').with_content(/^\$ActionQueueMaxDiskSpace 1g/) }
            it { should contain_file('rsyslog_config').with_content(/^\$ActionQueueSaveOnShutdown on/) }
            it { should contain_file('rsyslog_config').with_content(/^\$ActionQueueType LinkedList/) }
            it { should contain_file('rsyslog_config').with_content(/^\$ActionResumeRetryCount -1/) }
          else
            it { should contain_file('rsyslog_config').without_content(/^\$WorkDirectory \/var\/spool\/rsyslog/) }
            it { should contain_file('rsyslog_config').without_content(/^\$ActionQueueFileName queue/) }
            it { should contain_file('rsyslog_config').without_content(/^\$ActionQueueMaxDiskSpace 1g/) }
            it { should contain_file('rsyslog_config').without_content(/^\$ActionQueueSaveOnShutdown on/) }
            it { should contain_file('rsyslog_config').without_content(/^\$ActionQueueType LinkedList/) }
            it { should contain_file('rsyslog_config').without_content(/^\$ActionResumeRetryCount -1/) }
          end
        end

        context 'with explicit umask=\'0022\'' do
          let :params do
            {
              :umask => '0022',
            }
          end
          it { should contain_file('rsyslog_config').with_content(/^\$umask 0022$/) }
        end

        context 'with file_create_mode=\'0664\'' do
          let :params do
            {
              :file_create_mode=> '0644',
            }
          end
          it { should contain_file('rsyslog_config').with_content(/^\$FileCreateMode 0644$/) }
        end

        context 'with dir_create_mode=\'0770\'' do
          let :params do
            {
              :dir_create_mode=> '0770',
            }
          end
          it { should contain_file('rsyslog_config').with_content(/^\$DirCreateMode 0770$/) }
        end
      end
    end

    context 'with use_tls' do
      ['false',false].each do |value|
        context "set to #{value}" do
          let(:params) { { :use_tls => value } }

          it { should contain_file('rsyslog_config').without_content(/^\s*\$DefaultNetstreamDriverCAFile/) }
          it { should contain_file('rsyslog_config').without_content(/^\s*\$ActionSendStreamDriver gtls/) }
          it { should contain_file('rsyslog_config').without_content(/^\s*\$ActionSendStreamDriverMode 1/) }
          it { should contain_file('rsyslog_config').without_content(/^\s*\$ActionSendStreamDriverAuthMode/) }
          it { should contain_file('rsyslog_config').without_content(/^\s*\$ActionSendStreamDriverPermittedPeer/) }
        end
      end

      ['true',true].each do |value|
        context "set to #{value}" do
          context 'ca_file set to valid path and permitted_peer set to a valid string' do
            let(:params) do
              {
                :use_tls        => value,
                :ca_file        => '/etc/papertrail-bundle.pem',
                :permitted_peer => '*.papertrailapp.com',
              }
            end

            it { should contain_file('rsyslog_config').with_content(/^\$DefaultNetstreamDriverCAFile \/etc\/papertrail-bundle.pem # trust these CAs$/) }
            it { should contain_file('rsyslog_config').with_content(/^\$ActionSendStreamDriver gtls # use gtls netstream driver$/) }
            it { should contain_file('rsyslog_config').with_content(/^\$ActionSendStreamDriverMode 1 # require TLS$/) }
            it { should contain_file('rsyslog_config').with_content(/^\$ActionSendStreamDriverAuthMode x509\/name # authenticate by hostname$/) }
            it { should contain_file('rsyslog_config').with_content(/^\$ActionSendStreamDriverPermittedPeer \*.papertrailapp.com$/) }
          end

          context 'ca_file set to invalid path' do
            let(:params) do
              {
                :use_tls        => value,
                :ca_file        => 'invalid/path',
                :permitted_peer => '*.papertrailapp.com',
              }
            end

            it do
              expect {
                should contain_class('rsyslog')
              }.to raise_error(Puppet::Error,/"invalid\/path" is not an absolute path\./)
            end
          end

          context 'permitted_peer set to a non-string' do
            let(:params) do
              {
                :use_tls        => value,
                :ca_file        => '/etc/papertrail-bundle.pem',
                :permitted_peer => ['invalid'],
              }
            end

            it do
              expect {
                should contain_class('rsyslog')
              }.to raise_error(Puppet::Error,/\["invalid"\] is not a string\./)
            end
          end
        end
      end
    end

    describe 'on a platform with mod_imjournal set to true' do
      let :facts do
        {
          :osfamily               => 'RedHat',
          :operatingsystemrelease => '7.0',
          :kernel                 => 'Linux',
          :domain                 => 'defaultdomain',
          :rsyslog_version        => '5.8.10',
        }
      end

      context 'work_directory specified' do
        let :params do
          {
            :work_directory => '/tmp/foo',
            :mod_imjournal  => true,
          }
        end

        it { should contain_file('rsyslog_config').with_content(/^\$WorkDirectory \/tmp\/foo$/) }
      end

      context 'journalstate_file specified' do
        let :params do
          {
            :journalstate_file => 'my.journal',
            :mod_imjournal     => true,
          }
        end

        it { should contain_file('rsyslog_config').with_content(/^\$IMJournalStateFile my.journal$/) }
      end
    end

    describe 'rsyslog_package' do
      context 'with default params' do
        it {
          should contain_package('rsyslog').with({
            'ensure' => 'present'
          })
        }
      end

      context 'with default params and use_tls set to true' do
        let(:params) do
          {
            :use_tls => true,
            :ca_file => '/etc/papertrail-bundle.pem',
          }
        end

        it {
          should contain_package('rsyslog').with({
            'ensure' => 'present'
          })
        }

        it {
          should contain_package('rsyslog-gnutls').with({
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
          }.to raise_error(Puppet::Error,/daemon_ensure may be either \'running\' or \'stopped\' and is set to <invalid>\./)
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
          }.to raise_error(Puppet::Error,/Unknown type of boolean/)
        end
      end
    end

    describe 'rsyslog_logrotate_d_config' do
      logrotate_matrix = {
        'redhat5'   => { :osfamily => 'RedHat',  :release => '5.10', :kernel => 'Linux',   },
        'redhat6'   => { :osfamily => 'RedHat',  :release => '6.5',  :kernel => 'Linux',   },
        'redhat7'   => { :osfamily => 'RedHat',  :release => '7.0.1406', :kernel => 'Linux',   },
        'redhat8'   => { :osfamily => 'RedHat',  :release => '8.0',  :kernel => 'Linux',   },
        'debian7'   => { :osfamily => 'Debian',  :release => '7.3',  :kernel => 'Linux',   },
        'suse10'    => { :osfamily => 'Suse',    :release => '10.1',   :kernel => 'Linux',   },
        'suse11'    => { :osfamily => 'Suse',    :release => '11.1',   :kernel => 'Linux',   },
        'suse12'    => { :osfamily => 'Suse',    :release => '12.1',   :kernel => 'Linux',   },
        'suse15'    => { :osfamily => 'Suse',    :release => '15.1',   :kernel => 'Linux',   },
        'solaris10' => { :osfamily => 'Solaris', :release => '5.10', :kernel => 'Solaris', },
        'solaris11' => { :osfamily => 'Solaris', :release => '5.11', :kernel => 'Solaris', },
      }

      logrotate_matrix.sort.each do |k,v|
        logrotate_fixture = File.read(fixtures("logrotate.#{k}"))

        context "with default params on #{v[:osfamily]} #{v[:release]}" do
          let :params do
            { :logrotate_present => true }
          end

            let :facts do
              {
                :kernel                 => v[:kernel],
                :osfamily               => v[:osfamily],
                :operatingsystemrelease => v[:release],
                :kernelrelease          => v[:release],
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
          it { should contain_file('rsyslog_logrotate_d_config').with_content(logrotate_fixture) }

        end
      end

      context 'with logrotate_syslog_files containing duplicate files' do
        let(:params) { { :logrotate_syslog_files => [ '/var/log/messages', '/var/log/secure', '/var/log/maillog', '/var/log/spooler', '/var/log/boot.log', '/var/log/cron', '/var/log/cron', ]  } }
        logrotate_fixture = File.read(fixtures('logrotate.redhat7'))

        it { should contain_file('rsyslog_logrotate_d_config').with_content(logrotate_fixture) }
      end

      context 'with kernel_target containing specific destination' do
        let(:params) { { :kernel_target => '/special/kernel_target', } }

        it {
          should contain_file('rsyslog_logrotate_d_config').with({
            'path'    => '/etc/logrotate.d/syslog',
            'owner'   => 'root',
            'group'   => 'root',
            'mode'    => '0644',
            'require' => 'Package[rsyslog]',
          })
        }

        it {
          should contain_file('rsyslog_logrotate_d_config').with_content(/^\/special\/kernel_target$/)
        }
      end

      context 'with logrotate_options containing specific value' do
        let(:params) { { :logrotate_options => [ 'rotate 242' ] } }

        it {
          should contain_file('rsyslog_logrotate_d_config').with({
            'path'    => '/etc/logrotate.d/syslog',
            'owner'   => 'root',
            'group'   => 'root',
            'mode'    => '0644',
            'require' => 'Package[rsyslog]',
          })
        }

        it {
          should contain_file('rsyslog_logrotate_d_config').with_content(/^\{\n    rotate 242\n\}$/)
        }
      end

      ['true','false',true,false,'yess','noo','invalid','-1',-1].each do |value|
        context "with logrotate_present=#{value} specified as #{value.class}" do
          let(:params) { { :logrotate_present => value, } }

          if value == true or value == 'true'
            it {
              should contain_file('rsyslog_logrotate_d_config').with({
                'ensure'  => 'file',
                'path'    => '/etc/logrotate.d/syslog',
                'owner'   => 'root',
                'group'   => 'root',
                'mode'    => '0644',
                'require' => 'Package[rsyslog]',
              })
            }
          elsif value == false or value == 'false'
            it { should_not contain_file('rsyslog_logrotate_d_config') }
          else
            it 'should fail' do
              expect {
                should contain_class('rsyslog')
              }.to raise_error(Puppet::Error,/str2bool\(\):/)
            end
          end
        end
      end

      context 'with pid_file paramter specified as valid value' do
        let(:params) { { :pid_file => '/path/to/syslog.pid' } }

        it {
          should contain_file('rsyslog_logrotate_d_config').with({
            'path'    => '/etc/logrotate.d/syslog',
            'owner'   => 'root',
            'group'   => 'root',
            'mode'    => '0644',
            'require' => 'Package[rsyslog]',
          })
        }

        it {
          should contain_file('rsyslog_logrotate_d_config').with_content(
            /^        \/bin\/kill -HUP `cat \/path\/to\/syslog.pid 2> \/dev\/null` 2> \/dev\/null || true$/
          )
        }
      end

      context 'with pid_file specified as an invalid value' do
        let(:params) { { :pid_file => 'invalid/path/to/syslog.pid' } }

        it do
          expect {
            should contain_class('rsyslog')
          }.to raise_error(Puppet::Error,/is not an absolute path/)
        end
      end
    end

    describe 'rsyslog_sysconfig' do
      context 'with syslogd_options specified as invalid type' do
        let(:params) { { :syslogd_options => [ 'ar', 'ray' ] } }

        it 'should fail' do
          expect {
            should contain_class('rsyslog')
          }.to raise_error(Puppet::Error,/is not a string\./)
        end
      end

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

        context 'with syslogd_options specified as valid value' do
          let(:params) { { :syslogd_options => '-c0' } }

          it { should contain_file('rsyslog_sysconfig').with_content(/^RSYSLOGD_OPTIONS="-c0"$/) }
        end
      end

      context 'on EL 7' do
        let :facts do
          {
            :kernel                 => 'Linux',
            :osfamily               => 'RedHat',
            :operatingsystemrelease => '7.0.1406',
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
            should contain_file('rsyslog_sysconfig').with_content(/^SYSLOGD_OPTIONS=""$/)
          }
        end

        context 'with syslogd_options specified as valid value' do
          let(:params) { { :syslogd_options => '-c0' } }

          it { should contain_file('rsyslog_sysconfig').with_content(/^SYSLOGD_OPTIONS="-c0"$/) }
        end
      end

      context 'on EL 6' do
        let :facts do
          {
            :kernel                 => 'Linux',
            :osfamily               => 'RedHat',
            :operatingsystemrelease => '6.5',
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
            should contain_file('rsyslog_sysconfig').with_content(/^SYSLOGD_OPTIONS=""$/)
          }
        end

        context 'with syslogd_options specified as valid value' do
          let(:params) { { :syslogd_options => '-c0' } }

          it { should contain_file('rsyslog_sysconfig').with_content(/^SYSLOGD_OPTIONS="-c0"$/) }
        end
      end

      context 'on EL 5' do
        let :facts do
          {
            :kernel                 => 'Linux',
            :osfamily               => 'RedHat',
            :operatingsystemrelease => '5.10',
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

        context 'with syslogd_options specified as valid value' do
          let(:params) { { :syslogd_options => '-c0' } }

          it { should contain_file('rsyslog_sysconfig').with_content(/^SYSLOGD_OPTIONS="-c0"$/) }
        end
      end

      context 'on EL 8' do
        let :facts do
          {
            :kernel                 => 'Linux',
            :osfamily               => 'RedHat',
            :operatingsystemrelease => '8.0',
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
          it { should contain_file('rsyslog_sysconfig').with_content(/^SYSLOGD_OPTIONS=""$/) }
        end

        context 'with syslogd_options specified as valid value' do
          let(:params) { { :syslogd_options => '-c0' } }

          it { should contain_file('rsyslog_sysconfig').with_content(/^SYSLOGD_OPTIONS="-c0"$/) }
        end
      end

      context 'on Suse 10' do
        let :facts do
          {
            :kernel                 => 'Linux',
            :osfamily               => 'Suse',
            :operatingsystemrelease => '10.2',
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

        context 'with syslogd_options specified as valid value' do
          let(:params) { { :syslogd_options => '-c0' } }

          it { should contain_file('rsyslog_sysconfig').with_content(/^SYSLOGD_PARAMS="-c0"$/) }
        end
      end

      context 'on Suse 11' do
        let :facts do
          {
            :kernel                 => 'Linux',
            :osfamily               => 'Suse',
            :operatingsystemrelease => '11.1',
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

        context 'with syslogd_options specified as valid value' do
          let(:params) { { :syslogd_options => '-c0' } }

          it { should contain_file('rsyslog_sysconfig').with_content(/^SYSLOGD_PARAMS="-c0"$/) }
        end
      end

      context 'on Suse 12' do
        let :facts do
          {
            :kernel                 => 'Linux',
            :osfamily               => 'Suse',
            :operatingsystemrelease => '12.0',
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
          it { should contain_file('rsyslog_sysconfig').with_content(/^RSYSLOGD_PARAMS=""$/) }
        end

        context 'with syslogd_options specified as valid value' do
          let(:params) { { :syslogd_options => '-c0' } }

          it { should contain_file('rsyslog_sysconfig').with_content(/^RSYSLOGD_PARAMS="-c0"$/) }
        end
      end

      context 'on Suse 15' do
        let :facts do
          {
            :kernel                 => 'Linux',
            :osfamily               => 'Suse',
            :operatingsystemrelease => '15.0',
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
          it { should contain_file('rsyslog_sysconfig').with_content(/^RSYSLOGD_PARAMS=""$/) }
        end

        context 'with syslogd_options specified as valid value' do
          let(:params) { { :syslogd_options => '-c0' } }

          it { should contain_file('rsyslog_sysconfig').with_content(/^RSYSLOGD_PARAMS="-c0"$/) }
        end
      end
    end

    describe 'rsyslog_d_dir' do
      context "with default params" do
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
        let (:params) { { :rsyslog_d_dir => 'custom/rsyslog.d' } }
        it 'should fail' do
          expect {
            should contain_class('rsyslog')
          }.to raise_error(Puppet::Error,/is not an absolute path/)
        end
      end

      ['true',true].each do |value|
        context "with rsyslog_d_dir_purge specified as #{value}" do
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
        let (:params) { { :rsyslog_d_dir_purge => 'invalid' } }

        it 'should fail' do
          expect {
            should contain_class('rsyslog')
          }.to raise_error(Puppet::Error,/str2bool\(\)/)
        end
      end
    end

    describe 'case is_log_server, default params' do
      context 'case true' do
        let(:params) { { :is_log_server => true } }
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
            :is_log_server => true,
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
        let(:params) { { :is_log_server => ['invalid','type'] } }
        it do
          expect {
            should contain_class('rsyslog')
          }.to raise_error(Puppet::Error,/\["invalid", "type"\] is not a boolean\./)
        end
      end
    end

    describe 'case transport_protocol, default params' do
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
  end

  describe 'module platform support' do
    support_matrix = {
      'redhat4'   => { :kernel => 'Linux',   :osfamily => 'RedHat',  :release => '4.3',    :support => 'unsupported', },
      'redhat5'   => { :kernel => 'Linux',   :osfamily => 'RedHat',  :release => '5.10',    :support => 'supported', },
      'redhat6'   => { :kernel => 'Linux',   :osfamily => 'RedHat',  :release => '6.5',    :support => 'supported', },
      'redhat7'   => { :kernel => 'Linux',   :osfamily => 'RedHat',  :release => '7.0.1406',    :support => 'supported', },
      'redhat8'   => { :kernel => 'Linux',   :osfamily => 'RedHat',  :release => '8.0',    :support => 'supported', },
      'debian7'   => { :kernel => 'Linux',   :osfamily => 'Debian',  :release => '7.3',    :support => 'supported', },
      'suse9'     => { :kernel => 'Linux',   :osfamily => 'Suse',    :release => '9.1',    :support => 'unsupported', },
      'suse10'    => { :kernel => 'Linux',   :osfamily => 'Suse',    :release => '10.2',   :support => 'supported', },
      'suse11'    => { :kernel => 'Linux',   :osfamily => 'Suse',    :release => '11.1',   :support => 'supported', },
      'suse12'    => { :kernel => 'Linux',   :osfamily => 'Suse',    :release => '12.1',   :support => 'supported', },
      'suse15'    => { :kernel => 'Linux',   :osfamily => 'Suse',    :release => '15.1',   :support => 'supported', },
      'solaris9'  => { :kernel => 'Solaris', :osfamily => 'Solaris', :release => '5.9',  :support => 'unsupported', },
      'solaris10' => { :kernel => 'Solaris', :osfamily => 'Solaris', :release => '5.10', :support => 'supported', },
      'solaris11' => { :kernel => 'Solaris', :osfamily => 'Solaris', :release => '5.11', :support => 'supported', },
    }

    support_matrix.sort.each do |k,v|
      context "on osfamily #{v[:osfamily]} with major release #{v[:release]} which is #{v[:support]}" do
        if v[:kernel] == 'Linux'
          let :facts do
            {
              :kernel                 => v[:kernel],
              :osfamily               => v[:osfamily],
              :operatingsystemrelease => v[:release],
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

  describe 'module platform support for mod_imjournal' do
    platforms = {
      'redhat5'   => { :kernel => 'Linux',   :osfamily => 'RedHat',  :release => '5',    :mod_imjournal => false, },
      'redhat6'   => { :kernel => 'Linux',   :osfamily => 'RedHat',  :release => '6',    :mod_imjournal => false, },
      'redhat7'   => { :kernel => 'Linux',   :osfamily => 'RedHat',  :release => '7',    :mod_imjournal => true, },
      'redhat8'   => { :kernel => 'Linux',   :osfamily => 'RedHat',  :release => '8',    :mod_imjournal => true, },
      'debian7'   => { :kernel => 'Linux',   :osfamily => 'Debian',  :release => '7',    :mod_imjournal => false, },
      'suse10'    => { :kernel => 'Linux',   :osfamily => 'Suse',    :release => '10',   :mod_imjournal => false, },
      'suse11'    => { :kernel => 'Linux',   :osfamily => 'Suse',    :release => '11',   :mod_imjournal => false, },
      'suse12'    => { :kernel => 'Linux',   :osfamily => 'Suse',    :release => '12',   :mod_imjournal => false, },
      'suse15'    => { :kernel => 'Linux',   :osfamily => 'Suse',    :release => '15',   :mod_imjournal => false, },
      'solaris10' => { :kernel => 'Solaris', :osfamily => 'Solaris', :release => '5.10', :mod_imjournal => false, },
      'solaris11' => { :kernel => 'Solaris', :osfamily => 'Solaris', :release => '5.11', :mod_imjournal => false, },
    }

    platforms.sort.each do |k,v|
      context "on osfamily #{v[:osfamily]} with major release #{v[:release]} support for mod_imjournal is #{v[:mod_imjournal]}" do
        let :facts do
          {
            :kernel                 => v[:kernel],
            :osfamily               => v[:osfamily],
            :operatingsystemrelease => v[:release],
            :kernelrelease          => v[:release],
            :domain                 => 'defaultdomain',
            :rsyslog_version        => '5.8.10',
          }
        end

        if v[:mod_imjournal] == true
          it { should contain_file('rsyslog_config').with_content(/^\$ModLoad imjournal/) }
          it { should contain_file('rsyslog_config').with_content(/^\$WorkDirectory \/var\/lib\/rsyslog$/) }
          it { should contain_file('rsyslog_config').with_content(/^\$OmitLocalLogging on$/) }
          it { should contain_file('rsyslog_config').with_content(/^\$IMJournalStateFile imjournal.state$/) }
        else
          it { should contain_file('rsyslog_config').without_content(/^\s*\$ModLoad\s+imjournal/) }
          it { should contain_file('rsyslog_config').without_content(/^\s*\$WorkDirectory/) }
          it { should contain_file('rsyslog_config').without_content(/^\s*\$OmitLocalLogging/) }
          it { should contain_file('rsyslog_config').without_content(/^\s*\$IMJournalStateFile/) }
        end
      end
    end
  end

  describe 'module platform support for manage_devlog' do
    platforms = {
      'redhat5'   => { :kernel => 'Linux',   :osfamily => 'RedHat',  :release => '5',    :manage_devlog => false, },
      'redhat6'   => { :kernel => 'Linux',   :osfamily => 'RedHat',  :release => '6',    :manage_devlog => false, },
      'redhat7'   => { :kernel => 'Linux',   :osfamily => 'RedHat',  :release => '7',    :manage_devlog => true, },
      'redhat8'   => { :kernel => 'Linux',   :osfamily => 'RedHat',  :release => '8',    :manage_devlog => true, },
      'debian7'   => { :kernel => 'Linux',   :osfamily => 'Debian',  :release => '7',    :manage_devlog => false, },
      'suse10'    => { :kernel => 'Linux',   :osfamily => 'Suse',    :release => '10',   :manage_devlog => false, },
      'suse11'    => { :kernel => 'Linux',   :osfamily => 'Suse',    :release => '11',   :manage_devlog => false, },
      'suse12'    => { :kernel => 'Linux',   :osfamily => 'Suse',    :release => '12',   :manage_devlog => false, },
      'suse15'    => { :kernel => 'Linux',   :osfamily => 'Suse',    :release => '15',   :manage_devlog => false, },
      'solaris10' => { :kernel => 'Solaris', :osfamily => 'Solaris', :release => '5.10', :manage_devlog => false, },
      'solaris11' => { :kernel => 'Solaris', :osfamily => 'Solaris', :release => '5.11', :manage_devlog => false, },
    }

    platforms.sort.each do |k,v|
      context "on osfamily #{v[:osfamily]} with major release #{v[:release]} support for manage_devlog is #{v[:manage_devlog]}" do
        let :facts do
          {
            :kernel                 => v[:kernel],
            :osfamily               => v[:osfamily],
            :operatingsystemrelease => v[:release],
            :kernelrelease          => v[:release],
            :domain                 => 'defaultdomain',
            :rsyslog_version        => '5.8.10',
          }
        end

        if v[:manage_devlog] == true
          it {
            should contain_exec('manage devlog').with({
              'command' => 'systemctl restart systemd-journald.socket',
              'creates' => '/dev/log',
              'path'    => '/bin:/usr/bin:/sbin:/usr/sbin',
            })
          }
        else
          it { should_not contain_exec('manage devlog') }
        end
      end
    end
  end

  describe 'variable type and content validations' do
    # set needed custom facts and variables
    let :facts do
      {
        :kernel                 => 'Linux',
        :osfamily               => 'RedHat',
        :operatingsystemrelease => '6.5',
        :domain                 => 'defaultdomain',
        :rsyslog_version        => '5.8.10',
      }
    end
    let(:validation_params) do
      {
        #:param => 'value',
      }
    end

    validations = {
      'absolute_path' => {
        :name    => ['work_directory'],
        :valid   => ['/absolute/filepath','/absolute/directory/'],
        :invalid => ['invalid',3,2.42,['array'],a={'ha'=>'sh'}],
        :message => 'is not an absolute path',
      },
      'array/string' => {
        :name    => %w(log_server),
        :valid   => [%w(ar ray), 'string'],
        :invalid => [{ 'ha' => 'sh' }, 3, 2.42, true, false],
        :message => 'must be an array or string',
      },
      'boolean' => {
        :name    => ['mod_imjournal'],
        :valid   => [true,false,'true','false'],
        :invalid => ['string',['array'],a={'ha'=>'sh'},3,2.42,nil],
        :message => 'str2bool()',
      },
      'string' => {
        :name    => ['journalstate_file'],
        :valid   => ['valid'],
        :invalid => [['array'],a={'ha'=>'sh'},true],
        :message => 'is not a string',
      },
    }

    validations.sort.each do |type, var|
      var[:name].each do |var_name|
        var[:valid].each do |valid|
          context "with #{var_name} (#{type}) set to valid #{valid} (as #{valid.class})" do
            let(:params) { validation_params.merge({ :"#{var_name}" => valid, }) }
            it { should compile }
          end
        end

        var[:invalid].each do |invalid|
          context "with #{var_name} (#{type}) set to invalid #{invalid} (as #{invalid.class})" do
            let(:params) { validation_params.merge({ :"#{var_name}" => invalid, }) }
            it 'should fail' do
              expect do
                should contain_class(subject)
              end.to raise_error(Puppet::Error, /#{var[:message]}/)
            end
          end
        end
      end # var[:name].each
    end # validations.sort.each
  end # describe 'variable type and content validations'
end
