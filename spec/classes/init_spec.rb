require 'spec_helper'

describe 'rsyslog' do
  describe 'with default params' do
    context 'on supported platform EL 6, should work' do
      let :facts do
        {
          :osfamily          => 'redhat',
          :lsbmajdistrelease => '6',
        }
      end

      it { should include_class('rsyslog') }

      it {
            should contain_package('rsyslog_package').with( { 'name' => 'rsyslog' } )
            should contain_service('rsyslog_daemon').with( { 'name' => 'rsyslog' } )
          }

      it {
        should contain_file('rsyslog_config').with({
          'path'   => '/etc/rsyslog.conf',
          'owner'  => 'root',
          'group'  => 'root',
          'mode'   => '0644',
        })
      }

      it {
        should contain_file('rsyslog_sysconfig').with({
          'path'   => '/etc/sysconfig/rsyslog',
          'owner'  => 'root',
          'group'  => 'root',
          'mode'   => '0644',
        })
      }
    end

    context 'on supported platform EL 5, should work' do
      let :facts do
        {
          :osfamily          => 'redhat',
          :lsbmajdistrelease => '5',
        }
      end

      it { should include_class('rsyslog') }

      it {
            should contain_package('rsyslog_package').with( { 'name' => 'rsyslog' } )
            should contain_service('rsyslog_daemon').with( { 'name' => 'rsyslog' } )
          }

      it {
        should contain_file('rsyslog_config').with({
          'path'   => '/etc/rsyslog.conf',
          'owner'  => 'root',
          'group'  => 'root',
          'mode'   => '0644',
        })
      }

      it {
        should contain_file('rsyslog_sysconfig').with({
          'path'   => '/etc/sysconfig/rsyslog',
          'owner'  => 'root',
          'group'  => 'root',
          'mode'   => '0644',
        })
      }
    end

    context 'on unsupported platform, Debian, should fail' do
      let(:facts) { {:osfamily => 'debian' } }
      it do
        expect {
          should include_class('rsyslog')
        }.to raise_error(Puppet::Error,/rsyslog supports osfamily redhat and you have debian./)
      end
    end
  end
end
