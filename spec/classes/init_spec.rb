require 'spec_helper'

  describe 'rsyslog' do

    describe 'RHEL 6 should include rsyslog class with default params' do

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

    describe 'RHEL 5 should include rsyslog class with default params' do

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

    describe 'debian systems should fail' do
      let(:facts) { {:osfamily => 'debian' } }
      it do 
        expect {
          should include_class('rsyslog')
        }.to raise_error(Puppet::Error,/rsyslog supports osfamily redhat and you have debian./)
      end
    end

    describe 'SuSE systems should fail' do
      let(:facts) { {:osfamily => 'suse' } }
      it do 
        expect {
          should include_class('rsyslog')
        }.to raise_error(Puppet::Error,/rsyslog supports osfamily redhat and you have suse./)
      end
    end

    describe 'Gentoo systems should fail' do
      let(:facts) { {:osfamily => 'Gentoo' } }
      it do 
        expect {
          should include_class('rsyslog')
        }.to raise_error(Puppet::Error,/rsyslog supports osfamily redhat and you have Gentoo./)
      end
    end

    describe 'Solaris systems should fail' do
      let(:facts) { {:osfamily => 'solaris' } }
      it do 
        expect {
          should include_class('rsyslog')
        }.to raise_error(Puppet::Error,/rsyslog supports osfamily redhat and you have solaris./)
      end
    end
  end
