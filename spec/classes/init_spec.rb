require 'spec_helper'

  describe 'rsyslog' do

    describe 'should include rsyslog class with default params' do

      let :facts do
        {
          :osfamily          => 'redhat',
          :lsbmajdistrelease => '6',
        }
      end

      it { should include_class('rsyslog') }
      
      it {
            should contain_package('rsyslog').with( { 'name' => 'rsyslog' } )
            should contain_service('rsyslog').with( { 'name' => 'rsyslog' } )
          }
      
      it {
        should contain_file('syslog').with(
          :ensure => 'file',
          :path   => '/etc/logrotate.d/syslog',
          :owner  => 'root',
          :group  => 'root',
          :mode   => '0644'
        )
      }
      
      it {
        should contain_file('rsyslog.conf').with(
          :ensure => 'file',
          :path   => '/etc/rsyslog.conf',
          :owner  => 'root',
          :group  => 'root',
          :mode   => '0644'
        )
      }
      
      it {
        should contain_file('rsyslog').with(
          :ensure => 'file',
          :path   => '/etc/sysconfig/rsyslog',
          :owner  => 'root',
          :group  => 'root',
          :mode   => '0644'
        )
      }
    end
  end
