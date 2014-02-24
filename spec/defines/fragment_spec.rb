require 'spec_helper'
describe 'rsyslog::fragment' do

  context 'create file from content' do
    let(:title) { 'example' }
    let(:params) {
      { :content => '# ### begin forwarding rule ###
# Example rule
# ### end of the forwarding rule ###'
      }
    }
    let(:facts) {
      {
        :osfamily          => 'RedHat',
        :lsbmajdistrelease => '5',
      }
    }

    it { should contain_class('rsyslog') }

    it {
      should contain_file('/etc/rsyslog.d/example.conf').with({
        'owner'   => 'root',
        'group'   => 'root',
        'mode'    => '0644',
        'require' => 'Common::Mkdir_p[/etc/rsyslog.d]',
      })
    }
    it { should contain_file('/etc/rsyslog.d/example.conf').with_content(
%{# ### begin forwarding rule ###
# Example rule
# ### end of the forwarding rule ###})
    }
  end

  context 'with content specified as invalid string' do
    let(:title) { 'example' }
    let(:facts) {
      { :osfamily          => 'RedHat',
        :lsbmajdistrelease => '6',
      }
    }
    let(:params) { { :content => true } }

    it 'should fail' do
      expect {
        should contain_class('rsyslog')
      }.to raise_error(Puppet::Error)
    end
  end

  context 'with ensure specified as absent' do
    let(:title) { 'example' }
    let(:facts) {
      { :osfamily          => 'RedHat',
        :lsbmajdistrelease => '6',
      }
    }
    let(:params) { { :ensure => 'absent' } }

    it { should contain_class('rsyslog') }

    it {
      should contain_file('/etc/rsyslog.d/example.conf').with({
        'ensure'  => 'absent',
        'owner'   => 'root',
        'group'   => 'root',
        'mode'    => '0644',
        'require' => 'Common::Mkdir_p[/etc/rsyslog.d]',
      })
    }
  end

  context 'with ensure specified as invalid value' do
    let(:title) { 'example' }
    let(:facts) {
      { :osfamily          => 'RedHat',
        :lsbmajdistrelease => '6',
      }
    }
    let(:params) { { :ensure => 'true' } }

    it 'should fail' do
      expect {
        should contain_class('rsyslog')
      }.to raise_error(Puppet::Error)
    end
  end
end
