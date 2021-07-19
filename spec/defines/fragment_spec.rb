require 'spec_helper'
describe 'rsyslog::fragment' do
  let(:title) { 'example' }
  let(:facts) {
    {
      :kernel                 => 'Linux',
      :osfamily               => 'RedHat',
      :operatingsystemrelease => '6.5',
    }
  }

  context 'create file from content' do
    let(:params) {
      { :content => '# ### begin forwarding rule ###
# Example rule
# ### end of the forwarding rule ###'
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
    let(:params) { { :content => true } }

    it 'should fail' do
      expect {
        should contain_class('rsyslog')
      }.to raise_error(Puppet::Error,/is not a string/)
    end
  end

  context 'with ensure specified as absent' do
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

  ['true',true,'present'].each do |value|
    context "with ensure specified as invalid value (#{value})" do
      let(:params) { { :ensure => value } }

      it 'should fail' do
        expect {
          should contain_class('rsyslog')
        }.to raise_error(Puppet::Error,/does not match ..file., .absent/)
      end
    end
  end
end
