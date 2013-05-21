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
    end
  end
