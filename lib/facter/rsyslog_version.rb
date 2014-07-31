# rsyslog_version.rb

Facter.add("rsyslog_version") do
  setcode do
    test_exists = "rpm -q rsyslog 2>&1 >/dev/null ; echo $?"
    if Facter::Util::Resolution.exec(test_exists) == '0'
      cmd = "rpm -q --queryformat='%{VERSION}' rsyslog"
      response = Facter::Util::Resolution.exec(cmd)
    end
  end
end
