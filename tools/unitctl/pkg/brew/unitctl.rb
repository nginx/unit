class Unitctl < Formula
  desc "CLI interface to the NGINX UNIT Control API"
  homepage "https://github.com/nginxinc/unit-rust-sdk"
  version "0.3.0"
  package_name = "unitctl"
  src_repo = "https://github.com/nginxinc/unit-rust-sdk"

  if OS.mac? and Hardware::CPU.intel?
      url "#{src_repo}/releases/download/v#{version}/#{package_name}_v#{version}_x86_64-apple-darwin.tar.gz"
      sha256 "3e476850d1fc08aabc3cb25d19d42d171f52d55cea887aec754d47d1142c3638"
  elsif OS.mac? and Hardware::CPU.arm?
      url "#{src_repo}/releases/download/v#{version}/#{package_name}_#{version}_aarch64-apple-darwin.tar.gz"
      sha256 "c1ec83ae67c08640f1712fba1c8aa305c063570fb7f96203228bf75413468bab"
  elsif OS.linux? and Hardware::CPU.intel?
      url "#{src_repo}/releases/download/v#{version}/#{package_name}_#{version}_x86_64-unknown-linux-gnu.tar.gz"
      sha256 "9616687a7e4319c8399c0071059e6c1bb80b7e5b616714edc81a92717264a70f"
  elsif OS.linux? and Hardware::CPU.arm? and Hardware::CPU.is_64_bit?
      url "#{src_repo}/releases/download/v#{version}/#{package_name}_#{version}_aarch64-unknown-linux-gnu.tar.gz"
      sha256 "88c2c7a8bc3d1930080c2b9a397a33e156ae4f876903b6565775270584055534"
  else
      odie "Unsupported architecture"
  end


  def install
    bin.install "unitctl"
    man1.install "unitctl.1.gz"
  end
end
