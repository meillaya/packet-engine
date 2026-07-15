{
  description = "Packet Engine C++23 development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          config.allowUnfree = true;
        };

        # nixpkgs distributes libxdp inside the xdp-tools package.  Use the
        # separate `lib` output so LIBXDP_OBJECT_PATH points at the BPF objects.
        libxdp-lib = pkgs.xdp-tools.lib;
        libxdp-pinned = pkgs.xdp-tools;
      in
      {
        devShells.default = pkgs.mkShell {
          name = "packet-engine";

          nativeBuildInputs = with pkgs; [
            gcc
            cmake
            ninja
            bear
            pkg-config
            clang-tools
          ];

          buildInputs = with pkgs; [
            libxdp-lib
            libbpf
            dpdk
            numactl
            boost
            gtest
            nlohmann_json
            linuxPackages.kernel.dev
          ];

          packages = with pkgs; [
            iperf3
            tcpreplay
            xdp-tools
          ];

          shellHook = ''
            export LIBXDP_OBJECT_PATH="${libxdp-lib}/lib/bpf"
            export PKG_CONFIG_PATH="${libxdp-lib}/lib/pkgconfig:${pkgs.libbpf}/lib/pkgconfig:${pkgs.dpdk}/lib/pkgconfig:${pkgs.elfutils.dev}/lib/pkgconfig:${pkgs.zlib.dev}/share/pkgconfig:${pkgs.zstd.dev}/lib/pkgconfig''${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
            echo "Packet Engine dev shell ready"
            echo "  LIBXDP_OBJECT_PATH=$LIBXDP_OBJECT_PATH"
            echo "  libxdp $(pkg-config --modversion libxdp 2>/dev/null || echo 'not found')"
          '';
        };
      });
}
