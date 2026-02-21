```sh
# Install Zig 0.14.0
wget https://ziglang.org/download/0.14.0/zig-linux-x86_64-0.14.0.tar.xz
tar xf zig-linux-x86_64-0.14.0.tar.xz
export PATH=$PWD/zig-linux-x86_64-0.14.0:$PATH

# Build (WSL2 mode)
cd zproxy
zig build -Dwsl2=true

# Run tests
zig build test -Dwsl2=true

# Run (point it at a backend first)
./zig-out/bin/zproxy
```